import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("Application startup: Logging is enabled.")


from fastapi import FastAPI
from routers import cspm, cwpp
from cloudsec.db.session import engine
from cloudsec.db.models import Base
from cloudsec.db import models
from dotenv import load_dotenv
from sqlalchemy import create_engine
from collectors.collector import get_running_containers, detect_root_containers, detect_privileged_containers
from cwpp.runtime_monitor import monitor_containers  # Import the runtime scanner


from collectors.ec2_scanner import scan_ec2
from collectors.iam_scanner import scan_iam
from collectors.sg_scanner import scan_security_groups

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy.orm import Session, sessionmaker
from database import get_db
from pydantic import BaseModel
from fastapi import APIRouter
from fastapi import Request
from fastapi import Depends
from auth.dependencies import get_current_user
from cloudsec.db.models import User
from datetime import timedelta
from utils.jwt import authenticate_user, create_access_token
from schemas import Token  # your response model for token
from utils.jwt import ACCESS_TOKEN_EXPIRE_MINUTES
from aws_scanner import router as aws_router  # 👈 Import router
from aws_scanner import scan_ec2, scan_s3, scan_iam, scan_security_groups, scan_rds, scan_lambda


from routers import auth
from fastapi.middleware.cors import CORSMiddleware
from utils.jwt import create_access_token

from database import Base, engine
import models

ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency to get DB session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app = FastAPI(title="CloudSec Platform")
app.include_router(auth.router)
app.include_router(aws_router)  # 👈 Register router

origins = [
    "http://localhost:3000/login",  # React dev server default port
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
router = APIRouter()
Base.metadata.create_all(bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    username: str
    password: str


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL, echo=True)
Base.metadata.create_all(bind=engine)
app.include_router(cspm.router, prefix="/scan", tags=["CSPM"])
app.include_router(cwpp.router, prefix="/monitor", tags=["CWPP"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cloud Security API"}

@app.get("/scan/cspm")
def scan_cspm():
    ec2_findings = scan_ec2()
    iam_findings = scan_iam()
    sg_findings = scan_security_groups()
    rds_findings = scan_rds()
    lambda_findings = scan_lambda()
    s3_findings = scan_s3()  # Placeholder, implement scan_s3 if available

    all_findings = (
        ec2_findings["findings"]
        + iam_findings["findings"]
        + sg_findings["findings"]
        + rds_findings["findings"]
        + lambda_findings["findings"]
        + s3_findings["findings"]
    )
    # store_findings_to_db(all_findings)  # Uncomment and implement if needed

    return {"message": "CSPM scan completed", "results": all_findings}


@app.post("/scan/cspm")
def scan_cspm(current_user: User = Depends(get_current_user)):
    results = {
        "ec2": scan_ec2(),
        "iam": scan_iam(),
        "security_groups": scan_security_groups(),
         "rds": scan_rds(),
    "lambda": scan_lambda(),
    "s3": scan_s3()
    }
    return {"status": "success", "data": results}

@app.post("/scan/cwpp")
async def scan_cwpp():
    containers = get_running_containers()
    root_containers = detect_root_containers(containers)
    privileged_containers = detect_privileged_containers(containers)

    results = []

    for c in root_containers:
        results.append({
            "container_id": c.id,
            "name": c.name,
            "image": c.image.tags,
            "issue": "Running as root user"
        })

    for c in privileged_containers:
        results.append({
            "container_id": c.id,
            "name": c.name,
            "image": c.image.tags,
            "issue": "Running in privileged mode"
        })

    return {"threats_detected": results, "count": len(results)}

@app.get("/scan/cwpp")
def scan_cwpp():
    # Call your container runtime monitor
    try:
        monitor_containers()
        return {"status": "success", "message": "Runtime monitoring complete"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

@app.post("/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if user exists
        existing_user = db.query(models.User).filter(models.User.username == user.username).first()
        if existing_user:
            return {"error": "User already exists"}

        # Hash the password
        hashed_password = pwd_context.hash(user.password)

        # Create new user model instance
        new_user = models.User(username=user.username, hashed_password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {"message": "User registered successfully", "username": new_user.username}

    except Exception as e:
        logger.error(f"Register error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")