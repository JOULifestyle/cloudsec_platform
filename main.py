import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("🚀 Application startup: Logging is enabled.")


from fastapi import FastAPI
from routers import cspm, cwpp
from cloudsec.db.session import engine
from cloudsec.db.models import Base

app = FastAPI(title="CloudSec Platform")
Base.metadata.create_all(bind=engine)
app.include_router(cspm.router, prefix="/scan", tags=["CSPM"])
app.include_router(cwpp.router, prefix="/monitor", tags=["CWPP"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cloud Security API"}
