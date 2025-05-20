# database.py

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from sqlalchemy import Column, Integer, String, JSON, TIMESTAMP
import os

# Replace this with your actual PostgreSQL URL
SQLALCHEMY_DATABASE_URL = "postgresql+psycopg2://postgres:yifouwchte@<host>:5432/cloudsec_db
"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

        # PostgreSQL connection string
DATABASE_URL = "postgresql://postgres:yifouwchte@localhost:5432/cloudsec_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class CSPMFinding(Base):
    __tablename__ = "cspm_findings"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String(50))
    issue_type = Column(String(255))
    resource_id = Column(String(255))
    details = Column(JSON)
    timestamp = Column(TIMESTAMP, default=datetime.datetime.utcnow)

# Call this once on startup or via Alembic to create tables
def init_db():
    Base.metadata.create_all(bind=engine)

# The insert function
def insert_cspm_finding(service: str, issue_type: str, resource_id: str, details: dict):
    db = SessionLocal()
    try:
        finding = CSPMFinding(
            service=service,
            issue_type=issue_type,
            resource_id=resource_id,
            details=details
        )
        db.add(finding)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Insert error: {e}")
    finally:
        db.close()
