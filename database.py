# database.py

import os
import datetime
from dotenv import load_dotenv

from sqlalchemy import (
    create_engine, Column, Integer, String, JSON, TIMESTAMP
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Load environment variables from .env
load_dotenv()

# Get DB connection string from environment
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in environment variables")

# Create the SQLAlchemy engine and session
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declare base for models
Base = declarative_base()

# Dependency to get a DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# CSPM Findings Table
class CSPMFinding(Base):
    __tablename__ = "cspm_findings"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String(50), nullable=False)
    issue_type = Column(String(255), nullable=False)
    resource_id = Column(String(255), nullable=False)
    details = Column(JSON, nullable=False)
    timestamp = Column(TIMESTAMP, default=datetime.datetime.utcnow)

# Initialize tables
def init_db():
    Base.metadata.create_all(bind=engine)

# Insert finding helper
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
        print(f"[DB ERROR] Insert failed: {e}")
    finally:
        db.close()
