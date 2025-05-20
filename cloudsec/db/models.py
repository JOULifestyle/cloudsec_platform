from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from datetime import datetime
from cloudsec.db.session import Base
from datetime import datetime
from .session import Base  # Ensure you're using the same Base from your session setup

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(String, nullable=False)
    issue = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    remediation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class S3BucketFinding(Base):
    __tablename__ = "s3_bucket_findings"

    id = Column(Integer, primary_key=True, index=True)
    bucket_name = Column(String, nullable=False)
    issue = Column(String, nullable=False)
    region = Column(String)
    account_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
