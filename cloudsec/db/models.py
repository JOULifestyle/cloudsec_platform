from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from cloudsec.db.session import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(String, nullable=False)
    issue = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    remediation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
