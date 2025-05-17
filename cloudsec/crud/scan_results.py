from cloudsec.db.models import ScanResult
from cloudsec.db.session import SessionLocal

def save_scan_result(result_data: dict):
    db = SessionLocal()
    result = ScanResult(**result_data)
    db.add(result)
    db.commit()
    db.refresh(result)
    db.close()
    return result
