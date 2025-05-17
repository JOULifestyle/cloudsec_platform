from fastapi import APIRouter
from collectors import aws_collector
from cloudsec.aws.cspm_scanner import list_s3_buckets, store_s3_findings_to_db

router = APIRouter()

@router.get("/s3")
def scan_s3():
    return aws_collector.collect_buckets()

@router.post("/cspm")
def run_cspm_scan():
    findings = list_s3_buckets()
    store_s3_findings_to_db(findings)
    return {"status": "success", "results": findings}