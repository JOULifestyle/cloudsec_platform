import boto3

from cloudsec.db.session import SessionLocal
from cloudsec.db.models import S3BucketFinding

def list_s3_buckets():
    s3 = boto3.client('s3')
    buckets_info = []

    try:
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            # Check if the bucket is public
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get('Grants', [])
            is_public = any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                            for grant in grants)
            buckets_info.append({
                'name': bucket_name,
                'is_public': is_public
            })
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
    
    return buckets_info

def store_s3_findings_to_db(findings):
    db = SessionLocal()
    try:
        for item in findings:
            finding = S3BucketFinding(name=item['name'], is_public=item['is_public'])
            db.add(finding)
        db.commit()
    except Exception as e:
        print(f"Error storing to DB: {e}")
        db.rollback()
    finally:
        db.close()
