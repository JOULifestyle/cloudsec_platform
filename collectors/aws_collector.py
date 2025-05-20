import psycopg2
from datetime import datetime

def insert_ec2_scan_result(instance_id, public_ip):
    conn = psycopg2.connect(
        dbname="cloudsec_db",
        user="postgres",
        password="yifouwchte",
        host="localhost",
        port=5432
    )
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO ec2_scan_results (instance_id, public_ip, scan_time) VALUES (%s, %s, %s)",
        (instance_id, public_ip, datetime.utcnow())
    )
    conn.commit()
    cur.close()
    conn.close()

def collect_buckets():
    # Temporary mock logic (replace with real AWS later)
    return {"buckets": ["test-bucket-1", "test-bucket-2"]}

if __name__ == "__main__":
    # Example call
    insert_ec2_scan_result('i-0123456789abcdef0', '54.123.45.67')
