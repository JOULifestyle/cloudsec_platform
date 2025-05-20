import boto3

def scan_iam():
    iam = boto3.client("iam")
    users = iam.list_users()
    findings = []

    for user in users.get("Users", []):
        findings.append({
            "user_name": user["UserName"],
            "arn": user["Arn"],
            "create_date": user["CreateDate"].isoformat()
        })
    return findings
