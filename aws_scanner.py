# aws_scanner.py
import boto3
from fastapi import APIRouter
from database import insert_cspm_finding

router = APIRouter()

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
iam = boto3.client('iam')

@router.get("/scan/ec2")
def scan_ec2():
    response = ec2.describe_instances()
    instances = []
    for r in response['Reservations']:
        for i in r['Instances']:
            instances.append({
                "InstanceId": i.get("InstanceId"),
                "Type": i.get("InstanceType"),
                "State": i.get("State", {}).get("Name"),
                "PublicIp": i.get("PublicIpAddress")
            })
    return {"findings": instances}  # ✅ changed key to findings

@router.get("/scan/s3")
def scan_s3():
    response = s3.list_buckets()
    buckets = [{"Name": b["Name"], "Created": b["CreationDate"].isoformat()} for b in response["Buckets"]]
    return {"findings": buckets}


@router.get("/scan/iam")
def scan_iam():
    response = iam.list_users()
    findings = [
        {
            "UserName": u["UserName"],
            "Created": u["CreateDate"].isoformat()
        }
        for u in response["Users"]
    ]
    return {"findings": findings}


@router.get("/scan/security-groups")
def scan_security_groups():
    response = ec2.describe_security_groups()
    findings = []

    for sg in response['SecurityGroups']:
        for permission in sg.get('IpPermissions', []):
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    findings.append({
                        "GroupId": sg["GroupId"],
                        "GroupName": sg.get("GroupName"),
                        "Description": sg.get("Description"),
                        "PortRange": f"{permission.get('FromPort')} - {permission.get('ToPort')}",
                        "Protocol": permission.get("IpProtocol"),
                        "PublicAccess": ip_range.get('CidrIp')
                    })

    return {"findings": findings}

def scan_rds():
    rds = boto3.client('rds')
    results = []

    try:
        instances = rds.describe_db_instances()['DBInstances']
        for db in instances:
            results.append({
                'type': 'RDS',
                'id': db['DBInstanceIdentifier'],
                'engine': db['Engine'],
                'public': db.get('PubliclyAccessible', False),
                'status': db['DBInstanceStatus']
            })
    except Exception as e:
        results.append({'error': str(e)})

    return {"findings": results}


def scan_lambda():
    lambda_client = boto3.client('lambda')
    results = []

    try:
        functions = lambda_client.list_functions()['Functions']
        for fn in functions:
            results.append({
                'type': 'Lambda',
                'function_name': fn['FunctionName'],
                'runtime': fn['Runtime'],
                'handler': fn['Handler'],
                'role': fn['Role']
            })
    except Exception as e:
        results.append({'error': str(e)})

    return {"findings": results}

def scan_iam():
    findings = []
    iam_client = boto3.client('iam')
    users = iam_client.list_users()["Users"]
    for user in users:
        mfa_devices = iam_client.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa_devices:
            findings.append({
                "UserName": user["UserName"],
                "Created": user["CreateDate"]
            })
            # Insert into DB
            insert_cspm_finding(
                service="IAM",
                issue_type="User Without MFA",
                resource_id=user["UserName"],
                details=user
            )
    return {"findings": findings}  # ✅ changed key to findings

def scan_s3():
    findings = []
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()["Buckets"]
    for bucket in buckets:
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket["Name"])
            for grant in acl["Grants"]:
                if "AllUsers" in str(grant["Grantee"]):
                    findings.append({
                        "Bucket": bucket["Name"],
                        "ACL": acl
                    })
                    insert_cspm_finding(
                        service="S3",
                        issue_type="Public Bucket",
                        resource_id=bucket["Name"],
                        details=acl
                    )
        except Exception as e:
            print(f"Error scanning bucket {bucket['Name']}: {e}")
    return {"findings": findings}


def scan_ec2():
    findings = []
    ec2_client = boto3.client('ec2')
    sec_groups = ec2_client.describe_security_groups()["SecurityGroups"]
    for sg in sec_groups:
        if not sg["IpPermissions"] and not sg["IpPermissionsEgress"]:
            findings.append({
                "GroupId": sg["GroupId"],
                "Description": sg.get("Description", "No description")
            })
            insert_cspm_finding(
                service="EC2",
                issue_type="Unused Security Group",
                resource_id=sg["GroupId"],
                details=sg
            )
    return {"findings": findings}


def scan_lambda():
    findings = []
    lambda_client = boto3.client('lambda')
    functions = lambda_client.list_functions()["Functions"]
    for fn in functions:
        config = lambda_client.get_function_configuration(FunctionName=fn["FunctionName"])
        if not config.get("Environment", {}).get("Variables"):
            findings.append({
                "FunctionName": fn["FunctionName"],
                "Configuration": config
            })
            insert_cspm_finding(
                service="Lambda",
                issue_type="No Environment Variables",
                resource_id=fn["FunctionName"],
                details=config
            )
    return {"findings": findings}


def scan_rds():
    findings = []
    rds_client = boto3.client('rds')
    instances = rds_client.describe_db_instances()["DBInstances"]
    for instance in instances:
        if not instance.get("StorageEncrypted", False):
            findings.append({
                "DBInstanceIdentifier": instance["DBInstanceIdentifier"],
                "Engine": instance["Engine"]
            })
            insert_cspm_finding(
                service="RDS",
                issue_type="Unencrypted RDS",
                resource_id=instance["DBInstanceIdentifier"],
                details=instance
            )
    return {"findings": findings}


