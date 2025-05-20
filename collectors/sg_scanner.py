import boto3

def scan_security_groups():
    ec2 = boto3.client("ec2")
    sgs = ec2.describe_security_groups()
    findings = []

    for sg in sgs.get("SecurityGroups", []):
        for permission in sg.get("IpPermissions", []):
            if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in permission.get("IpRanges", [])):
                findings.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "open_port": permission.get("FromPort"),
                    "protocol": permission.get("IpProtocol")
                })
    return findings
