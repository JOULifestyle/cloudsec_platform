import boto3

def scan_ec2():
    ec2 = boto3.client("ec2")
    instances = ec2.describe_instances()
    findings = []

    for reservation in instances.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            findings.append({
                "instance_id": instance["InstanceId"],
                "state": instance["State"]["Name"],
                "public_ip": instance.get("PublicIpAddress"),
                "security_groups": instance.get("SecurityGroups", [])
            })
    return findings
