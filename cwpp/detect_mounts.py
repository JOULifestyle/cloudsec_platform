# cwpp/threat_detection/detect_mounts.py

def detect_suspicious_mounts(container):
    suspicious = []
    mounts = container.attrs.get("Mounts", [])
    binds = container.attrs.get("HostConfig", {}).get("Binds", [])

    sensitive_paths = ["/", "/var/run/docker.sock", "/etc", "/root", "/boot"]
    all_mounts = binds + [mount.get("Source", "") for mount in mounts]

    for path in all_mounts:
        for sensitive in sensitive_paths:
            if path.startswith(sensitive):
                suspicious.append(path)
    return suspicious
