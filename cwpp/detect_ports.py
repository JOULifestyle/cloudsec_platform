# cwpp/threat_detection/detect_ports.py

def detect_privileged_ports(container):
    exposed_ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
    privileged_ports = ["22/tcp", "2375/tcp", "3306/tcp"]

    return [
        port for port in privileged_ports
        if port in exposed_ports and exposed_ports[port] is not None
    ]
