# cwpp/collector.py

import docker

def get_running_containers():
    client = docker.from_env()
    containers = client.containers.list()
    return containers

def detect_root_containers(containers):
    root_containers = []
    for c in containers:
        user = c.attrs['Config'].get('User', '')
        # Empty or "0" or "root" means running as root user
        if user in ['', '0', 'root']:
            root_containers.append(c)
    return root_containers

def detect_privileged_containers(containers):
    privileged_containers = []
    for c in containers:
        privileged = c.attrs['HostConfig'].get('Privileged', False)
        if privileged:
            privileged_containers.append(c)
    return privileged_containers
