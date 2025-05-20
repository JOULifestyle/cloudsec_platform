# cwpp/threat_detection/detect_outdated_images.py

def detect_outdated_images(container):
    image_name = container.attrs.get("Config", {}).get("Image", "")
    return ":latest" in image_name or image_name.endswith(":latest")
