import time
import pyudev
import json
import requests
from datetime import datetime

# Django server URL
DJANGO_SERVER_URL = "https://ndk.khanhnguyenduy1308.com/usb/usb/webhook/"

def get_device_details(device):
    """Extract relevant USB device details"""
    details = {
        "action": device.action,
        "device_node": getattr(device, "device_node", ""),
        "device_type": device.subsystem,
        "vendor_id": device.attributes.get("idVendor", "").decode("utf-8") if hasattr(device.attributes, "get") and device.attributes.get("idVendor") else "",
        "product_id": device.attributes.get("idProduct", "").decode("utf-8") if hasattr(device.attributes, "get") and device.attributes.get("idProduct") else "",
        "manufacturer": device.attributes.get("manufacturer", "").decode("utf-8") if hasattr(device.attributes, "get") and device.attributes.get("manufacturer") else "",
        "product": device.attributes.get("product", "").decode("utf-8") if hasattr(device.attributes, "get") and device.attributes.get("product") else "",
        "serial": device.attributes.get("serial", "").decode("utf-8") if hasattr(device.attributes, "get") and device.attributes.get("serial") else "",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return details

def send_to_django(device_info):
    """Send device information to Django application"""
    try:
        response = requests.post(
            DJANGO_SERVER_URL,
            json=device_info,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 200:
            print(f"Successfully sent data to Django for {device_info.get('product', 'Unknown Device')}")
        else:
            print(f"Failed to send data. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending data to Django: {e}")

def monitor_usb_devices():
    """Monitor USB devices for add/remove events"""
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')
    
    # Enable monitoring
    monitor.start()
    
    print("USB monitoring started. Waiting for events...")
    
    for device in iter(monitor.poll, None):
        if device.action in ('add', 'remove'):
            print(f"USB {device.action} event detected")
            device_info = get_device_details(device)
            print(json.dumps(device_info, indent=2))
            send_to_django(device_info)

if __name__ == "__main__":
    try:
        monitor_usb_devices()
    except KeyboardInterrupt:
        print("USB monitoring stopped by user")