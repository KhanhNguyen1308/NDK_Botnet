import time
import json
import requests
from datetime import datetime
import wmi
import win32com.client
import pythoncom

# Django server URL
DJANGO_SERVER_URL = "http://127.0.0.1:8000/usb/webhook/"

def get_usb_devices():
    """Get all USB devices connected to the system using WMI"""
    pythoncom.CoInitialize()  # Initialize COM for this thread
    c = wmi.WMI()
    devices = []
    
    # Get USB devices
    for usb in c.Win32_USBControllerDevice():
        try:
            # Get the dependent device
            dependent = usb.Dependent
            if dependent:
                device_id = dependent.DeviceID
    
                # Get device info
                for pnp_entity in c.Win32_PnPEntity():
                    if pnp_entity.DeviceID == device_id:
                        vendor_id = ""
                        product_id = ""
                        
                        # Extract vendor and product ID from hardware ID if available
                        if pnp_entity.HardwareID:
                            for hw_id in pnp_entity.HardwareID:
                                if "VID_" in hw_id and "PID_" in hw_id:
                                    parts = hw_id.split("\\")[1].split("&")
                                    for part in parts:
                                        if part.startswith("VID_"):
                                            vendor_id = part[4:]
                                        elif part.startswith("PID_"):
                                            product_id = part[4:]
                                    break
                        
                        details = {
                            "action": "present",
                            "device_node": pnp_entity.DeviceID,
                            "device_type": "usb",
                            "vendor_id": vendor_id,
                            "product_id": product_id,
                            "manufacturer": pnp_entity.Manufacturer or "",
                            "product": pnp_entity.Caption or pnp_entity.Description or "",
                            "serial": pnp_entity.PNPDeviceID.split("\\")[-1] if pnp_entity.PNPDeviceID else "",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        devices.append(details)
        except Exception as e:
            print(f"Error processing device: {e}")
    
    pythoncom.CoUninitialize()  # Clean up COM resources
    return devices

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

def setup_wmi_event_watcher():
    """Set up WMI event watcher for device changes"""
    pythoncom.CoInitialize()  # Initialize COM for this thread
    
    wmi_service = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    wmi_obj = wmi_service.ConnectServer(".", "root\\cimv2")
    
    # Create event watcher
    watcher = wmi_obj.ExecNotificationQuery(
        "SELECT * FROM __InstanceOperationEvent WITHIN 1 WHERE "
        "TargetInstance ISA 'Win32_PnPEntity'"
    )
    
    return watcher

def monitor_usb_devices():
    """Monitor USB devices for changes using WMI events"""
    print("USB monitoring started. Watching for events...")
    
    # Get initial devices
    initial_devices = get_usb_devices()
    print(initial_devices)
    known_devices = {d["device_node"]: d for d in initial_devices}
    
    # Send initial device information
    for device in initial_devices:
        if "USB" in device["product"]:  # Filter to likely USB devices
            print(f"Found USB device: {device['product']}")
            send_to_django(device)
    
    # Set up WMI event watcher
    try:
        watcher = setup_wmi_event_watcher()
        
        while True:
            try:
                # Wait for an event with timeout
                event = watcher.NextEvent(100)  # 1 second timeout
                # Check if event is for a USB device
                target = event.TargetInstance
                print(target.Caption)
                if "USB" in target.Caption or "USB" in target.Description:
                    # Sleep briefly to allow system to update device info
                    time.sleep(0.1)
                    # Get current device list
                    current_devices = get_usb_devices()
                    current_device_nodes = {d["device_node"]: d for d in current_devices}
                    
                    # Check for added devices
                    for node, device in current_device_nodes.items():
                        if node not in known_devices and "USB" in device["product"]:
                            device["action"] = "add"
                            print(f"USB connected: {device['product']}")
                            print(json.dumps(device, indent=2))
                            send_to_django(device)
                    
                    # Check for removed devices
                    for node, device in known_devices.items():
                        if node not in current_device_nodes and "USB" in device["product"]:
                            device["action"] = "remove"
                            device["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"USB disconnected: {device['product']}")
                            print(json.dumps(device, indent=2))
                            send_to_django(device)
                    
                    # Update known devices
                    known_devices = current_device_nodes.copy()
            
            except pythoncom.com_error as e:
                # Timeout or other COM error, do a full refresh periodically
                if e.args[0] == -2147352567:  # Timeout error code
                    # Get current device list periodically to catch any missed events
                    current_devices = get_usb_devices()
                    current_device_nodes = {d["device_node"]: d for d in current_devices}
                    
                    # Check for changes
                    for node, device in current_device_nodes.items():
                        if node not in known_devices and "USB" in device["product"]:
                            device["action"] = "add"
                            print(f"USB connected (periodic check): {device['product']}")
                            send_to_django(device)
                    
                    for node, device in known_devices.items():
                        if node not in current_device_nodes and "USB" in device["product"]:
                            device["action"] = "remove"
                            device["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"USB disconnected (periodic check): {device['product']}")
                            send_to_django(device)
                    
                    # Update known devices
                    known_devices = current_device_nodes.copy()
                else:
                    print(f"COM error: {e}")
                    time.sleep(1)  # Avoid tight loop on error
            
            except Exception as e:
                print(f"Error in event processing: {e}")
                time.sleep(1)  # Avoid tight loop on error
        
    except KeyboardInterrupt:
        print("USB monitoring stopped by user")
    finally:
        pythoncom.CoUninitialize()  # Clean up COM resources

if __name__ == "__main__":
    try:
        monitor_usb_devices()
    except Exception as e:
        print(f"Fatal error: {e}")