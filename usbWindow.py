import os
import sys
import wmi
import time
import json
import pystray
import requests
import threading
import pythoncom
import win32com.client
from datetime import datetime
from PIL import Image, ImageDraw

# Django server URL
DJANGO_SERVER_URL = "http://127.0.0.1:8000/usb/webhook/"

exit_click = False

def setup_tray_icon():
    global exit_click
    def create_image():
        
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle (executable)
            application_path = sys._MEIPASS
        else:
            # If the application is run as a script
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        icon_path = os.path.join(application_path, "icon.png")
        
        try:
            image = Image.open(icon_path)
            return image
        except Exception as e:
            print(f"Error loading icon: {e}")
            # Fallback to a generated icon
            image = Image.new('RGB', (64, 64), 'blue')
            draw = ImageDraw.Draw(image)
            draw.rectangle((16, 16, 48, 48), fill='white')
            return image

    def on_click(icon, item):
        global exit_click
        if str(item) == 'Exit':
            icon.stop()
            try:
                exit_click = True
                exit()
            except SystemExit:
                exit_click = True
        else:
            print(f"Clicked: {item}")

    image = create_image()
    menu = (pystray.MenuItem('Exit', on_click),)
    icon = pystray.Icon("USB Monitor", image, "USB Monitor", menu)
    icon.run()

def get_usb_devices():
    global exit_click
    """Get all USB devices connected to the system using WMI"""
    pythoncom.CoInitialize()  # Initialize COM for this thread
    c = wmi.WMI()
    devices = []
    
    for usb in c.Win32_USBControllerDevice():
        if exit_click: break
        try:
            dependent = usb.Dependent
            if dependent:
                device_id = dependent.DeviceID
                for pnp_entity in c.Win32_PnPEntity():
                    if exit_click: break
                    if pnp_entity.DeviceID == device_id:
                        vendor_id = ""
                        product_id = ""      
                        if pnp_entity.HardwareID:
                            for hw_id in pnp_entity.HardwareID:
                                if exit_click: break
                                if "VID_" in hw_id and "PID_" in hw_id:
                                    parts = hw_id.split("\\")[1].split("&")
                                    for part in parts:
                                        if part.startswith("VID_"): vendor_id = part[4:]
                                        elif part.startswith("PID_"): product_id = part[4:]
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

def send2Server(device_info):
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
    global exit_click
    """Monitor USB devices for changes using WMI events"""
    print("USB monitoring started. Watching for events...")
    # Get initial devices
    print("Get usb devices")
    initial_devices = get_usb_devices()
    print("Get usb devices done!!!!!!!!")
    print(initial_devices)
    known_devices = {d["device_node"]: d for d in initial_devices}
    # Send initial device information
    for device in initial_devices:
        if exit_click: break
        if "USB" in device["product"]:  # Filter to likely USB devices
            print(f"Found USB device: {device['product']}")
            send2Server(device)
    
    # Set up WMI event watcher
    try:
        watcher = setup_wmi_event_watcher()
        
        while True:
            print("exit_click: ", exit_click)
            try:
                if exit_click: break
                event = watcher.NextEvent(100)
                target = event.TargetInstance
                print(target.Caption)
                if "USB" in target.Caption or "USB" in target.Description:
                    time.sleep(0.1)
                    print("get_usb_device")
                    current_devices = get_usb_devices()
                    print("get_usb_device DONE!!!!!!!!")
                    current_device_nodes = {d["device_node"]: d for d in current_devices}
                    for node, device in current_device_nodes.items():
                        if node not in known_devices and "USB" in device["product"]:
                            device["action"] = "add"
                            print(f"USB connected: {device['product']}")
                            print(json.dumps(device, indent=2))
                            send2Server(device)
                    
                    for node, device in known_devices.items():
                        if node not in current_device_nodes and "USB" in device["product"]:
                            device["action"] = "remove"
                            device["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"USB disconnected: {device['product']}")
                            print(json.dumps(device, indent=2))
                            send2Server(device)
                    
                    known_devices = current_device_nodes.copy()
            
            except pythoncom.com_error as e:
                if e.args[0] == -2147352567:  # Timeout error code
                    current_devices = get_usb_devices()
                    current_device_nodes = {d["device_node"]: d for d in current_devices}
                    
                    for node, device in current_device_nodes.items():
                        if node not in known_devices and "USB" in device["product"]:
                            device["action"] = "add"
                            print(f"USB connected (periodic check): {device['product']}")
                            send2Server(device)
                    
                    for node, device in known_devices.items():
                        if node not in current_device_nodes and "USB" in device["product"]:
                            device["action"] = "remove"
                            device["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"USB disconnected (periodic check): {device['product']}")
                            send2Server(device)
                    
                    known_devices = current_device_nodes.copy()
                else:
                    print(f"COM error: {e}")
                    time.sleep(.5)  # Avoid tight loop on error
            
            except Exception as e:
                print(f"Error in event processing: {e}")
                time.sleep(.5)  # Avoid tight loop on error
        
    except KeyboardInterrupt:
        print("USB monitoring stopped by user")
    finally:
        pythoncom.CoUninitialize()  # Clean up COM resources

if __name__ == "__main__":
    try:
        tray_thread = threading.Thread(target=setup_tray_icon)
        tray_thread.start()
        monitor_usb_devices()
    except Exception as e:
        print(f"Fatal error: {e}")

    pythoncom.CoUninitialize()