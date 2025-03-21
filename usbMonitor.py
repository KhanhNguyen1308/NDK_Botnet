import collections
import sys
from utils import font1
if sys.version_info >= (3, 3):
    import collections.abc as abc
else:
    import collections as abc

import pyudev
import requests
import json

def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')

    for device in iter(monitor.poll, None):
        if device.action == 'add':
            print("USB device connected!")
            usb_info = {
                'vendor_id': device.get('ID_VENDOR_ID'),
                'product_id': device.get('ID_MODEL_ID'),
                'serial': device.get('ID_SERIAL'),
                'model': device.get('ID_MODEL')
            }
            # send_usb_info_to_django(usb_info)

if __name__ == "__main__":
    monitor_usb()