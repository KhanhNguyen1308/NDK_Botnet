import pyshark
import netifaces
import subprocess

def get_local_network_ips():
    """Gets the IP addresses of the local machine's network interfaces."""
    local_ips = set()
    for interface in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for addr_info in addresses[netifaces.AF_INET]:
                    local_ips.add(addr_info['addr'])
        except OSError:
            # Handle potential permission errors or interfaces that don't exist
            pass
    return local_ips

def get_tshark_interfaces():
    try:
        process = subprocess.run(['tshark', '-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        interfaces = [line.split('. ')[1] for line in process.stdout.strip().split('\n')]
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving interfaces: {e}")
        return []
    except FileNotFoundError:
        print("tshark not found. Ensure tshark is installed and in your PATH.")
        return []

def find_devices_on_lan(interface=None, timeout=10):
    """
    Captures network traffic for a specified duration and identifies devices
    on the local network based on their MAC and IP addresses.
    """
    devices = {}
    local_ips = get_local_network_ips()

    try:
        if interface:
            capture = pyshark.LiveCapture(interface=interface, display_filter="arp or ip")
        else:
            capture = pyshark.LiveCapture(display_filter="arp or ip")

        if capture.interfaces: # Check to see if there is an interface.
            print(f"Capturing traffic on interface '{capture.interfaces[0]}' for {timeout} seconds...")
        else:
            print(f"Capturing traffic for {timeout} seconds...")
        capture.sniff(timeout=timeout)

        for packet in capture:
            if 'arp' in packet:
                ip = packet.arp.sender_ip
                mac = packet.arp.sender_hw_addr
                if ip not in local_ips:
                    devices[mac] = ip
            elif 'ip' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst

                if src_ip not in local_ips:
                    devices.setdefault(src_mac, src_ip)
                if dst_ip not in local_ips:
                    devices.setdefault(dst_mac, dst_ip)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
         if 'capture' in locals() and 'capture' in globals():
            capture.close()

    print("\nDevices found on the local network:")
    for mac, ip in devices.items():
        print(f"MAC Address: {mac}, IP Address: {ip}")

if __name__ == "__main__":
    available_interfaces = get_tshark_interfaces()
    if available_interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(available_interfaces):
            print(f"{i+1}. {iface}")

        interface_choice = input("Enter the number of the interface to capture on (or leave blank for auto-detection): ")
        selected_interface = None
        if interface_choice:
            try:
                index = int(interface_choice) - 1
                if 0 <= index < len(available_interfaces):
                    selected_interface = available_interfaces[index]
                else:
                    print("Invalid interface number.")
            except ValueError:
                print("Invalid input.")

        find_devices_on_lan(interface=selected_interface)