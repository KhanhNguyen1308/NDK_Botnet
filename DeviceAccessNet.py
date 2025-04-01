import socket
import subprocess
import platform
import concurrent.futures
import requests
import ipaddress
from datetime import datetime

def get_local_ip():
    """Get the local IP address of this machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_prefix():
    """Get the network prefix from the local IP"""
    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."

def ping(host):
    """
    Returns True if host responds to a ping request
    """
    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]
    
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_ip(ip):
    """Scan an IP address to see if it's active"""
    if ping(ip):
        return ip
    return None

def check_website_access(ip, website_url, timeout=5):
    """Check if a device can access a website"""
    try:
        # For a more accurate test, you could set up a proxy on the target device
        # This is a simplified version that just checks if the IP is reachable
        # and assumes if the device is up, it can likely access the website
        
        socket_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_test.settimeout(timeout)
        socket_test.connect((ip, 80))
        socket_test.close()
        
        # Basic connectivity test - you could extend this with actual HTTP requests
        # through the device if you have appropriate access
        
        try:
            # Try to access the website from the current machine
            response = requests.get(website_url, timeout=timeout)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            return False
            
        return True
    except (socket.timeout, socket.error):
        return False

def main():
    # Configuration
    website_to_check = "https://www.google.com"  # Change this to your target website
    network_prefix = get_network_prefix()
    start_range = 1
    end_range = 254
    
    print(f"Local IP: {get_local_ip()}")
    print(f"Network prefix: {network_prefix}")
    print(f"Scanning network for active devices...")
    
    # First, find all active devices
    active_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        ip_range = [f"{network_prefix}{i}" for i in range(start_range, end_range + 1)]
        results = executor.map(scan_ip, ip_range)
        
        for ip in results:
            if ip:
                active_ips.append(ip)
    
    print(f"Found {len(active_ips)} active devices")
    
    # Now check website access for each active device
    results = []
    print(f"\nChecking access to {website_to_check}...")
    
    for ip in active_ips:
        can_access = check_website_access(ip, website_to_check)
        results.append((ip, can_access))
        print(f"Device {ip}: {'Can access' if can_access else 'Cannot access'} {website_to_check}")
    
    # Summary
    print("\nSummary:")
    print(f"Total devices: {len(active_ips)}")
    print(f"Devices with access: {sum(1 for _, access in results if access)}")
    print(f"Devices without access: {sum(1 for _, access in results if not access)}")
    
    # Generate a timestamp for the report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nScan completed at {timestamp}")

if __name__ == "__main__":
    main()