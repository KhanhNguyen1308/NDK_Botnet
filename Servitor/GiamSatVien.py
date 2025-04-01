import socket
import time
import threading
import subprocess
import logging
import requests
import ipaddress
import platform
import json
from scapy.all import ARP, Ether, srp
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from datetime import datetime
from queue import Queue
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='network_monitor.log',
    filemode='a'
)
logger = logging.getLogger('NetworkMonitor')

class NetworkMonitor:
    """
    Network Monitor for Windows that detects devices on the local network,
    identifies potentially unauthorized connections, and takes protective actions.
    """
    
    def __init__(self, config=None):
        """
        Initialize the NetworkMonitor with configuration settings.
        
        Args:
            config (dict): Configuration dictionary with settings
        """
        self.config = config or {
            'local_network': '192.168.1.0/24',  # Default local network CIDR
            'scan_interval': 60,  # Seconds between scans
            'django_server': 'http://localhost:8000/api/logs/',  # Log server URL
            'api_key': 'your_api_key_here',  # API key for authentication
            'authorized_macs': [],  # List of authorized MAC addresses
            'log_locally': True,  # Whether to log locally
            'block_unauthorized': True,  # Whether to block unauthorized devices
            'max_servitors': 10,  # Maximum number of worker threads
        }
        
        # Validate we're running on Windows
        if platform.system() != 'Windows':
            logger.error("This script is designed for Windows OS only.")
            raise OSError("This script is designed for Windows OS only.")
        
        # Parse the local network CIDR notation
        try:
            self.local_network = ipaddress.IPv4Network(self.config['local_network'])
            logger.info(f"Monitoring local network: {self.local_network}")
        except ValueError as e:
            logger.error(f"Invalid network address format: {e}")
            raise
            
        # Store for known devices - format: {MAC: {'ip': IP, 'last_seen': timestamp, 'status': 'authorized|unauthorized|blocked'}}
        self.known_devices = {}
        
        # Thread-safe queue for logging events
        self.log_queue = Queue()
        
        # Flag to control the monitoring and logging threads
        self.running = False
        
        # Lock for thread-safe operations on shared data
        self.lock = threading.Lock()
        
    def start(self):
        """Start the network monitoring and logging threads."""
        if self.running:
            logger.warning("Network monitor is already running.")
            return
            
        self.running = True
        
        # Start log processing thread
        self.log_thread = threading.Thread(target=self._process_logs, daemon=True)
        self.log_thread.start()
        
        # Start network scanning thread
        self.scan_thread = threading.Thread(target=self._scan_network_periodically, daemon=True)
        self.scan_thread.start()
        
        logger.info("Network monitoring started.")
        
    def stop(self):
        """Stop all monitoring and logging threads."""
        self.running = False
        logger.info("Network monitoring stopped.")
        
    def _scan_network_periodically(self):
        """Continuously scan the network at regular intervals."""
        while self.running:
            try:
                self._scan_network()
                time.sleep(self.config['scan_interval'])
            except Exception as e:
                logger.error(f"Error during network scan: {e}")
                time.sleep(10)  # Short delay before retry on error
    
    def _scan_network(self):
        """
        Scan the local network for devices using ARP.
        Identify new devices and check their status.
        """
        logger.info(f"Scanning network {self.local_network}...")
        
        # Create ARP request packet
        arp = ARP(pdst=str(self.local_network))
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
        packet = ether/arp
        
        try:
            # Send ARP request and get responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process discovered devices
            current_devices = set()
            
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                current_devices.add(mac)
                
                with self.lock:
                    if mac not in self.known_devices:
                        # New device discovered
                        is_authorized = mac in self.config['authorized_macs']
                        status = 'authorized' if is_authorized else 'unauthorized'
                        
                        self.known_devices[mac] = {
                            'ip': ip,
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now(),
                            'status': status
                        }
                        
                        self._log_event({
                            'event_type': 'device_discovered',
                            'ip': ip,
                            'mac': mac,
                            'status': status,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Check if device has internet access
                        if status == 'unauthorized' and self._has_internet_access(ip):
                            self._handle_unauthorized_device(mac, ip)
                    else:
                        # Update existing device
                        self.known_devices[mac]['last_seen'] = datetime.now()
                        self.known_devices[mac]['ip'] = ip  # IP might have changed (DHCP)
                        
                        # Recheck unauthorized devices
                        if self.known_devices[mac]['status'] == 'unauthorized':
                            if self._has_internet_access(ip):
                                self._handle_unauthorized_device(mac, ip)
            
            # Check for devices that disappeared
            with self.lock:
                for mac in list(self.known_devices.keys()):
                    if mac not in current_devices:
                        if (datetime.now() - self.known_devices[mac]['last_seen']).total_seconds() > 300:  # 5 minutes
                            # Device has been gone for 5 minutes, log and remove
                            self._log_event({
                                'event_type': 'device_disappeared',
                                'ip': self.known_devices[mac]['ip'],
                                'mac': mac,
                                'status': self.known_devices[mac]['status'],
                                'timestamp': datetime.now().isoformat()
                            })
                            del self.known_devices[mac]
            
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            raise
    
    def _has_internet_access(self, ip):
        """
        Check if a device has internet access by monitoring traffic.
        This is a simplified check and would need enhancement in production.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if device appears to have internet access
        """
        # In a real implementation, you might:
        # 1. Use netflow data to check for connections to external IPs
        # 2. Check firewall logs
        # 3. Use packet capture to detect connections outside local network
        
        # For this example, we're using a simple approach
        # Check if the IP is making connections to ports commonly used for internet access
        common_ports = [80, 443, 8080]
        
        try:
            for port in common_ports:
                # Create a socket to check if the port is open
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                s.close()
                
                if result == 0:
                    # Port is open, device might have internet access
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking internet access for {ip}: {e}")
            return False
    
    def _handle_unauthorized_device(self, mac, ip):
        """
        Handle an unauthorized device with internet access.
        
        Args:
            mac (str): MAC address of the device
            ip (str): IP address of the device
        """
        logger.warning(f"Unauthorized device detected: {mac} ({ip}) with internet access")
        
        with self.lock:
            self.known_devices[mac]['status'] = 'blocked'
        
        self._log_event({
            'event_type': 'unauthorized_access',
            'ip': ip,
            'mac': mac,
            'action': 'blocking',
            'timestamp': datetime.now().isoformat()
        })
        
        if self.config['block_unauthorized']:
            # Block the device using Windows Firewall
            self._block_device(ip)
            
            # Initiate DDoS protection (rate-limited traffic to disrupt connection)
            threading.Thread(target=self._protective_ddos, args=(ip,), daemon=True).start()
    
    def _block_device(self, ip):
        """
        Block a device using Windows Firewall.
        
        Args:
            ip (str): IP address to block
        """
        try:
            # Create Windows Firewall rule to block the IP
            rule_name = f"BlockUnauthorized_{ip.replace('.', '_')}"
            
            # Check if rule already exists
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            check_process = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if "No rules match the specified criteria" in check_process.stdout:
                # Rule doesn't exist, create it
                block_cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_name}"',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip}',
                    'enable=yes',
                    'profile=any',
                    'description="Automatically blocked unauthorized device"'
                ]
                
                subprocess.run(block_cmd, check=True)
                logger.info(f"Successfully blocked unauthorized device {ip}")
                
                # Also block outgoing connections
                block_out_cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_name}_out"',
                    'dir=out',
                    'action=block',
                    f'remoteip={ip}',
                    'enable=yes',
                    'profile=any',
                    'description="Automatically blocked unauthorized device (outbound)"'
                ]
                
                subprocess.run(block_out_cmd, check=True)
            else:
                logger.info(f"Firewall rule for {ip} already exists")
                
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to block device {ip}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error blocking device {ip}: {e}")
    
    def _protective_ddos(self, target_ip, duration=30, rate_limit=500):
        """
        Perform a controlled, defensive traffic generation to disrupt unauthorized connections.
        This is a simplified implementation for educational purposes.
        
        NOTE: In a real-world scenario, you should use proper network security tools
        and not perform actual DoS attacks, even against unauthorized devices.
        This could violate laws and network policies.
        
        Args:
            target_ip (str): IP address to target
            duration (int): Duration in seconds
            rate_limit (int): Maximum packets per second to avoid overloading network
        """
        logger.warning(f"Starting protective traffic generation against {target_ip}")
        
        try:
            start_time = time.time()
            packets_sent = 0
            
            # Use a random high port for the target to avoid disrupting common services
            target_port = 40000 + int(time.time() % 10000)
            
            while time.time() - start_time < duration and self.running:
                # Create a TCP SYN packet
                packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
                
                # Send the packet
                send(packet, verbose=0)
                packets_sent += 1
                
                # Rate limiting to avoid overwhelming our own network
                if packets_sent % rate_limit == 0:
                    time.sleep(1)
            
            logger.info(f"Completed protective traffic generation against {target_ip}. Packets sent: {packets_sent}")
            
        except Exception as e:
            logger.error(f"Error during protective traffic generation: {e}")
    
    def _log_event(self, event_data):
        """
        Queue an event for logging.
        
        Args:
            event_data (dict): Event data to log
        """
        self.log_queue.put(event_data)
    
    def _process_logs(self):
        """Process queued log events and send them to the Django server."""
        batch_size = 10
        batch = []
        last_send_time = time.time()
        
        while self.running:
            try:
                # Try to get a log event with a timeout
                try:
                    event = self.log_queue.get(timeout=5)
                    batch.append(event)
                    self.log_queue.task_done()
                except Queue.Empty:
                    # No new events, check if we need to send batch due to time
                    pass
                
                # Send batch if it's full or if enough time has passed
                if len(batch) >= batch_size or (time.time() - last_send_time > 30 and batch):
                    self._send_logs_to_server(batch)
                    batch = []
                    last_send_time = time.time()
                    
            except Exception as e:
                logger.error(f"Error processing logs: {e}")
                time.sleep(5)  # Back off on error
    
    def _send_logs_to_server(self, logs):
        """
        Send logs to the Django server.
        
        Args:
            logs (list): List of log events to send
        """
        if not logs:
            return
            
        # Log locally if configured
        if self.config['log_locally']:
            for log in logs:
                logger.info(f"Event: {json.dumps(log)}")
        
        # Send to Django server
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.config["api_key"]}'
            }
            
            data = {
                'logs': logs,
                'source': socket.gethostname(),
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                self.config['django_server'],
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to send logs to server. Status code: {response.status_code}, Response: {response.text}")
            else:
                logger.debug(f"Successfully sent {len(logs)} logs to server")
                
        except requests.RequestException as e:
            logger.error(f"Error sending logs to server: {e}")
            # Keep logs in memory if sending fails
            for log in logs:
                self.log_queue.put(log)
    
    def get_status_report(self):
        """
        Get a status report of all known devices.
        
        Returns:
            dict: Status report
        """
        with self.lock:
            return {
                'devices': {mac: info.copy() for mac, info in self.known_devices.items()},
                'device_count': len(self.known_devices),
                'authorized_count': sum(1 for info in self.known_devices.values() if info['status'] == 'authorized'),
                'unauthorized_count': sum(1 for info in self.known_devices.values() if info['status'] == 'unauthorized'),
                'blocked_count': sum(1 for info in self.known_devices.values() if info['status'] == 'blocked'),
                'scan_count': 0,  # Would track this in a real implementation
                'last_scan': datetime.now().isoformat()
            }

def main():
    """Main function to run the network monitor."""
    # Example configuration
    config = {
        'local_network': '192.168.1.0/24',  # Change to your local network
        'scan_interval': 60,  # Seconds between scans
        'django_server': 'http://localhost:8000/api/logs/',  # Change to your Django server
        'api_key': 'your_api_key_here',  # Change to your API key
        'authorized_macs': [
            '00:11:22:33:44:55',  # Example authorized MAC
            'aa:bb:cc:dd:ee:ff'   # Example authorized MAC
        ],
        'log_locally': True,
        'block_unauthorized': True,
        'max_servitors': 10
    }
    
    try:
        # Create and start the network monitor
        monitor = NetworkMonitor(config)
        monitor.start()
        
        # Keep the main thread running
        print("Network monitor running. Press Ctrl+C to stop.")
        while True:
            time.sleep(60)
            status = monitor.get_status_report()
            print(f"Status: {status['device_count']} devices, {status['authorized_count']} authorized, "
                  f"{status['unauthorized_count']} unauthorized, {status['blocked_count']} blocked")
            
    except KeyboardInterrupt:
        print("Stopping network monitor...")
        monitor.stop()
        print("Network monitor stopped.")
    except Exception as e:
        print(f"Error: {e}")
        logger.critical(f"Critical error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)