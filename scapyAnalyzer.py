#!/usr/bin/env python3
import scapy.all as scapy
import socket
import argparse
from collections import defaultdict
import time
import os
import pandas as pd
from datetime import datetime

class NetworkTrafficAnalyzer:
    def __init__(self, interface=None):
        self.interface = interface
        self.devices = {}  # MAC to IP mapping
        self.traffic_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'protocols': defaultdict(int),
            'destinations': defaultdict(int)
        })
        self.start_time = time.time()
    
    def get_mac_vendor(self, mac):
        """Try to identify device vendor from MAC address"""
        try:
            # This is a simplistic approach - in production you'd use a proper OUI database
            first_three_octets = mac.replace(':', '').replace('-', '').upper()[0:6]
            # This would be replaced with a proper MAC/OUI lookup
            vendors = {
                'FCFBFB': 'Apple',
            '00CDFE': 'Apple',
            '88C663': 'Apple',
            '3C0754': 'Apple',
            '34C059': 'Apple',
            '9CF48E': 'Apple',
            
            # Cisco devices
            '00259C': 'Cisco',
            '7CCB0D': 'Cisco',
            '58AC78': 'Cisco',
            'E05FB9': 'Cisco',
            '00162B': 'Cisco',
            
            # Samsung devices
            '002275': 'Samsung',
            '5CF6DC': 'Samsung',
            'F42B48': 'Samsung',
            '347195': 'Samsung',
            '8C7712': 'Samsung',
            
            # Intel devices
            '0C8BFD': 'Intel',
            '00AA00': 'Intel',
            '001517': 'Intel',
            '0022FA': 'Intel',
            
            # Dell devices
            '001422': 'Dell',
            '002219': 'Dell',
            'F8BC12': 'Dell',
            'D067E5': 'Dell',
            '5CF9DD': 'Dell',
            
            # HP devices
            '0016B9': 'HP',
            '001B78': 'HP',
            '1458D0': 'HP',
            '9457A5': 'HP',
            
            # Huawei devices
            '00E0FC': 'Huawei',
            '48DB50': 'Huawei',
            '80FB06': 'Huawei',
            '00259E': 'Huawei',
            
            # Microsoft devices
            '0025AE': 'Microsoft',
            '50F2D5': 'Microsoft',
            '985FD3': 'Microsoft',
            
            # Netgear devices
            '000FE9': 'Netgear',
            'C03F0E': 'Netgear',
            '008030': 'Netgear',
            
            # TP-Link devices
            '000AEB': 'TP-Link',
            'EC086B': 'TP-Link',
            '54E6FC': 'TP-Link',
            
            # Linksys devices
            '000C41': 'Linksys',
            '001310': 'Linksys',
            '00121C': 'Linksys',
            
            # Asus devices
            '001BFC': 'Asus',
            '485D60': 'Asus',
            '00248C': 'Asus',
            
            # Google devices
            'F4F5D8': 'Google',
            '94EB2C': 'Google',
            '2C4D54': 'Google',
            
            # Aruba devices
            '000B86': 'Aruba',
            '001A1E': 'Aruba',
            '9C1C12': 'Aruba',
            
            # D-Link devices
            '00179A': 'D-Link',
            '1CAFF7': 'D-Link',
            '14D64D': 'D-Link',
            
            # Sony devices
            '001D0D': 'Sony',
            '001315': 'Sony',
            'FC0FE6': 'Sony',
            
            # Ubiquiti devices
            '00156D': 'Ubiquiti',
            'F09FC2': 'Ubiquiti',
            'DCFB02': 'Ubiquiti',
            
            # Xiaomi devices
            '286C07': 'Xiaomi',
            '9C99A0': 'Xiaomi',
            'F8A45F': 'Xiaomi',
            
            # Lenovo devices
            '00061B': 'Lenovo',
            'E068EB': 'Lenovo',
            '70720D': 'Lenovo'
            }
            return vendors.get(first_three_octets, 'Unknown')
        except:
            return 'Unknown'
    
    def get_hostname(self, ip):
        """Try to resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
    
    def process_packet(self, packet):
        """Process a single packet and update traffic statistics"""
        if not packet.haslayer(scapy.IP):
            return
        
        # Extract packet information
        ip_layer = packet.getlayer(scapy.IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)
        
        # Extract MAC addresses when available
        src_mac = dst_mac = None
        if packet.haslayer(scapy.Ether):
            eth_layer = packet.getlayer(scapy.Ether)
            src_mac = eth_layer.src
            dst_mac = eth_layer.dst
            
            # Update device database
            if src_mac not in self.devices:
                self.devices[src_mac] = {
                    'ip': src_ip,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'vendor': self.get_mac_vendor(src_mac),
                    'hostname': self.get_hostname(src_ip)
                }
            else:
                self.devices[src_mac]['last_seen'] = datetime.now()
                self.devices[src_mac]['ip'] = src_ip  # Update IP in case it changed (DHCP)
        
        # Determine protocol
        protocol = "Other"
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            tcp_layer = packet.getlayer(scapy.TCP)
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                protocol = "HTTP"
            elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                protocol = "HTTPS"
            elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                protocol = "SSH"
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            udp_layer = packet.getlayer(scapy.UDP)
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                protocol = "DNS"
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
        
        # Update traffic statistics for source device (outgoing traffic)
        if src_mac:
            self.traffic_stats[src_mac]['bytes_sent'] += length
            self.traffic_stats[src_mac]['packets_sent'] += 1
            self.traffic_stats[src_mac]['protocols'][protocol] += 1
            self.traffic_stats[src_mac]['destinations'][dst_ip] += 1
        
        # Update traffic statistics for destination device (incoming traffic)
        if dst_mac and dst_mac in self.devices:  # Only track for known local devices
            self.traffic_stats[dst_mac]['bytes_received'] += length
            self.traffic_stats[dst_mac]['packets_received'] += 1
    
    def start_capture(self, count=0, timeout=None):
        """Start capturing packets"""
        print(f"Starting traffic capture on interface {self.interface or 'default'}")
        print("Press Ctrl+C to stop capturing and view results")
        
        try:
            # Start packet capture
            scapy.sniff(iface=self.interface, prn=self.process_packet, 
                        store=False, count=count, timeout=timeout)
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        finally:
            self.display_results()
    
    def generate_report(self, output_file=None):
        """Generate a detailed report of the traffic analysis"""
        # Create device DataFrame
        devices_data = []
        for mac, info in self.devices.items():
            traffic = self.traffic_stats[mac]
            
            devices_data.append({
                'MAC': mac,
                'IP': info['ip'],
                'Hostname': info['hostname'],
                'Vendor': info['vendor'],
                'First Seen': info['first_seen'],
                'Last Seen': info['last_seen'],
                'Bytes Sent': traffic['bytes_sent'],
                'Bytes Received': traffic['bytes_received'],
                'Packets Sent': traffic['packets_sent'],
                'Packets Received': traffic['packets_received'],
                'Total Traffic (MB)': (traffic['bytes_sent'] + traffic['bytes_received']) / 1024 / 1024,
                'Top Protocol': max(traffic['protocols'].items(), key=lambda x: x[1])[0] if traffic['protocols'] else "N/A",
                'Top Destination': max(traffic['destinations'].items(), key=lambda x: x[1])[0] if traffic['destinations'] else "N/A"
            })
        
        df = pd.DataFrame(devices_data)
        
        # Sort by total traffic in descending order
        df = df.sort_values(by='Total Traffic (MB)', ascending=False)
        
        # Save report to file if specified
        if output_file:
            if output_file.endswith('.csv'):
                df.to_csv(output_file, index=False)
            elif output_file.endswith('.xlsx'):
                df.to_excel(output_file, index=False)
            elif output_file.endswith('.html'):
                df.to_html(output_file, index=False)
            else:
                # Default to CSV
                df.to_csv(output_file, index=False)
            print(f"Report saved to {output_file}")
        
        return df
    
    def display_results(self):
        """Display the results of the traffic analysis"""
        duration = time.time() - self.start_time
        
        print(f"\n{'=' * 80}")
        print(f"Network Traffic Analysis Report")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Devices detected: {len(self.devices)}")
        print(f"{'=' * 80}")
        
        # Generate and display the report
        df = self.generate_report()
        
        # Display summary
        print("\nTop 10 devices by traffic volume:")
        pd.set_option('display.max_rows', 10)
        pd.set_option('display.width', 160)
        print(df[['MAC', 'IP', 'Hostname', 'Vendor', 'Total Traffic (MB)', 'Top Protocol', 'Top Destination']].head(10))
        
        # Protocol distribution
        all_protocols = {}
        for mac, stats in self.traffic_stats.items():
            for protocol, count in stats['protocols'].items():
                all_protocols[protocol] = all_protocols.get(protocol, 0) + count
        
        print("\nProtocol Distribution:")
        for protocol, count in sorted(all_protocols.items(), key=lambda x: x[1], reverse=True):
            print(f"{protocol}: {count} packets")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-t', '--time', type=int, help='Capture duration in seconds')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-o', '--output', help='Output file for detailed report (CSV, XLSX, or HTML)')
    args = parser.parse_args()
    
    # Check if running as root/admin (required for packet capture)
    if os.geteuid() != 0:
        print("This script requires root/administrator privileges to capture packets.")
        print("Please run with sudo or as administrator.")
        exit(1)
    
    analyzer = NetworkTrafficAnalyzer(interface=args.interface)
    analyzer.start_capture(count=args.count, timeout=args.time)
    
    if args.output:
        analyzer.generate_report(output_file=args.output)