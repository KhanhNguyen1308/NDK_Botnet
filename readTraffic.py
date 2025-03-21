#!/usr/bin/env python3
import pyshark
import time
import argparse
from collections import Counter
import os

def analyze_live_capture(interface, duration=60, packet_count=None, bpf_filter=None, display_live=True):
    """
    Capture and analyze live traffic on the specified interface.
    
    Parameters:
    - interface: Network interface to capture on
    - duration: Duration in seconds to capture (default: 60)
    - packet_count: Maximum number of packets to capture (default: None/unlimited)
    - bpf_filter: Berkeley Packet Filter expression (default: None)
    - display_live: Whether to print packets as they arrive
    
    Returns:
    - List of captured packets
    """
    print(f"Starting live capture on interface '{interface}'")
    
    # Create capture object
    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=bpf_filter
    )
    
    # Set timeout
    if packet_count is None:
        capture.sniff_timeout = duration
    
    # Dictionary to track protocols
    protocol_counter = Counter()
    
    # Start capture
    start_time = time.time()
    packets = []
    
    try:
        # Sniff packets
        if packet_count:
            capture.sniff(packet_count=packet_count)
        else:
            capture.sniff(timeout=duration)
        
        # Process captured packets
        for i, packet in enumerate(capture):
            packets.append(packet)
            
            # Get highest layer protocol
            highest_layer = packet.highest_layer
            protocol_counter[highest_layer] += 1
            
            if display_live:
                print(f"\nPacket {i+1}:")
                print(f"  Time: {packet.sniff_time}")
                print(f"  Highest Layer Protocol: {highest_layer}")
                try:
                    # Try to get source and destination
                    if hasattr(packet, 'ip'):
                        print(f"  Source IP: {packet.ip.src}")
                        print(f"  Destination IP: {packet.ip.dst}")
                    elif hasattr(packet, 'ipv6'):
                        print(f"  Source IP: {packet.ipv6.src}")
                        print(f"  Destination IP: {packet.ipv6.dst}")
                        
                    # Get transport layer info if available
                    if hasattr(packet, 'tcp'):
                        print(f"  Source Port: {packet.tcp.srcport}")
                        print(f"  Destination Port: {packet.tcp.dstport}")
                    elif hasattr(packet, 'udp'):
                        print(f"  Source Port: {packet.udp.srcport}")
                        print(f"  Destination Port: {packet.udp.dstport}")
                except AttributeError:
                    pass
                
                # Additional protocol-specific information
                for layer in packet.layers:
                    protocol = layer.layer_name.upper()
                    if protocol not in ('FRAME', 'ETH'):  # Skip frame and ethernet layers
                        print(f"  {protocol} Layer Details:")
                        for field_name in layer.field_names:
                            try:
                                # Get only interesting fields, avoiding verbose output
                                if ('src' in field_name or 'dst' in field_name or 
                                    'port' in field_name or 'type' in field_name or
                                    'version' in field_name or 'method' in field_name):
                                    value = getattr(layer, field_name)
                                    print(f"    {field_name}: {value}")
                            except AttributeError:
                                pass
    
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    finally:
        elapsed_time = time.time() - start_time
        
        # Display summary
        print("\n" + "="*50)
        print(f"Capture Summary (Duration: {elapsed_time:.2f}s)")
        print("="*50)
        print(f"Total Packets: {len(packets)}")
        
        # Protocol distribution
        if protocol_counter:
            print("\nProtocol Distribution:")
            for protocol, count in protocol_counter.most_common():
                percentage = (count / len(packets)) * 100 if packets else 0
                print(f"  {protocol}: {count} packets ({percentage:.2f}%)")
    
    return packets

def analyze_pcap_file(filename):
    """
    Analyze packets from a pcap file
    
    Parameters:
    - filename: Path to pcap file
    
    Returns:
    - List of analyzed packets
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return []
    
    print(f"Analyzing pcap file: {filename}")
    
    # Create FileCapture object
    capture = pyshark.FileCapture(filename)
    
    # Dictionary to track protocols
    protocol_counter = Counter()
    packets = []
    
    try:
        # Process all packets
        for i, packet in enumerate(capture):
            packets.append(packet)
            
            # Get highest layer protocol
            highest_layer = packet.highest_layer
            protocol_counter[highest_layer] += 1
            
            print(f"\nPacket {i+1}:")
            print(f"  Time: {packet.sniff_time}")
            print(f"  Highest Layer Protocol: {highest_layer}")
            
            try:
                # Try to get source and destination
                if hasattr(packet, 'ip'):
                    print(f"  Source IP: {packet.ip.src}")
                    print(f"  Destination IP: {packet.ip.dst}")
                elif hasattr(packet, 'ipv6'):
                    print(f"  Source IP: {packet.ipv6.src}")
                    print(f"  Destination IP: {packet.ipv6.dst}")
                    
                # Get transport layer info if available
                if hasattr(packet, 'tcp'):
                    print(f"  Source Port: {packet.tcp.srcport}")
                    print(f"  Destination Port: {packet.tcp.dstport}")
                elif hasattr(packet, 'udp'):
                    print(f"  Source Port: {packet.udp.srcport}")
                    print(f"  Destination Port: {packet.udp.dstport}")
            except AttributeError:
                pass
            
            # Additional protocol-specific information
            for layer in packet.layers:
                protocol = layer.layer_name.upper()
                if protocol not in ('FRAME', 'ETH'):  # Skip frame and ethernet layers
                    print(f"  {protocol} Layer Details:")
                    for field_name in layer.field_names:
                        try:
                            # Get only interesting fields, avoiding verbose output
                            if ('src' in field_name or 'dst' in field_name or 
                                'port' in field_name or 'type' in field_name or
                                'version' in field_name or 'method' in field_name):
                                value = getattr(layer, field_name)
                                print(f"    {field_name}: {value}")
                        except AttributeError:
                            pass
    
    except Exception as e:
        print(f"Error processing file: {e}")
    finally:
        capture.close()
        
        # Display summary
        print("\n" + "="*50)
        print("Capture Summary")
        print("="*50)
        print(f"Total Packets: {len(packets)}")
        
        # Protocol distribution
        if protocol_counter:
            print("\nProtocol Distribution:")
            for protocol, count in protocol_counter.most_common():
                percentage = (count / len(packets)) * 100 if packets else 0
                print(f"  {protocol}: {count} packets ({percentage:.2f}%)")
    
    return packets

def get_available_interfaces():
    """List available network interfaces"""
    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        print("netifaces module not installed. Cannot list available interfaces.")
        print("Install with: pip install netifaces")
        return []

def main():
    parser = argparse.ArgumentParser(description='Network Protocol Analyzer using pyshark')
    
    # Capture options
    capture_group = parser.add_mutually_exclusive_group(required=True)
    capture_group.add_argument('-i', '--interface', help='Network interface for live capture')
    capture_group.add_argument('-f', '--file', help='PCAP file to analyze')
    capture_group.add_argument('-l', '--list-interfaces', action='store_true', help='List available network interfaces')
    
    # Live capture options
    parser.add_argument('-d', '--duration', type=int, default=60,
                        help='Duration in seconds for live capture (default: 60)')
    parser.add_argument('-c', '--count', type=int, help='Maximum number of packets to capture')
    parser.add_argument('-b', '--bpf-filter', help='Berkeley Packet Filter expression')
    parser.add_argument('--silent', action='store_true', help='Do not display packets in real-time')
    
    args = parser.parse_args()
    
    # List interfaces
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        if interfaces:
            print("Available network interfaces:")
            for iface in interfaces:
                print(f"  - {iface}")
        return
    
    # Live capture
    if args.interface:
        analyze_live_capture(
            interface=args.interface,
            duration=args.duration,
            packet_count=args.count,
            bpf_filter=args.bpf_filter,
            display_live=not args.silent
        )
    
    # Analyze PCAP file
    elif args.file:
        analyze_pcap_file(args.file)

if __name__ == "__main__":
    main()