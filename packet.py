#!/usr/bin/env python3
import pyshark
import time
import argparse
from collections import Counter
import os
from tabulate import tabulate
import datetime

#  protocol ports
PROTOCOL_PORTS = {
    'FTP': [20, 21],      
    'SMTP': [25, 465, 587],  
    'POP3': [110, 995],  
    'IMAP': [143, 993], 
}

def identify_protocol(packet):
    identified_protocols = []
    
    # Check for TCP/UDP
    if hasattr(packet, 'tcp'):
        identified_protocols.append('TCP')
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
    elif hasattr(packet, 'udp'):
        identified_protocols.append('UDP')
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
    else:
        return identified_protocols  # Return early if not TCP or UDP
    
    # Check for application layer protocols based on port numbers
    for protocol, ports in PROTOCOL_PORTS.items():
        if src_port in ports or dst_port in ports:
            identified_protocols.append(protocol)
    
    # Check for protocol identification from pyshark directly
    if packet.highest_layer == 'FTP' or hasattr(packet, 'ftp'):
        if 'FTP' not in identified_protocols:
            identified_protocols.append('FTP')
    if packet.highest_layer == 'SMTP' or hasattr(packet, 'smtp'):
        if 'SMTP' not in identified_protocols:
            identified_protocols.append('SMTP')
    if packet.highest_layer == 'POP' or hasattr(packet, 'pop'):
        if 'POP3' not in identified_protocols:
            identified_protocols.append('POP3')
    if packet.highest_layer == 'IMAP' or hasattr(packet, 'imap'):
        if 'IMAP' not in identified_protocols:
            identified_protocols.append('IMAP')
            
    return identified_protocols

def get_packet_details(packet, protocols):
    """Extract key information from packet into a dictionary"""
    details = {
        'number': 0,  # Will be set by the caller
        'time': packet.sniff_time.strftime('%H:%M:%S.%f')[:-3],
        'src_ip': '',
        'dst_ip': '',
        'src_port': '',
        'dst_port': '',
        'protocols': ', '.join(protocols),
        'length': packet.length if hasattr(packet, 'length') else '',
        'info': get_protocol_info(packet, protocols)
    }
    
    # Get IP information
    if hasattr(packet, 'ip'):
        details['src_ip'] = packet.ip.src
        details['dst_ip'] = packet.ip.dst
    elif hasattr(packet, 'ipv6'):
        details['src_ip'] = packet.ipv6.src
        details['dst_ip'] = packet.ipv6.dst
    
    # Get port information
    if hasattr(packet, 'tcp'):
        details['src_port'] = packet.tcp.srcport
        details['dst_port'] = packet.tcp.dstport
    elif hasattr(packet, 'udp'):
        details['src_port'] = packet.udp.srcport
        details['dst_port'] = packet.udp.dstport
        
    return details

def get_protocol_info(packet, protocols):
    """Extract protocol-specific information"""
    info = []
    
    # Get FTP info
    if 'FTP' in protocols:
        if hasattr(packet, 'ftp'):
            if hasattr(packet.ftp, 'request'):
                info.append(f"FTP: {packet.ftp.request}")
            elif hasattr(packet.ftp, 'response'):
                info.append(f"FTP: {packet.ftp.response}")
        
    # Get SMTP info
    if 'SMTP' in protocols:
        if hasattr(packet, 'smtp'):
            if hasattr(packet.smtp, 'req'):
                info.append(f"SMTP: {packet.smtp.req}")
            elif hasattr(packet.smtp, 'rsp'):
                info.append(f"SMTP: {packet.smtp.rsp}")
    
    # Get POP3 info
    if 'POP3' in protocols:
        if hasattr(packet, 'pop'):
            if hasattr(packet.pop, 'request'):
                info.append(f"POP3: {packet.pop.request}")
            elif hasattr(packet.pop, 'response'):
                info.append(f"POP3: {packet.pop.response}")
    
    # Get IMAP info
    if 'IMAP' in protocols:
        if hasattr(packet, 'imap'):
            if hasattr(packet.imap, 'request'):
                info.append(f"IMAP: {packet.imap.request}")
            elif hasattr(packet.imap, 'response'):
                info.append(f"IMAP: {packet.imap.response}")
    
    # Get TCP/UDP info if no other protocol info is available
    if not info:
        if hasattr(packet, 'tcp'):
            flags = []
            if hasattr(packet.tcp, 'flags'):
                tcp_flags = packet.tcp.flags
                if hasattr(tcp_flags, 'syn') and tcp_flags.syn == '1':
                    flags.append('SYN')
                if hasattr(tcp_flags, 'ack') and tcp_flags.ack == '1':
                    flags.append('ACK')
                if hasattr(tcp_flags, 'fin') and tcp_flags.fin == '1':
                    flags.append('FIN')
                if hasattr(tcp_flags, 'rst') and tcp_flags.rst == '1':
                    flags.append('RST')
                if hasattr(tcp_flags, 'psh') and tcp_flags.psh == '1':
                    flags.append('PSH')
            
            seq = f"Seq={packet.tcp.seq}" if hasattr(packet.tcp, 'seq') else ""
            ack = f"Ack={packet.tcp.ack}" if hasattr(packet.tcp, 'ack') else ""
            flags_str = ' '.join(flags)
            
            parts = [p for p in [flags_str, seq, ack] if p]
            if parts:
                info.append(f"TCP: {' '.join(parts)}")
    
    return " | ".join(info) if info else "No additional info"

def print_packet_table(packet_details, batch_size=50):
    """Print packet information in a table format"""
    headers = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
    
    # Process packets in batches to avoid overwhelming the terminal
    for i in range(0, len(packet_details), batch_size):
        batch = packet_details[i:i+batch_size]
        
        # Format data for tabulate
        rows = []
        for p in batch:
            src = f"{p['src_ip']}:{p['src_port']}" if p['src_port'] else p['src_ip']
            dst = f"{p['dst_ip']}:{p['dst_port']}" if p['dst_port'] else p['dst_ip']
            
            rows.append([
                p['number'],
                p['time'],
                src,
                dst,
                p['protocols'],
                p['length'],
                p['info']
            ])
        
        # Print the table
        print(tabulate(rows, headers=headers, tablefmt="grid"))
        
        # If there are more packets, wait for user input before showing the next batch
        if i + batch_size < len(packet_details):
            input("\nPress Enter to show next batch of packets...")

def analyze_live_capture(interface, duration=60, packet_count=None, bpf_filter=None, display_live=True, 
                         target_protocols=None, output_format="table"):
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
    packet_details = []
    
    # Start capture
    start_time = time.time()
    packets = []
    packet_count_processed = 0
    
    try:
        # Sniff packets
        if packet_count:
            capture.sniff(packet_count=packet_count)
        else:
            capture.sniff(timeout=duration)
        
        # Process captured packets
        for packet in capture:
            packet_count_processed += 1
            
            # Identify protocols in this packet
            identified_protocols = identify_protocol(packet)
            
            # Skip packet if we have target protocols and none match
            if target_protocols and not any(p in identified_protocols for p in target_protocols):
                continue
                
            packets.append(packet)
            
            # Count protocols
            for protocol in identified_protocols:
                protocol_counter[protocol] += 1
            
            # Get packet details
            details = get_packet_details(packet, identified_protocols)
            details['number'] = len(packets)  # Set packet number
            packet_details.append(details)
            
            # If displaying live and using detailed format
            if display_live and output_format == "detail":
                print(f"\nPacket {details['number']}:")
                print(f"  Time: {details['time']}")
                print(f"  Source: {details['src_ip']}:{details['src_port']}")
                print(f"  Destination: {details['dst_ip']}:{details['dst_port']}")
                print(f"  Protocols: {details['protocols']}")
                print(f"  Length: {details['length']}")
                print(f"  Info: {details['info']}")
        
        # If displaying live and using table format, print the table after all packets are captured
        if display_live and output_format == "table":
            print("\nCaptured Packets:")
            print_packet_table(packet_details)
    
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    finally:
        elapsed_time = time.time() - start_time
        
        # Display summary
        print("\n" + "="*50)
        print(f"Capture Summary (Duration: {elapsed_time:.2f}s)")
        print("="*50)
        print(f"Total Packets Processed: {packet_count_processed}")
        print(f"Matching Packets: {len(packets)}")
        
        # Protocol distribution
        if protocol_counter:
            print("\nProtocol Distribution:")
            protocols_table = []
            for protocol, count in protocol_counter.most_common():
                percentage = (count / len(packets)) * 100 if packets else 0
                protocols_table.append([protocol, count, f"{percentage:.2f}%"])
            
            print(tabulate(protocols_table, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
    
    return packets

def analyze_pcap_file(filename, target_protocols=None, output_format="table"):
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return []
    
    print(f"Analyzing pcap file: {filename}")
    
    # Create FileCapture object
    capture = pyshark.FileCapture(filename)
    
    # Dictionary to track protocols
    protocol_counter = Counter()
    packets = []
    packet_details = []
    
    try:
        # Process all packets
        for packet in capture:
            # Identify protocols in this packet
            identified_protocols = identify_protocol(packet)
            
            # Skip packet if we have target protocols and none match
            if target_protocols and not any(p in identified_protocols for p in target_protocols):
                continue
                
            packets.append(packet)
            
            # Count protocols
            for protocol in identified_protocols:
                protocol_counter[protocol] += 1
            
            # Get packet details
            details = get_packet_details(packet, identified_protocols)
            details['number'] = len(packets)  # Set packet number
            packet_details.append(details)
            
            # If using detailed format
            if output_format == "detail":
                print(f"\nPacket {details['number']}:")
                print(f"  Time: {details['time']}")
                print(f"  Source: {details['src_ip']}:{details['src_port']}")
                print(f"  Destination: {details['dst_ip']}:{details['dst_port']}")
                print(f"  Protocols: {details['protocols']}")
                print(f"  Length: {details['length']}")
                print(f"  Info: {details['info']}")
        
        # If using table format, print the table after all packets are processed
        if output_format == "table":
            print("\nCaptured Packets:")
            print_packet_table(packet_details)
    
    except Exception as e:
        print(f"Error processing file: {e}")
    finally:
        capture.close()
        
        # Display summary
        print("\n" + "="*50)
        print("Capture Summary")
        print("="*50)
        print(f"Total Matching Packets: {len(packets)}")
        
        # Protocol distribution
        if protocol_counter:
            print("\nProtocol Distribution:")
            protocols_table = []
            for protocol, count in protocol_counter.most_common():
                percentage = (count / len(packets)) * 100 if packets else 0
                protocols_table.append([protocol, count, f"{percentage:.2f}%"])
            
            print(tabulate(protocols_table, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
    
    return packets

def create_protocol_filter(target_protocols):
    """Create a BPF filter expression for the specified protocols"""
    filters = []
    
    # TCP/UDP base filters
    if 'TCP' in target_protocols:
        filters.append('tcp')
    if 'UDP' in target_protocols:
        filters.append('udp')
    
    # Add application protocol port filters
    for protocol, ports in PROTOCOL_PORTS.items():
        if protocol in target_protocols:
            port_filters = [f'port {port}' for port in ports]
            if port_filters:
                filters.append('(' + ' or '.join(port_filters) + ')')
    
    # Combine all filters with 'or'
    if filters:
        return ' or '.join(filters)
    return None

def get_available_interfaces():
    """List available network interfaces"""
    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        print("netifaces module not installed. Cannot list available interfaces.")
        print("Install with: pip install netifaces")
        return []

def export_to_csv(packet_details, filename):
    """Export packet details to CSV file"""
    import csv
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['number', 'time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocols', 'length', 'info']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for packet in packet_details:
            writer.writerow(packet)
    
    print(f"Exported {len(packet_details)} packets to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Network Protocol Analyzer for TCP, UDP, FTP, SMTP, POP3, IMAP')
    
    # Capture options
    capture_group = parser.add_mutually_exclusive_group(required=True)
    capture_group.add_argument('-i', '--interface', help='Network interface for live capture')
    capture_group.add_argument('-f', '--file', help='PCAP file to analyze')
    capture_group.add_argument('-l', '--list-interfaces', action='store_true', help='List available network interfaces')
    
    # Live capture options
    parser.add_argument('-d', '--duration', type=int, default=60,
                        help='Duration in seconds for live capture (default: 60)')
    parser.add_argument('-c', '--count', type=int, help='Maximum number of packets to capture')
    parser.add_argument('-b', '--bpf-filter', help='Berkeley Packet Filter expression (overrides protocol filters)')
    
    # Output options
    parser.add_argument('--output', choices=['table', 'detail'], default='table',
                        help='Output format: table or detailed (default: table)')
    parser.add_argument('--export', help='Export results to CSV file')
    
    # Protocol filter options
    parser.add_argument('--tcp', action='store_true', help='Capture TCP packets')
    parser.add_argument('--udp', action='store_true', help='Capture UDP packets')
    parser.add_argument('--ftp', action='store_true', help='Capture FTP packets')
    parser.add_argument('--smtp', action='store_true', help='Capture SMTP packets')
    parser.add_argument('--pop3', action='store_true', help='Capture POP3 packets')
    parser.add_argument('--imap', action='store_true', help='Capture IMAP packets')
    parser.add_argument('--all-protocols', action='store_true', help='Capture all supported protocols')
    
    args = parser.parse_args()
    
    # Check for tabulate module
    try:
        import tabulate
    except ImportError:
        print("tabulate module not installed. Please install it with:")
        print("pip install tabulate")
        return
    
    # List interfaces
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        if interfaces:
            print("Available network interfaces:")
            for iface in interfaces:
                print(f"  - {iface}")
        return
    
    # Determine which protocols to capture
    target_protocols = []
    if args.tcp or args.all_protocols:
        target_protocols.append('TCP')
    if args.udp or args.all_protocols:
        target_protocols.append('UDP')
    if args.ftp or args.all_protocols:
        target_protocols.append('FTP')
    if args.smtp or args.all_protocols:
        target_protocols.append('SMTP')
    if args.pop3 or args.all_protocols:
        target_protocols.append('POP3')
    if args.imap or args.all_protocols:
        target_protocols.append('IMAP')
    
    # If no protocols specified, default to all
    if not target_protocols:
        target_protocols = ['TCP', 'UDP', 'FTP', 'SMTP', 'POP3', 'IMAP']
    
    # Create BPF filter if not provided
    bpf_filter = args.bpf_filter
    if not bpf_filter and target_protocols:
        bpf_filter = create_protocol_filter(target_protocols)
    
    print(f"Targeting protocols: {', '.join(target_protocols)}")
    if bpf_filter:
        print(f"Using BPF filter: {bpf_filter}")
    
    # Live capture
    if args.interface:
        packets = analyze_live_capture(
            interface=args.interface,
            duration=args.duration,
            packet_count=args.count,
            bpf_filter=bpf_filter,
            display_live=True,
            target_protocols=target_protocols,
            output_format=args.output
        )
    
    # Analyze PCAP file
    elif args.file:
        packets = analyze_pcap_file(
            filename=args.file,
            target_protocols=target_protocols,
            output_format=args.output
        )
    
    # Export results if requested
    if args.export and packets:
        # Convert packets to details for export
        packet_details = []
        for i, packet in enumerate(packets, 1):
            protocols = identify_protocol(packet)
            details = get_packet_details(packet, protocols)
            details['number'] = i
            packet_details.append(details)
        
        export_to_csv(packet_details, args.export)

if __name__ == "__main__":
    main()