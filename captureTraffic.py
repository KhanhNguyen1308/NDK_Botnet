import scapy.all as scapy

def process_packet(packet):
    """Processes each captured packet."""
    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Check if the destination IP is a public IP (i.e., on the internet)
        if not dst_ip.startswith("192.168.") and \
           not dst_ip.startswith("10.") and \
           not dst_ip.startswith("172.16.") and \
           not dst_ip.startswith("127.") and \
           not dst_ip.startswith("169.254."):

            print(f"Device {src_ip} sent a request to {dst_ip}")

            # You can add more detailed analysis here:
            if scapy.TCP in packet:
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                print(f"  Protocol: TCP, Ports: {src_port} -> {dst_port}")
            elif scapy.UDP in packet:
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                print(f"  Protocol: UDP, Ports: {src_port} -> {dst_port}")
            # Add other protocol handling as needed

def capture_traffic(interface="eth0"): # Replace eth0 with your network interface
    """Captures network traffic and processes packets."""
    try:
        scapy.sniff(iface=interface, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Capture stopped.")

if __name__ == "__main__":
    capture_traffic()