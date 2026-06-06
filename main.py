from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        time = datetime.datetime.now().strftime("%H:%M:%S")


        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{time}] TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{time}] UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif ICMP in packet:
            
            print(f"[{time}] ICMP | {src_ip} -> {dst_ip}")

print("Starting packet capture...")
sniff(prn=packet_callback, count=20)