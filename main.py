from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif ICMP in packet:
            print(f"ICMP | {src_ip} -> {dst_ip}")

print("Starting packet capture...")
sniff(prn=packet_callback, count=20)