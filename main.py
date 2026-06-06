from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
import datetime

# Counters
tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0

def packet_callback(packet):
    global tcp_count, udp_count, icmp_count, dns_count

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = datetime.datetime.now().strftime("%H:%M:%S")
        
        if DNS in packet and DNSQR in packet:
           dns_count += 1
           domain = packet[DNSQR].qname.decode()
           print(f"[{time}] DNS | {src_ip} -> looking up -> {domain}")

        if TCP in packet:
            tcp_count += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{time}] TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif UDP in packet:
            udp_count += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{time}] UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif ICMP in packet:
            icmp_count += 1
            print(f"[{time}] ICMP | {src_ip} -> {dst_ip}")

def print_summary():
    print("\n--- Capture Summary ---")
    print(f"TCP packets  : {tcp_count}")
    print(f"UDP packets  : {udp_count}")
    print(f"ICMP packets : {icmp_count}")
    print(f"Total        : {tcp_count + udp_count + icmp_count}")
    print(f"DNS queries  : {dns_count}")

print("Starting packet capture... (Press Ctrl+C to stop)")
try:
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print_summary()