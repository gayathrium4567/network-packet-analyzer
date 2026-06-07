from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
import datetime
from collections import defaultdict

# Counters
tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0
alert_count = 0

# For threat detection
port_scan_tracker = defaultdict(set)
syn_flood_tracker = defaultdict(int)

def get_time():
    return datetime.datetime.now().strftime("%H:%M:%S")

def log_alert(message):
    global alert_count
    alert_count += 1
    time = get_time()
    alert = f"[{time}] *** ALERT: {message}"
    print(alert)
    with open("alerts.log", "a") as f:
        f.write(alert + "\n")

def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) > 10:
        log_alert(f"PORT SCAN detected from {src_ip} — scanned {len(port_scan_tracker[src_ip])} ports!")

def detect_syn_flood(src_ip, flags):
    if flags == 2:  # SYN flag
        syn_flood_tracker[src_ip] += 1
        if syn_flood_tracker[src_ip] > 20:
            log_alert(f"SYN FLOOD detected from {src_ip} — {syn_flood_tracker[src_ip]} SYN packets!")

def packet_callback(packet):
    global tcp_count, udp_count, icmp_count, dns_count

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = get_time()

        if DNS in packet and DNSQR in packet:
            dns_count += 1
            domain = packet[DNSQR].qname.decode()
            print(f"[{time}] DNS | {src_ip} -> looking up -> {domain}")

        if TCP in packet:
            tcp_count += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[{time}] TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            detect_port_scan(src_ip, dst_port)
            detect_syn_flood(src_ip, flags)

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
    print(f"DNS queries  : {dns_count}")
    print(f"Total        : {tcp_count + udp_count + icmp_count}")
    print(f"*** Alerts   : {alert_count}")

print("Starting packet capture... (Press Ctrl+C to stop)")
try:
    sniff(prn=packet_callback, store=0, iface=None)
except KeyboardInterrupt:
    print_summary()
