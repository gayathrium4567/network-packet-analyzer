# Network Packet Analyzer with Threat Detection
# Built using Python and Scapy
# Detects: Port Scans, SYN Floods, DNS queries
# Author: Gayathri U M

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
import datetime
from collections import defaultdict

# ── Counters ──────────────────────────────
tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0
alert_count = 0

# ── Threat Detection Trackers ──────────────
# Tracks ports scanned by each IP
port_scan_tracker = defaultdict(set)
# Tracks SYN packets sent by each IP
syn_flood_tracker = defaultdict(int)

def get_time():
    """Returns current time as HH:MM:SS string"""
    return datetime.datetime.now().strftime("%H:%M:%S")

def log_alert(message):
    """Prints alert to terminal and saves to alerts.log file"""
    global alert_count
    alert_count += 1
    time = get_time()
    alert = f"[{time}] *** ALERT: {message}"
    print(alert)
    with open("alerts.log", "a") as f:
        f.write(alert + "\n")

def detect_port_scan(src_ip, dst_port):
    """Detects if an IP is scanning multiple ports"""
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) > 10:
        log_alert(f"PORT SCAN detected from {src_ip} - scanned {len(port_scan_tracker[src_ip])} ports!")

def detect_syn_flood(src_ip, flags):
    """Detects SYN flood attack based on excessive SYN packets"""
    if flags == 2:  # SYN flag value = 2
        syn_flood_tracker[src_ip] += 1
        if syn_flood_tracker[src_ip] > 20:
            log_alert(f"SYN FLOOD detected from {src_ip} - {syn_flood_tracker[src_ip]} SYN packets!")

def packet_callback(packet):
    """Called automatically for every captured packet"""
    global tcp_count, udp_count, icmp_count, dns_count

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = get_time()

        # ── DNS Detection ──────────────────
        if DNS in packet and DNSQR in packet:
            dns_count += 1
            domain = packet[DNSQR].qname.decode()
            print(f"[{time}] DNS  | {src_ip} -> looking up -> {domain}")

        # ── TCP Detection ──────────────────
        if TCP in packet:
            tcp_count += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[{time}] TCP  | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            detect_port_scan(src_ip, dst_port)
            detect_syn_flood(src_ip, flags)

        # ── UDP Detection ──────────────────
        elif UDP in packet:
            udp_count += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{time}] UDP  | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # ── ICMP Detection ─────────────────
        elif ICMP in packet:
            icmp_count += 1
            print(f"[{time}] ICMP | {src_ip} -> {dst_ip}")

def print_summary():
    """Prints capture statistics when stopped"""
    print("\n" + "="*40)
    print("         CAPTURE SUMMARY")
    print("="*40)
    print(f"TCP packets  : {tcp_count}")
    print(f"UDP packets  : {udp_count}")
    print(f"ICMP packets : {icmp_count}")
    print(f"DNS queries  : {dns_count}")
    print(f"Total        : {tcp_count + udp_count + icmp_count}")
    print(f"*** Alerts   : {alert_count}")
    print("="*40)
    print("Alerts saved to: alerts.log")

# ── Main Program ───────────────────────────
print("="*40)
print("   NETWORK PACKET ANALYZER")
print("   Author: Gayathri U M")
print("   Press Ctrl+C to stop")
print("="*40)

try:
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print_summary()