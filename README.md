# Network Packet Analyzer

A real-time network packet analyzer with threat detection capabilities, built using Python and Scapy.

## Features

- Real-time packet capture on WiFi interface
- Protocol detection — TCP, UDP, ICMP, DNS
- Port scan detection
- SYN flood attack detection
- Alert logging to file with timestamps
- Capture summary with packet statistics

## Tools Used

- Python 3
- Scapy — packet capture and analysis
- Wireshark — traffic validation
- Nmap — testing and verification

## Project Structure 
```
network-packet-analyzer/
├── main.py        # Main analyzer with threat detection
├── alerts.log     # Generated alert log file
└── README.md      # Project documentation
```
## How to Run

1. Install dependencies:
pip install scapy

2. Run as Administrator (required for packet capture):
py main.py

3. Press Ctrl+C to stop and see summary

## Threat Detection

| Threat | Detection Method |
|--------|-----------------|
| Port Scan | Flags if single IP scans more than 10 ports |
| SYN Flood | Flags if single IP sends more than 20 SYN packets |

## Sample Output

```
========================================
   NETWORK PACKET ANALYZER
   Author: Gayathri U M
   Press Ctrl+C to stop
========================================
[16:13:44] TCP  | 192.168.1.5:30502 -> 34.149.66.154:443
[16:13:45] DNS  | 192.168.1.5 -> looking up -> github.com.
[16:13:46] *** ALERT: PORT SCAN detected from 192.168.1.6 - scanned 11 ports!
[16:13:46] *** ALERT: SYN FLOOD detected from 192.168.1.6 - 21 SYN packets!
```
## Author

**Gayathri U M**

B.Tech Electronics and Communication Engineering

Government Engineering College, Thrissurg
