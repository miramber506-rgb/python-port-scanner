cat << 'EOF' > sniffer.py
from scapy.all import sniff, IP

def process_packet(packet):
    if packet.haslayer(IP):
        print(f"[+] Traffic: {packet[IP].src} --> {packet[IP].dst}")

print("--- SNIFFER ACTIVE: Listening for 10 packets... ---")
sniff(prn=process_packet, count=10)
EOF