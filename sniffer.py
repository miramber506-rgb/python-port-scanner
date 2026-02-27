import scapy.all as scapy
from datetime import datetime

# The dictionary
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def p(pkt):
    if pkt.haslayer(scapy.IP):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src = pkt[scapy.IP].src
        dst = pkt[scapy.IP].dst
        
        # 1. We name it proto here...
        proto = pkt[scapy.IP].proto

        # 2. ...so we must use proto here!
        proto_name = PROTOCOLS.get(proto, f"Unknown({proto})")

        # 3. Use proto_name in the string so you see "TCP/UDP"
        log_entry = f"[{timestamp}] {src} -> {dst} | Protocol: {proto_name}\n"

        print(log_entry.strip())

        with open("packet_log.txt", "a") as f:
            f.write(log_entry)

print("--- SNIFFER ACTIVE: (Logging to packet_log.txt) ---")
try:
    scapy.sniff(prn=p, store=0)
except KeyboardInterrupt:
    print("\n--- SNIFFER STOPPED ---")