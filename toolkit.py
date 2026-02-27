import scapy.all as scapy
import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION & HELPERS ---
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# --- MODULE 1: SNIFFER ---
def packet_callback(pkt):
    if pkt.haslayer(scapy.IP):
        proto = PROTOCOLS.get(pkt[scapy.IP].proto, f"Unknown({pkt[scapy.IP].proto})")
        log = f"[{datetime.now().strftime('%H:%M:%S')}] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} | {proto}\n"
        print(log.strip())
        with open("packet_log.txt", "a") as f: f.write(log)

def start_sniffer():
    print("--- SNIFFER ACTIVE (Ctrl+C to stop) ---")
    scapy.sniff(prn=packet_callback, store=0)

# --- MODULE 2: SCANNER ---
def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            print(f"[+] Port {port} is OPEN")
        else:
            # This prints a dot without a new line, creating a progress bar effect
            print(".", end="", flush=True)

def start_scanner():
    target = input("Target IP: ")
    print(f"--- SCANNING {target} ---")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1, 1025):
            executor.submit(scan_port, target, port)

# --- MAIN MENU ---
def main():
    print("\n=== NYXIAN RAY SECURITY TOOLKIT ===")
    print("1. Network Sniffer")
    print("2. Port Scanner (Multithreaded)")
    print("3. Exit")
    choice = input("Select an option: ")

    if choice == '1':
        try: start_sniffer()
        except KeyboardInterrupt: print("\nStopped.")
    elif choice == '2':
        start_scanner()
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
