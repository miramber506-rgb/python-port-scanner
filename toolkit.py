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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                # 1. Grab the Banner
                try:
                    s.send(b"GET / HTTP/1.1\r\n\r\n")
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    service_info = f" | Banner: {banner[:50]}" if banner else " | No banner"
                except:
                    banner = "Restricted"
                    service_info = " | Banner: Restricted"
                
                # 2. Print to Screen
                print(f"\n[+] Port {port} is OPEN{service_info}")

                # 3. Save only SUCCESSFUL hits to the file
                with open("scan_report.txt", "a") as f:
                    f.write(f"Target: {ip} | Port: {port} | Banner: {banner}\n")
            else:
                # Visual feedback for closed ports
                print(".", end="", flush=True)
    except Exception as e:
        pass


def start_scanner(target_ip=None):
    # Use the passed IP if available, otherwise ask for one
    target = target_ip if target_ip else input("Target IP: ")
    
    print(f"\n--- SCANNING {target} ---")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1, 1025):
            executor.submit(scan_port, target, port)

#module 3: sub domain finder

def subdomain_finder():
    target_domain  = input("Ënter target domain (eg.. google.com):")
    wordlist_path = "wordlist.txt"

    print(f"\n--- Searching Subdomains on {target_domain} ---")

    try:
        with open(wordlist_path, "r") as file:
            subdomain = file.read().splitlines()
    except FileNotFoundError:
        print("[!] Error: wordlist.txt not found.")
        return

    found = []
    for sub in subdomain:
        url = f"{sub}.{target_domain}"
        try:
            #getting the ip of subdomains
            ip=socket.gethostbyname(url)
            print(f"[+] Found: {url} ({ip})")
            found.append((url, ip))
        except socket.gaierror:
            pass # subdomain doesn't exist

    if found:
        choice = input("\nWould you like to scan one of these IPs?")
        if choice.lower() == 'y':
            print("\n select an IP to scan")
            for i, ip in enumerate(found):
                print(f"{i}.{ip}")
            idx = int(input("Enter index:"))

            return found[idx][1]
    return None

# --- MAIN MENU ---
def main():
    print("\n=== NYXIAN RAY SECURITY TOOLKIT ===")
    print("1. Network Sniffer")
    print("2. Port Scanner (Multithreaded)")
    print("3. Subdomain finder")
    print("4. Exit")
    choice = input("Select an option: ")

    if choice == '1':
        try: start_sniffer()
        except KeyboardInterrupt: print("\nStopped.")
    elif choice == '2':
        try: start_scanner()
        except KeyboardInterrupt: print("\nStopped.")
    elif choice == '3':
            try: 
                # Catch the IP returned by the finder
                target_ip = subdomain_finder()
                
                # If an IP was selected, automatically trigger the scanner
                if target_ip:
                    print(f"\n[!] Pivoting to Port Scanner for: {target_ip}")
                    # We pass target_ip to a modified start_scanner or 
                    # just let the user know it's ready.
                    start_scanner(target_ip) 
            except KeyboardInterrupt: 
                print("\n[!] Subdomain Search Stopped.")
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
