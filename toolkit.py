import scapy.all as scapy
import socket
import sys
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Global file lock for thread safety
file_lock = threading.Lock()

# --- CONFIGURATION & HELPERS ---
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# --- MODULE 1: SNIFFER ---
def packet_callback(pkt):
    if pkt.haslayer(scapy.IP):
        proto = PROTOCOLS.get(pkt[scapy.IP].proto, f"Unknown({pkt[scapy.IP].proto})")
        log = f"[{datetime.now().strftime('%H:%M:%S')}] {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} | {proto}\n"
        print(log.strip())
        with file_lock:
            with open("packet_log.txt", "a") as f: 
                f.write(log)

def start_sniffer():
    print("--- SNIFFER ACTIVE (Ctrl+C to stop) ---")
    scapy.sniff(prn=packet_callback, store=0)

# --- MODULE 2: SCANNER (Previous fixes applied) ---
def identify_service(banner, port):
    banner = banner.upper()
    if "SSH-" in banner: return "Secure Shell (SSH)"
    if "HTTP/" in banner or "LOCATION:" in banner: return "Web Server (HTTP)"
    if "FTP" in banner or banner.startswith("220"): return "File Transfer (FTP)"
    if "SMTP" in banner: return "Email Server (SMTP)"
    if "MARIADB" in banner or "MYSQL" in banner: return "Database (MySQL)"
    if port == 53: return "DNS Server"
    return "Unknown Service"

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                # 1. Grab the Banner - PROTOCOL SPECIFIC (Previous fix)
                try:
                    if port in [80, 443, 8080]:
                        s.send(b"GET / HTTP/1.1\r\n\r\n")
                    elif port == 22:
                        s.send(b"")  # SSH
                    elif port == 21:
                        s.send(b"")  # FTP
                    elif port == 25:
                        s.send(b"EHLO test\r\n")  # SMTP
                    else:
                        s.send(b"\r\n")
                    
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ""
                
                # 2. Identify the service
                service_type = identify_service(banner, port)
                banner_clean = banner[:20].replace('\n', ' ').strip() if banner else "No banner"
                service_info = f"{service_type} ({banner_clean})"
                
                print(f"\n[+] Port {port} is OPEN")
                
                # 3. Log to file - THREAD SAFE (Previous fix)
                with file_lock:
                    with open("scan_report.txt", "a") as f:
                        f.write(f"Target: {ip} | Port: {port} | Info: {service_info}\n")
                
                return (port, service_info)
            else:
                print(".", end="", flush=True)
                return None
    except:
        return None

def start_scanner(target_ip=None):
    target = target_ip if target_ip else input("Target IP: ")
    
    print("\n" + "="*50)
    print(f"🚀 NYXIAN SCANNER STARTING ON: {target}")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)

    found_ports = []

    try:
        with ThreadPoolExecutor(max_workers=50) as executor:  # Reduced from 100
            futures = [executor.submit(scan_port, target, p) for p in range(1, 8081)]
            for future in futures:
                res = future.result()
                if res:
                    found_ports.append(res)

    except KeyboardInterrupt:
        print("\n\n[!] User interrupted. Cleaning up...")

    # --- THE VISUALIZER TABLE (Previous formatting) ---
    print("\n\n┌" + "─"*62 + "┐")
    print(f"│ {'PORT':<8} │ {'STATUS':<10} │ {'SERVICE/BANNER':<38} │")
    print("├" + "─"*10 + "┼" + "─"*12 + "┼" + "─"*40 + "┤")
    
    if not found_ports:
        print(f"│ {'NONE':<8} │ {'CLOSED':<10} │ {'No open ports found':<38} │")
    else:
        for p, b in sorted(found_ports):
            print(f"│ {p:<8} │ {'OPEN':<10} │ {b[:38]:<38} │")
            
    print("└" + "─"*62 + "┘")
    print(f"Scan Completed at: {datetime.now().strftime('%H:%M:%S')}\n")

# --- MODULE 3: SUBDOMAIN FINDER ---
def subdomain_finder():
    target_domain = input("Enter target domain (eg. google.com): ")
    wordlist_path = "wordlist.txt"

    print(f"\n--- Searching Subdomains on {target_domain} ---")

    try:
        with open(wordlist_path, "r") as file:
            subdomains = file.read().splitlines()
    except FileNotFoundError:
        print("[!] Error: wordlist.txt not found.")
        return None

    found = []
    for sub in subdomains:
        url = f"{sub}.{target_domain}"
        try:
            ip = socket.gethostbyname(url)
            print(f"[+] Found: {url} ({ip})")
            found.append((url, ip))
        except socket.gaierror:
            pass

    if found:
        choice = input("\nWould you like to scan one of these IPs? (y/n): ")
        if choice.lower() == 'y':
            print("\nSelect an IP to scan:")
            for i, (url, ip) in enumerate(found):
                print(f"{i}. {url} ({ip})")
            try:
                idx = int(input("Enter index: "))
                return found[idx][1]
            except (ValueError, IndexError):
                print("[!] Invalid selection.")
    return None

# --- MAIN MENU ---
def main():
    print("\n=== NYXIAN RAY SECURITY TOOLKIT ===")
    print("1. Network Sniffer")
    print("2. Port Scanner (Multithreaded)") 
    print("3. Subdomain Finder")
    print("4. Exit")
    choice = input("Select an option: ")

    if choice == '1':
        try: 
            print("[!] Sniffer requires sudo privileges!")
            start_sniffer()
        except KeyboardInterrupt: 
            print("\nStopped.")
    elif choice == '2':
        try: start_scanner()
        except KeyboardInterrupt: print("\nStopped.")
    elif choice == '3':
        try: 
            target_ip = subdomain_finder()
            if target_ip:
                print(f"\n[!] Pivoting to Port Scanner for: {target_ip}")
                start_scanner(target_ip)
        except KeyboardInterrupt: 
            print("\n[!] Subdomain Search Stopped.")
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
