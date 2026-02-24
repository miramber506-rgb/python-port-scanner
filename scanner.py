import socket
import time
import threading
from datetime import datetime

# 1. Setup Input
target = input("Enter the IP address or domain to scan: ")

# 2. Define the Logic
def port_scan(port):
    time.sleep(0.01) 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                s.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n') 
                banner = s.recv(1024).decode().strip()
                
                # Only take the first line (e.g., "HTTP/1.0 400 Bad Request")
                first_line = banner.split('\n')[0]
                banner_info = f" | Service: {first_line}"
            except:
                banner_info = " | Service: Unknown"

            print(f"\033[92m[*] Port {port} is OPEN{banner_info}\033[0m")
        s.close()
    except:
        pass

# 3. Print the Starting Banner
print("_" * 50)
print(f"Scanning Target: {target}")
print(f"Time started: {datetime.now()}")
print("_" * 50)

# 4. Execute with Threading
start_time = time.time()

for p in range(1, 9001):
    thread = threading.Thread(target=port_scan, args=(p,))
    thread.start()

# 5. Synchronize and Finish
for thread in threading.enumerate():
    if thread is not threading.main_thread():
        thread.join()

end_time = time.time()
print("_" * 50)
print(f"Scan finished in: {round(end_time - start_time, 2)} seconds")
print("_" * 50)