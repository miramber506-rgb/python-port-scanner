# Python Multi-Threaded Port Scanner

A high-speed, multi-threaded network reconnaissance tool built in Python. This tool identifies open ports and performs "Banner Grabbing" to fingerprint services.

##  Features
- **High Speed:** Utilizes Python's `threading` library to scan thousands of ports in seconds.
- **Service Detection:** Performs banner grabbing using HTTP GET requests to identify running services.
- **Visual Feedback:** Color-coded terminal output for easy identification of open ports.
- **Performance Tracking:** Reports the exact time taken to complete the scan.

##  Installation & Usage
1. Clone this repository or download `scanner.py`.
2. Run the script:
   ```bash
   python3 scanner.py

   target ip address 127.0.0.1


sample output

[*] Port 8080 is OPEN | Service: HTTP/1.0 200 OK
Scan finished in: 4.95 seconds
