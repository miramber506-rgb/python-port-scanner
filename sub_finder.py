import requests
import concurrent.futures

target = input("Enter domain: ")

def check_subdomain(word):
    subdomain = f"{word.strip()}.{target}"
    try:
        response = requests.get(f"http://{subdomain}", timeout=2)
        print(f"[+] Found: {subdomain} | Status: {response.status_code}")
    except:
        pass

# This is the "Engine" that runs 10 checks at once
with open("wordlist.txt", "r") as file:
    words = file.readlines()
    print(f"--- Scanning {len(words)} subdomains... ---\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_subdomain, words)