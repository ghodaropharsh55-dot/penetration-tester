import socket
import requests
from concurrent.futures import ThreadPoolExecutor

# ===============================
# 1. PORT SCANNER
# ===============================
def port_scanner(target, start_port, end_port):
    print(f"\n[+] Scanning ports on {target}...")
    open_ports = []
    def scan(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)
                print(f"[OPEN] Port {port}")
            s.close()
        except:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan, port)
    print(f"[INFO] Open ports found: {open_ports}")

# ===============================
# 2. DIRECTORY BRUTE FORCER
# ===============================
def dir_brute_force(base_url, wordlist):
    print(f"\n[+] Starting directory brute force on {base_url}")
    with open(wordlist, "r") as f:
        dirs = f.read().splitlines()

    for dir in dirs:
        url = f"{base_url}/{dir}"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(f"[FOUND] {url}")
        except requests.RequestException:
            pass

# ===============================
# 3. SIMPLE LOGIN BRUTE FORCER
# ===============================
def login_brute_force(url, username, password_list, username_field, password_field):
    print(f"\n[+] Starting login brute force on {url}")
    with open(password_list, "r") as f:
        passwords = f.read().splitlines()

    for password in passwords:
        data = {username_field: username, password_field: password}
        try:
            r = requests.post(url, data=data)
            if "invalid" not in r.text.lower():  # Adjust keyword as needed
                print(f"[SUCCESS] Password found: {password}")
                return
        except requests.RequestException:
            pass
    print("[FAILED] No password matched.")

# ===============================
# MAIN MENU
# ===============================
def main():
    print("""
    ==========================
     Penetration Testing Toolkit
    ==========================
    1. Port Scanner
    2. Directory Brute Forcer
    3. Login Brute Forcer
    """)
    choice = input("Select option (1-3): ").strip()

    if choice == "1":
        target = input("Enter target IP/Domain: ").strip()
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        port_scanner(target, start_port, end_port)

    elif choice == "2":
        base_url = input("Enter base URL (http/https): ").strip()
        wordlist = input("Enter path to wordlist file: ").strip()
        dir_brute_force(base_url, wordlist)

    elif choice == "3":
        url = input("Enter login form URL: ").strip()
        username = input("Enter username: ").strip()
        password_list = input("Enter path to password list file: ").strip()
        username_field = input("Enter username field name: ").strip()
        password_field = input("Enter password field name: ").strip()
        login_brute_force(url, username, password_list, username_field, password_field)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
