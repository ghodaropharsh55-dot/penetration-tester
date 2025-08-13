import socket
import requests

def port_scanner(target, ports):
    print(f"\n[+] Scanning ports on {target}...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
            sock.close()
        except Exception as e:
            print(f"[ERROR] Could not scan port {port} - {e}")

def brute_force_login(url, username, wordlist):
    print(f"\n[+] Starting brute force on {url} with username '{username}'...")
    for password in wordlist:
        data = {'username': username, 'password': password}
        try:
            response = requests.post(url, data=data)
            if "Login successful" in response.text or response.status_code == 200:
                print(f"[SUCCESS] Password found: {password}")
                return password
        except Exception as e:
            print(f"[ERROR] {e}")
    print("[FAILED] No password found in wordlist.")
    return None

if __name__ == "__main__":
    print("=== Penetration Testing Toolkit ===")
    print("1. Port Scanner")
    print("2. Brute Force Tester")
    
    choice = input("Select module: ").strip()

    if choice == "1":
        target = input("Enter target IP/Domain: ").strip()
        ports = list(map(int, input("Enter comma-separated ports to scan: ").split(",")))
        port_scanner(target, ports)

    elif choice == "2":
        url = input("Enter login URL: ").strip()
        username = input("Enter username: ").strip()
        wordlist = input("Enter comma-separated passwords to try: ").split(",")
        brute_force_login(url, username, wordlist)

    else:
        print("Invalid choice.")
