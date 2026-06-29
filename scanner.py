import socket
import subprocess
import platform
import requests
import json

def collect_Sys_Info():
    print("[*] Collecting system infomation...")

    #check which ports are open
    open_ports = []
    ports_to_check = [21, 22, 23, 80, 3389, 8080]

    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    print(f"[*] Open ports found: {open_ports}")
    return open_ports

def check_ssh_enabled():
    ssh_open = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', 22))
    if result == 0:
        ssh_open = True
    sock.close()
    print(f"[*] SSH enabled: {ssh_open}")
    return ssh_open

def check_telnet_enabled():
    telnet_open = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', 23))
    if result == 0:
        telnet_open = True
    sock.close()
    print(f"[*] Telnet enabled: {telnet_open}")
    return telnet_open

def check_ftp_enabled():
    ftp_open = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', 21))
    if result == 0:
        ftp_open = True 
    sock.close()
    print(f"[*] FTP enabled: {ftp_open}")
    return ftp_open

def get_password_policy():
    min_length = 8

    if platform.system() == "Windows":
        try:
            output = subprocess.run(
                ['net', 'accounts'],
                capture_output=True,
                text=True
            )
            for line in output.stdout.splitlines():
                if 'Minimum password length' in line:
                    parts = line.split(':')
                    value = parts[1].strip()
                    if value.isdigit():
                        min_length = int(value)
        except Exception as e:
            print(f"[!] Could not read password policy: {e}")

    print(f"[*] Minimum password length: {min_length}")
    return min_length

def send_to_api(open_ports, ssh_enabled, telnet_enabled, ftp_enabled, password_length):
    print("\n[*] Sending data to SecureCheck API...")

    payload = {
        "open_ports": open_ports,
        "ssh_enabled": ssh_enabled,
        "telnet_enabled": telnet_enabled,
        "ftp_enabled": ftp_enabled,
        "password_length": password_length
    }

    try:
        response = requests.post(
            'http://127.0.0.1:5000/scan',
            json=payload
        )
        return response.json()
    except Exception as e:
        print(f"[!] Could not reach SecureCheck API: {e}")
        print(f"[!] Make sure your Flask app is running.")
        return None

def main():
    print("=" * 50)
    print("       SecureCheck Automated Scanner")
    print("=" * 50)

    open_ports = collect_Sys_Info()
    ssh_enabled = check_ssh_enabled()
    telnet_enabled = check_telnet_enabled()
    ftp_enabled = check_ftp_enabled()
    password_length = get_password_policy()

    results = send_to_api(open_ports, ssh_enabled, telnet_enabled, ftp_enabled, password_length)
    
    if results:
        print("\n" + "=" * 50)
        print("         SECURECHECK COMPLIANCE REPORT")
        print("=" * 50)
        print(f"Overall Status : {results['overall_status']}")
        print(f"Score          : {results['score']}")
        print(f"Total Findings : {len(results['findings'])}")
        print("\n--- FINDINGS ---")
        for finding in results['findings']:
            print(f"\n[{finding['severity']}] {finding['rule']}")
            print(f"  Status : {finding['status']}")
            print(f"  Detail : {finding['detail']}")
        print("\n" + "=" * 50)

if __name__ == "__main__":
    main()