import socket
import ipaddress
import sys
from typing import List, Dict

def check_host(ip: str, port: int = 80, timeout: float = 1) -> bool:
    """Check if a host is live by attempting to connect to a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return True
    except Exception as e:
        print(f"Error checking host {ip}: {e}")
    return False

def scan_network(cidr: str) -> List[Dict]:
    """Scan a network range (CIDR format) for live hosts."""
    live_hosts = []
    network = ipaddress.ip_network(cidr, strict=False)

    print(f"Scanning network: {cidr}")
    for ip in network.hosts():
        ip_str = str(ip)
        if check_host(ip_str):
            live_hosts.append({"IP": ip_str, "Status": "Live"})
            print(f"Host {ip_str} is live.")
        else:
            print(f"Host {ip_str} is not reachable.")

    return live_hosts

def print_results(cidr: str, live_hosts: List[Dict]):
    """Print the scan results to the terminal."""
    print(f"\nNetwork Scan Report for {cidr}")
    print("-" * 30)
    if live_hosts:
        for host in live_hosts:
            print(f"IP: {host['IP']}, Status: {host['Status']}")
    else:
        print("No live hosts found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_scanner.py <CIDR_RANGE>")
        print("Example: python network_scanner.py 192.168.1.0/24")
        sys.exit(1)

    cidr = sys.argv[1].strip()
    try:
        live_hosts = scan_network(cidr)
        print_results(cidr, live_hosts)
    except ValueError:
        print("Error: Invalid CIDR format.")