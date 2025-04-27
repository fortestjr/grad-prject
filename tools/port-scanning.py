import socket
from typing import Tuple
from socket import getservbyport
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def scan_port(target: str, port: int, protocol: str) -> Tuple[int, str, str]:
    """Scan a single port and return its status and name."""
    try:
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as s:
            s.settimeout(1)
            if protocol == "TCP":
                result = s.connect_ex((target, port))
                if result == 0:
                    service_name = getservbyport(port, "tcp") if port < 65536 else "Unknown"
                    return port, "Open", service_name
            elif protocol == "UDP":
                s.sendto(b"", (target, port))
                try:
                    data, _ = s.recvfrom(1024)
                    if data:
                        service_name = getservbyport(port, "udp") if port < 65536 else "Unknown"
                        return port, "Open", service_name
                except socket.timeout:
                    return port, "Closed", "Unknown"
            return port, "Closed", "Unknown"
    except Exception as e:
        logging.error(f"Error scanning port {port} ({protocol}): {e}")
        return port, f"Error: {e}", "Unknown"

def generate_report(target: str, ip: str, open_ports: dict) -> str:
    """Generate a formatted terminal report string."""
    report = []
    report.append(f"\n{'=' * 40}")
    report.append(f"Port Scan Report for {target} ({ip})")
    report.append(f"{'=' * 40}\n")

    for protocol in ["TCP", "UDP"]:
        if open_ports[protocol]:
            report.append(f"{protocol} Open Ports:")
            report.append("-" * 40)
            report.append(f"{'Port':<8} {'Status':<10} {'Service':<20}")
            report.append("-" * 40)
            for port, status, service in open_ports[protocol]:
                report.append(f"{port:<8} {status:<10} {service:<20}")
            report.append("\n")
        else:
            report.append(f"No open {protocol} ports found\n")

    summary = (
        f"Summary:\n"
        f"Total Open TCP Ports: {len(open_ports['TCP'])}\n"
        f"Total Open UDP Ports: {len(open_ports['UDP'])}"
    )
    report.append(summary)
    return "\n".join(report)

def port_scanner(target: str, start_port: int, end_port: int) -> str:
    """Scan a range of ports and return results as a formatted string."""
    try:
        ip = socket.gethostbyname(target)
        open_ports = {"TCP": [], "UDP": []}

        for protocol in ["TCP", "UDP"]:
            for port in range(start_port, end_port + 1):
                port_status = scan_port(target, port, protocol)
                if port_status[1] == "Open":
                    open_ports[protocol].append(port_status)
                logging.info(f"Scanned {protocol} port {port}: {port_status[1]}")

        return generate_report(target, ip, open_ports)

    except socket.gaierror:
        return "Error: Unable to resolve target address."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"Scan failed: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: port_scanner.py <target> <port-range>")
        print("Example: port_scanner.py example.com 20-80")
        sys.exit(1)
    
    target = sys.argv[1]
    port_range = sys.argv[2]
    
    try:
        # Parse port range (expecting format like "20-80")
        start_port, end_port = map(int, port_range.split('-'))
        
        # Validate ports
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            print("Error: Ports must be between 1 and 65535, and start_port must be <= end_port.")
            sys.exit(1)
            
        # Run scanner and print results
        result = port_scanner(target, start_port, end_port)
        print(result)
        
    except ValueError:
        print("Error: Invalid port range format. Expected format: start-end (e.g., 20-80)")
        sys.exit(1)
