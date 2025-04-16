import socket
import argparse
from typing import List, Dict, Optional

# Predefined list of insecure or outdated protocols and their associated risks
INSECURE_PROTOCOLS = {
    "ftp": "FTP - Unencrypted file transfer",
    "telnet": "Telnet - Unencrypted communication",
    "smtp": "SMTP - Open relay or misconfigurations",
    "http": "HTTP - Vulnerable web server",  # HTTP is flagged as insecure
    "snmp": "SNMP - Weak community strings",
    "rdp": "RDP - Weak credentials or misconfigurations",
    "vnc": "VNC - Unencrypted remote access",
    "ssh1": "SSHv1 - Insecure and outdated",
}

def detect_protocol(target: str, port: int) -> Optional[str]:
    """Detect the protocol running on a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                try:
                    protocol = socket.getservbyport(port)
                    return protocol
                except:
                    return "Unknown"
    except Exception as e:
        print(f"Error detecting protocol on port {port}: {e}")
    return None

def scan_protocols(target: str) -> List[Dict]:
    """Scan for supported protocols on a target system."""
    scan_results = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900, 8080, 161]

    print(f"Scanning target: {target}")
    for port in common_ports:
        protocol = detect_protocol(target, port)
        if protocol:
            risk = INSECURE_PROTOCOLS.get(protocol.lower(), "No known risks")
            scan_results.append({
                "Port": port,
                "Protocol": protocol,
                "Risk": risk
            })
            print(f"Port {port} ({protocol}) is open. Risk: {risk}")

    return scan_results

def generate_terminal_report(target: str, scan_results: List[Dict]) -> str:
    """Generate a formatted terminal report string."""
    report = []
    report.append(f"\n{'=' * 60}")
    report.append(f"Protocol Scan Report for {target}")
    report.append(f"{'=' * 60}\n")

    if not scan_results:
        report.append("No open ports or protocols found.")
        return "\n".join(report)

    # Table header
    report.append(f"{'Port':<8} {'Protocol':<20} {'Risk':<30}")
    report.append("-" * 60)

    # Table rows
    for result in scan_results:
        port = result["Port"]
        protocol = result["Protocol"]
        risk = result["Risk"]

        # Highlight insecure protocols in red
        if risk != "No known risks":
            risk = f"\033[91m{risk}\033[0m"  # Red color for risks

        report.append(f"{port:<8} {protocol:<20} {risk:<30}")

    # Summary
    report.append("\nSummary:")
    report.append(f"Total Open Ports: {len(scan_results)}")
    report.append(f"Insecure Protocols: {sum(1 for r in scan_results if r['Risk'] != 'No known risks')}")

    return "\n".join(report)

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Protocol Scanner")
    parser.add_argument("target", help="Target IP address or domain name")
    args = parser.parse_args()

    try:
        scan_results = scan_protocols(args.target)
        if scan_results:
            report = generate_terminal_report(args.target, scan_results)
            print(report)
        else:
            print("No open ports or protocols found.")
    except Exception as e:
        print(f"Unexpected error: {e}")