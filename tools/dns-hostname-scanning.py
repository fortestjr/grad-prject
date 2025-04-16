import dns.resolver
import dns.rdatatype
import argparse
from typing import List, Dict

# Predefined list of common DNS record types to check
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

def query_dns_records(domain: str, record_type: str) -> List[str]:
    """Query DNS records for a given domain and record type."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except dns.resolver.NoAnswer:
        print(f"No {record_type} records found for {domain}.")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
        return []
    except dns.resolver.Timeout:
        print(f"DNS query for {record_type} records timed out for {domain}.")
        return []
    except dns.resolver.NoNameservers:
        print(f"No nameservers found for {domain}.")
        return []
    except Exception as e:
        print(f"Unexpected error querying {record_type} records for {domain}: {e}")
        return []

def analyze_dns(domain: str) -> List[Dict]:
    """Analyze DNS records for a domain and identify subdomains or misconfigurations."""
    results = []

    # Query common DNS record types
    for record_type in DNS_RECORD_TYPES:
        records = query_dns_records(domain, record_type)
        if records:
            for record in records:
                results.append({
                    "Domain": domain,
                    "Record Type": record_type,
                    "Record Value": record,
                    "Issue": "None"
                })

    # Check for common DNS misconfigurations
    # Example: Missing SPF or DMARC records
    try:
        spf_records = query_dns_records(domain, "TXT")
        has_spf = any("v=spf1" in record for record in spf_records)
        if not has_spf:
            results.append({
                "Domain": domain,
                "Record Type": "SPF",
                "Record Value": "Missing",
                "Issue": "No SPF record found"
            })
    except Exception as e:
        print(f"Error checking SPF records for {domain}: {e}")

    try:
        dmarc_records = query_dns_records(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=DMARC1" in record for record in dmarc_records)
        if not has_dmarc:
            results.append({
                "Domain": domain,
                "Record Type": "DMARC",
                "Record Value": "Missing",
                "Issue": "No DMARC record found"
            })
    except Exception as e:
        print(f"Error checking DMARC records for {domain}: {e}")

    return results

def print_results(domain: str, dns_results: List[Dict]):
    """Print the DNS analysis results to the terminal."""
    print(f"\nDNS Analysis Report for {domain}")
    print("-" * 50)
    if dns_results:
        for result in dns_results:
            print(f"Domain: {result['Domain']}")
            print(f"Record Type: {result['Record Type']}")
            print(f"Record Value: {result['Record Value']}")
            print(f"Issue: {result['Issue']}")
            print("-" * 50)
    else:
        print("No DNS records found.")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="DNS Analysis Tool")
    parser.add_argument("domain", help="Domain name to analyze (e.g., example.com)")
    args = parser.parse_args()

    if args.domain:
        try:
            dns_results = analyze_dns(args.domain)
            print_results(args.domain, dns_results)
        except Exception as e:
            print(f"Unexpected error: {e}")
    else:
        print("Error: Domain name cannot be empty.")