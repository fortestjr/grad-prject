
# Security Tools Database Population

This README provides SQL insertion scripts to populate a `SecurityTools` table with categorized cybersecurity tools used for network analysis, vulnerability detection, malware scanning, and threat intelligence.

---

## Categories Used

Ensure these categories exist in your `Categories` table before running the inserts:

- **Network**: Tools related to network security and scanning.
- **Web**: Tools related to web application security and vulnerabilities.
- **Malware**: Tools that detect or analyze malicious files and URLs.
- **Threat Intelligence**: Tools for gathering and analyzing external cyber threat data.

---
# Security Tools Database Population

This README provides SQL insertion scripts to populate a `SecurityTools` table with categorized cybersecurity tools used for network analysis, vulnerability detection, malware scanning, and threat intelligence.

---

##  Categories Table Setup

Before inserting security tools, ensure that the following categories exist in the `Categories` table:

```sql
INSERT INTO Categories (name, description) VALUES ('Network', 'Tools related to network security and scanning');
INSERT INTO Categories (name, description) VALUES ('Web', 'Tools related to web application security and vulnerabilities');
INSERT INTO Categories (name, description) 
VALUES ('Threat Intelligence', 'Tools for analyzing and correlating threat data');

INSERT OR IGNORE INTO Categories (name, description) VALUES ('Malware', 'Tools related to malware detection and analysis');

- ## **Web** Security Tools**

These tools analyze web apps for vulnerabilities, misconfigurations, insecure cryptographic practices, and insecure design patterns.

```sql
INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES
(
  'SSRF Vulnerability Testing',
  'Tool to test for SSRF by sending crafted requests and analyzing responses',
  'python grad-proj\\tools\\ssrf-vulnerability-tool.py',
  'grad-proj\\tools\\ssrf-vulnerability-tool.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'Web Config Scanner',
  'Scans for misconfigurations and default credentials in web apps',
  'python grad-proj\\tools\\web-config-scanner.py <url>',
  'grad-proj\\tools\\web-config-scanner.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'crypto',
  'Demonstrates insecure hashing and encryption practices (e.g., MD5, hardcoded keys)',
  'python grad-proj\\tools\\crypto-demo.py',
  'grad-proj\\tools\\crypto-demo.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'design-checker',
  'Analyzes design documents for insecure patterns like SQL injection, no rate limiting, etc.',
  'python grad-proj\\tools\\design-checker.py',
  'grad-proj\\tools\\design-checker.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'vuln',
  'Scans Python requirements.txt for vulnerable packages using OSV API',
  'python grad-proj\\tools\\vuln.py',
  'grad-proj\\tools\\vuln.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'Software Integrity',
  'Checks for software integrity issues',
  'python grad-proj\\tools\\software-integrity.py',
  'grad-proj\\tools\\software-integrity.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'Logging Failure',
  'Detects logging configuration failures',
  'python grad-proj\\tools\\logging-failure.py',
  'grad-proj\\tools\\logging-failure.py',
  (SELECT id FROM Categories WHERE name='Web')
),
(
  'Identification Failure',
  'Identifies authentication and identification failures',
  'python grad-proj\\tools\\identification-failure.py',
  'grad-proj\\tools\\identification-failure.py',
  (SELECT id FROM Categories WHERE name='Web')
);

## **Network Security Tools**

These tools are used to scan networks, detect active hosts, check firewalls, and analyze protocols:

```sql
INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES
(
  'DNS Hostname Scanning',
  'Tool to analyze DNS records and detect subdomains',
  'python grad-proj\\tools\\dns-hostname-scanning.py',
  'grad-proj\\tools\\dns-hostname-scanning.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Firewall and ACL Testing',
  'Tool to check if a port is blocked by a firewall',
  'python grad-proj\\tools\\firewall-and-acl-testing.py',
  'grad-proj\\tools\\firewall-and-acl-testing.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'IP Scanning',
  'Tool to scan an IP range and detect live hosts',
  'python grad-proj\\tools\\ipscanning.py',
  'grad-proj\\tools\\ipscanning.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Port Scanning',
  'Tool to scan ports and detect open services',
  'python grad-proj\\tools\\port-scanning.py',
  'grad-proj\\tools\\port-scanning.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Protocol Analysis',
  'Tool to detect protocols and check for security risks',
  'python grad-proj\\tools\\protocol-ana.py',
  'grad-proj\\tools\\protocol-ana.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Service Detection',
  'Tool to detect running services and their versions',
  'python grad-proj\\tools\\service-detect.py',
  'grad-proj\\tools\\service-detect.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Subnet and VLAN Scanning',
  'Tool to scan subnets and detect improper VLAN configurations',
  'python grad-proj\\tools\\subnet-and-vlan-scanning.py',
  'grad-proj\\tools\\subnet-and-vlan-scanning.py',
  (SELECT id FROM Categories WHERE name='Network')
),
(
  'Latency Testing',
  'Tool to measure network latency and packet loss',
  'python grad-proj\\tools\\test-latency.py',
  'grad-proj\\tools\\test-latency.py',
  (SELECT id FROM Categories WHERE name='Network')
);

## **Malware**

INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES
(
  'File Scanner',
  'Scans files for malicious patterns and calculates file hashes',
  'python grad-proj\\tools\\file-scanner.py',
  'grad-proj\\tools\\file-scanner.py',
  (SELECT id FROM Categories WHERE name='Malware')
),
(
  'URL Scanner',
  'Scans URLs for potentially malicious patterns and suspicious characteristics',
  'python grad-proj\\tools\\url-scanner.py',
  'grad-proj\\tools\\url-scanner.py',
  (SELECT id FROM Categories WHERE name='Malware')
);

## **threat**

INSERT INTO SecurityTools (name, description, executionCmd, path, categoryId) 
VALUES (
  'Threat Intelligence Scanner',
  'Collects and analyzes threat intelligence from various sources',
  'python grad-proj\\tools\\threat.py',
  'grad-proj\\tools\\threat.py',
  (SELECT id FROM Categories WHERE name = 'Threat Intelligence')
);


