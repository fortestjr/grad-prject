
## Network API Collection (Postman) & Security Tools Integration

This document combines API documentation with security tool database configuration for network analysis tools.

---
## API Endpoints

**Base URL:** `http://localhost:3000/network`

| Feature     | Description                           |
|-------------|---------------------------------------|
| Format      | JSON                                  |
| Methods     | GET (all endpoints)                   |
| Auth        | None                                  |

### Endpoints

#### 1. IP Scanning (`/ipscan`)
```

##Body {"cidr": "192.168.1.1/24"}

```
**Associated Tool:** IP Scanning (detects live hosts)

#### 2. Firewall Check (`/firewall`)
```

##Body {"target": "google.com", "protocol": "tcp", "ports": "80,443,22"}

```
**Associated Tool:** Firewall and ACL Testing

#### 3. DNS Lookup (`/dns`)
```

##Body {"domain": "192.168.1.1"}

```
**Associated Tool:** DNS Hostname Scanning

#### 4. Port Scanning (`/portscan`)
```

##Body {"target": "google.com", "range": "20-80"}

```
**Associated Tool:** Port Scanning

#### 5. Protocol Detection (`/protocol`)
```

##Body {"target": "google.com"}

```
**Associated Tool:** Protocol Analysis

#### 6. Subnet Configuration (`/subnet`)
```

##Body {"subnet": "192.168.1.0/24", "vlan": "10"}

```
**Associated Tool:** Subnet and VLAN Scanning

#### 7. Service Detection (`/services`)
```

##Body {"target": "192.168.1.1", "versionDetection": "true"}

```
**Associated Tool:** Service Detection

#### 8. Latency Measurement (`/latency`)
```

{"target": "google.com", "count": "10"}

```
**Associated Tool:** Latency Testing

---
## Security Tools Database Setup

### SQL Schema Configuration
```

INSERT INTO Categories (name, description) VALUES ('Network', 'Tools related to network security and scanning');


INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES
(
'DNS Hostname Scanning',
'Analyzes DNS records and detects subdomains',
'python grad-proj\\tools\\dns-hostname-scanning.py',
'grad-proj\\tools\\dns-hostname-scanning.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Firewall and ACL Testing',
'Checks if ports are blocked by firewalls',
'python grad-proj\\tools\\firewall-and-acl-testing.py',
'grad-proj\\tools\\firewall-and-acl-testing.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'IP Scanning',
'Scans IP ranges for live hosts',
'python grad-proj\\tools\\ipscanning.py',
'grad-proj\\tools\\ipscanning.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Port Scanning',
'Scans ports for open services',
'python grad-proj\\tools\\port-scanning.py',
'grad-proj\\tools\\port-scanning.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Protocol Analysis',
'Detects network protocols and security risks',
'python grad-proj\\tools\\protocol-ana.py',
'grad-proj\\tools\\protocol-ana.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Service Detection',
'Identifies running services and versions',
'python grad-proj\\tools\\service-detect.py',
'grad-proj\\tools\\service-detect.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Subnet and VLAN Scanning',
'Detects VLAN configuration issues',
'python grad-proj\\tools\\subnet-and-vlan-scanning.py',
'grad-proj\\tools\\subnet-and-vlan-scanning.py',
(SELECT id FROM Categories WHERE name='Network')
),

(
'Latency Testing',
'Measures network latency/packet loss',
'python grad-proj\\tools\\test-latency.py',
'grad-proj\\tools\\test-latency.py',
(SELECT id FROM Categories WHERE name='Network')
);

```

---
## Implementation Notes

1. **API-Tool Mapping:** Each API endpoint corresponds to a specific Python tool
2. **Path Requirements:** Ensure Windows-style path separators (`\\`) in database entries
3. **Execution:** All tools run with Python 3.6+ using `python [path] [parameters]`

Use `POSTMAN_COLLECTION.json` for API testing and execute the SQL script to populate tool configurations.
```
