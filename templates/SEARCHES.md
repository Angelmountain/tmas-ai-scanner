# Security Assessment Search Definitions

This document describes the search queries in `input.csv` used by the Security Assessment Platform.

## CSV Format

```
name,description,sorting,log_type,orientation,query
```

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `name` | Yes | string | Display name (must be unique, used for Excel filename and PPT slide matching) |
| `description` | Yes | string | Human-readable description shown in the UI |
| `sorting` | Yes | string | API response field to aggregate by (see Field Reference below) |
| `log_type` | Yes | `network` or `detections` | Which Vision One API endpoint to query |
| `orientation` | Yes | `horizontal` or `vertical` | Chart orientation (horizontal = bar chart, vertical = column chart) |
| `query` | Yes | string | TMV1 search query (see Query Syntax below) |

## How to Add a New Search

1. Open `templates/input.csv` in any spreadsheet or text editor
2. Add a new row following the format above
3. Validate: visit the platform UI -> Custom CSV Upload -> upload the file to preview
4. If adding a search that maps to a PowerPoint slide, update `python_scripts/generate_ppt_report.py` SLIDE_MAPPING

## Field Reference (sorting column)

These are the API response fields you can aggregate by:

| Sorting Value | API Field | Use For | Output Columns |
|---------------|-----------|---------|----------------|
| `ruleName` | `ruleName` | Detection rule names | Rule Name, Count |
| `hostName` | `hostName` | Hostnames/domains | Hostname, Access Count |
| `app` | `app` | Application/protocol names | Protocol, Usage Count |
| `suid` | `suid` | User accounts (security ID) | Account Name, Usage Count |
| `serverPort` | `serverPort` | Destination ports | Server Port, Connection Count |
| `clientIp` | `clientIp` | Source IP addresses | Source IP, Connection Count |
| `serverIp` | `serverIp` | Destination IP addresses | Destination IP, Connection Count |
| `requestMethod` | `requestMethod` | HTTP methods (GET, POST, etc.) | Request Method, Count |
| `respCode` | `respCode` | HTTP response codes | Response Code, Count |
| `sslCertCommonName` | `sslCertCommonName` | SSL certificate CNs | Certificate, Count |
| `fileName` | `fileName` | File names | File Name, Access Count |
| `fileType` | `fileType` | File extensions | File Type, Access Count |
| `respAppVersion` | `respAppVersion` | Application versions | Version, Connection Count |
| `request` | `request` | Full request URLs | URL, Count |

## Query Syntax (TMV1-Query)

Trend Micro Vision One search query syntax:

```
# Basic field matching
hostName:(*.example.com)
app:(RDP OR SSH)
dstPort:(22 OR 3389)
ruleName:(*SSH*)

# Sensor filter (NDR sensors)
(productCode:pdi OR productCode:xns)

# Wildcards
hostName:(*openai.com OR *anthropic.com)
ruleName:*root*

# Negation
NOT serverIp:(10.* OR 192.168.*)

# Combining
(productCode:pdi OR productCode:xns) AND hostName:(*.ru)
(productCode:pdi OR productCode:xns) AND ruleName:*SSH* AND filterRiskLevel:(critical OR high)

# MITRE ATT&CK tactics
tacticId:(TA0001 OR TA0002)
```

## Search Categories

### Core Network Analysis (10 searches)
| # | Name | Sorting | What It Finds |
|---|------|---------|---------------|
| 1 | Network Detections | ruleName | All detection rules triggered by NDR sensors |
| 2 | Top Accounts used | suid | Most active user accounts in network traffic |
| 3 | Server ports used | serverPort | Most commonly targeted destination ports |
| 4 | Unsuccessful logon | ruleName | Failed login attempt patterns |
| 5 | Top File used | fileName | Most frequently accessed files |
| 6 | Top File types used | fileType | File extension distribution |
| 7 | Protocols used | app | Network protocol breakdown (HTTP, SSH, RDP, etc.) |
| 8 | Request methods | requestMethod | HTTP method distribution (GET, POST, etc.) |
| 9 | Response codes | respCode | HTTP response code distribution (200, 404, etc.) |
| 10 | SSL Cert Common Name | sslCertCommonName | SSL certificate subjects in use |

### SSH/RDP Monitoring (6 searches)
| # | Name | Sorting | What It Finds |
|---|------|---------|---------------|
| 11 | SSH Detections | ruleName | SSH-related security detections |
| 12 | SSH Versions | respAppVersion | SSH protocol versions in use |
| 19 | RDP User Usage | suid | User accounts using RDP |
| 20 | RDP Source IP | clientIp | Source IPs initiating RDP connections |
| 21 | RDP Destination IP | serverIp | Destination IPs receiving RDP connections |

### PUA Detection (8 searches)
| # | Name | Sorting | What It Finds |
|---|------|---------|---------------|
| 13 | PUA AI Services | hostName | Traffic to 100+ AI/ML services (OpenAI, Anthropic, etc.) |
| 14 | PUA Remote Access | hostName | Remote access tools (TeamViewer, AnyDesk, etc.) |
| 15 | PUA Cloud Storage | hostName | Cloud storage services (Dropbox, Mega, etc.) |
| 16 | PUA Darknet links | hostName | Tor hidden services (.onion domains) |
| 17 | PUA VPN Services | hostName | VPN/proxy services (NordVPN, ExpressVPN, etc.) |
| 18 | PUA Pastebin | hostName | Pastebin/code sharing (pastebin.com, etc.) |
| 22 | PUA Administrator Usage | app | Applications used by administrator accounts |

### Geographic & Vendor Risk (7 searches)
| # | Name | Sorting | What It Finds |
|---|------|---------|---------------|
| 23 | Suspicious TLDs | hostName | Traffic to suspicious top-level domains (.tk, .ml, etc.) |
| 24 | Bad States | hostName | Traffic to sanctioned countries (.kp, .ru, .cu, etc.) |
| 25 | Russian IT-companies | hostName | Russian IT company domains (Kaspersky, Yandex, etc.) |
| 26 | Chinese IT-companies | hostName | Chinese IT company domains (Huawei, Alibaba, etc.) |
| 27 | EPP/EDR/XDR Vendors | hostName | Security vendor domains (CrowdStrike, Symantec, etc.) |
| 28 | Firewall Vendors | hostName | Firewall vendor domains (Palo Alto, Fortinet, etc.) |
| 29 | US Vendors | hostName | US technology company domains (Microsoft, Google, etc.) |

### External Threats & Advanced (10 searches)
| # | Name | Sorting | What It Finds |
|---|------|---------|---------------|
| 30 | External Attacks | ruleName | Inbound attack detections (MITRE tactics TA0001-TA0002) |
| 31 | Web Rep RU | ruleName | Web reputation detections for .ru domains |
| 32 | RDP Detections | ruleName | RDP-related security detections |
| 33 | Root Detections | ruleName | Root/admin privilege detections |
| 34 | DNS Dead IP | ruleName | DNS responses to dead IP addresses |
| 35 | File Downloads | request | Executable/archive file downloads |
| 36 | Cert Downloads | request | Certificate file downloads |
| 37 | External RDP | serverIp | RDP to external (non-RFC1918) IP addresses |
| 38 | External SSH | serverIp | SSH to external IP addresses |
| 39 | External Protocols | app | Non-standard protocols to external IPs |

## PowerPoint Slide Mapping

Searches that have corresponding chart slides in the NDR Security Assessment v2.0 template:

| Search Name | Slide # | Template Title |
|-------------|---------|----------------|
| Network Detections | 6 | Network Detections |
| Top Accounts used | 7 | Top Accounts used |
| Server ports used | 8 | Server ports used |
| Unsuccessful logon | 9 | Unsuccessful logon |
| Protocols used | 12 | Protocols used |
| Request methods | 13 | Request method |
| Response codes | 14 | Response Codes |
| SSL Cert Common Name | 15 | SSL Cert Common Name |
| SSH Detections | 17 | SSH Detections |
| SSH Versions | 18 | SSH Versions |
| PUA AI Services | 20 | PUA AI Services |
| Root Detections | 21 | PUA root detections |
| PUA Remote Access | 22 | PUA Remote Access |
| PUA Cloud Storage | 23 | PUA Cloud Storage |
| PUA VPN Services | 24 | PUA country connections |
| PUA Pastebin | 25 | PUA email attachments |
| PUA Darknet links | 26 | PUA Darknet links |
| PUA Administrator Usage | 27 | PUA Administrator Usage |
| RDP User Usage | 29 | RDP user usage |
| RDP Source IP | 30 | RDP source IP |
| RDP Destination IP | 31 | RDP destination IP |
| Suspicious TLDs | 33 | .CH requests |
| Bad States | 34 | .RU requests |
| Russian IT-companies | 35 | Russian IT-companies |
| Chinese IT-companies | 36 | (data table if no chart) |
| EPP/EDR/XDR Vendors | 37 | EPP/EDR/XDR Vendors |
| Firewall Vendors | 38 | Firewall Vendors |
| US Vendors | 39 | US Vendors |

Searches without slides (Excel-only): Top File used, Top File types used, DNS Dead IP, File Downloads, Cert Downloads, External RDP, External SSH, External Protocols.
