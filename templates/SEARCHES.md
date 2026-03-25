# Security Assessment Search Definitions

All searches use the Trend Micro Vision One Search API v3.0.

**Base query** (from `config.json`): `(productCode:pdi OR productCode:xns)` — filters to NDR sensor data only.

---

## Quick Reference: Raw Queries for Vision One Console

Copy these directly into the Vision One search console to validate results.

### Core Network Analysis

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 1 | **Network Detections** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns)` |
| 2 | **Top Accounts** | `/v3.0/search/networkActivities` + `/v3.0/search/detections` | `suid` | `(productCode:pdi OR productCode:xns)` |
| 3 | **Server Ports** | `/v3.0/search/networkActivities` | `serverPort` | `(productCode:pdi OR productCode:xns)` |
| 4 | **Unsuccessful Logon** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND ruleName:("*unsuccessful*logon*" OR "*failed*logon*" OR "*logon*fail*")` |
| 5 | **Top Files** | `/v3.0/search/networkActivities` | `fileName` | `(productCode:pdi OR productCode:xns)` |
| 6 | **File Types** | `/v3.0/search/networkActivities` | `fileType` | `(productCode:pdi OR productCode:xns)` |
| 7 | **Protocols** | `/v3.0/search/networkActivities` | `app` | `(productCode:pdi OR productCode:xns)` |
| 8 | **Request Methods** | `/v3.0/search/networkActivities` | `requestMethod` | `(productCode:pdi OR productCode:xns)` |
| 9 | **Response Codes** | `/v3.0/search/networkActivities` | `respCode` | `(productCode:pdi OR productCode:xns)` |
| 10 | **SSL Certificates** | `/v3.0/search/networkActivities` | `sslCertCommonName` | `(productCode:pdi OR productCode:xns)` |

### SSH Monitoring

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 11 | **SSH Detections** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND ruleName:*SSH*` |
| 12 | **SSH Versions** | `/v3.0/search/networkActivities` | `respAppVersion` | `(productCode:pdi OR productCode:xns) AND app:SSH` |

### Potentially Unwanted Applications (PUA)

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 13 | **PUA AI Services** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*openai.com OR *chatgpt.com OR *api.openai.com OR *copilot.microsoft.com OR *ai.azure.com OR *copilot.bing.com OR *designer.microsoft.com OR *anthropic.com OR *claude.ai OR *deepseek.com OR *huggingface.co OR *stability.ai OR *midjourney.com OR *perplexity.ai OR *cursor.sh OR *codeium.com OR *tabnine.com ...)` [125 domains in ai_services.txt] |
| 14 | **PUA Remote Access** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*teamviewer.com OR *anydesk.com OR *logmein.com OR *gotomypc.com OR *splashtop.com OR *realvnc.com OR *connectwise.com OR *screenconnect.com OR *rustdesk.com OR *meshcentral.com ...)` [45 domains in remote_access.txt] |
| 15 | **PUA Cloud Storage** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*dropbox.com OR *box.com OR *icloud.com OR *drive.google.com OR *nextcloud.com OR *mega.nz OR *pcloud.com OR *wetransfer.com OR *syncthing.net ...)` [50 domains in cloud_storage.txt] |
| 16 | **PUA Darknet** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:*.onion` |
| 17 | **PUA VPN Services** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*nordvpn.com OR *expressvpn.com OR *surfshark.com OR *protonvpn.com OR *cyberghostvpn.com OR *mullvad.net OR *torproject.org ...)` [48 domains in vpn_services.txt] |
| 18 | **PUA Pastebin** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*pastebin.com OR *paste.ee OR *hastebin.com OR *dpaste.org OR *ghostbin.com OR *privatebin.net ...)` [33 domains in pastebin.txt] |
| 19 | **PUA Admin Usage** | `/v3.0/search/networkActivities` | `app` | `(productCode:pdi OR productCode:xns) AND suid:administrator` |
| 20 | **Root Detections** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND ruleName:*root*` |

### RDP Monitoring

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 21 | **RDP Users** | `/v3.0/search/networkActivities` | `suid` | `(productCode:pdi OR productCode:xns) AND app:RDP` |
| 22 | **RDP Source IPs** | `/v3.0/search/networkActivities` | `clientIp` | `(productCode:pdi OR productCode:xns) AND app:RDP` |
| 23 | **RDP Dest IPs** | `/v3.0/search/networkActivities` | `serverIp` | `(productCode:pdi OR productCode:xns) AND app:RDP` |
| 24 | **RDP Detections** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND ruleName:*RDP*` |
| 25 | **External RDP** | `/v3.0/search/networkActivities` | `serverIp` | `(productCode:pdi OR productCode:xns) AND app:RDP AND NOT serverIp:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.*)` |

### Geographic / Vendor Risk

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 26 | **Suspicious TLDs** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*.tk OR *.ml OR *.ga OR *.cf OR *.gq OR *.su OR *.to OR *.cc OR *.pw OR *.biz OR *.info OR *.top OR *.me OR *.xyz OR *.club OR *.work OR *.space OR *.men OR *.click OR *.loan OR *.win OR *.asia OR *.today OR *.lol OR *.world OR *.website OR *.wiki OR *.bar OR *.rest OR *.uno OR *.best OR *.ws OR *.social OR *.shop OR *.cfd OR *.quest)` |
| 27 | **Bad States** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*.kp OR *.ru OR *.cu OR *.by OR *.sy OR *.ir OR *.ve OR *.sd)` |
| 28 | **Russian IT** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*kaspersky.com OR *ptsecurity.com OR *solar.rt.ru OR *infotecs.ru OR *bi.zone OR *innostage.ru OR *norsi-trans.ru OR *jet.su OR *citadel.ru OR *softline.com OR *selectel.com OR *yandex.cloud OR *nano-av.com OR *cognitive.ru OR *platform.altergeo.ru)` |
| 29 | **Chinese IT** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*huawei.com OR *zte.com OR *hikvision.com OR *dahua.com OR *sangfor.com OR *xiaomi.com OR *baidu.com OR *alibaba.com OR *tencent.com OR *bytedance.com ...)` [63 domains in chinese_it.txt] |
| 30 | **Security Vendors** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*Avast.com OR *Avira.com OR *AVG.com OR *NortonLifeLock.com OR *McAfee.com OR *Sophos.com OR *Cybereason.com OR *Kaspersky.com OR *malwarebytes.com OR *carbonblack.com OR *Bitdefender.com OR *symantec.com OR *CrowdStrike.com OR *SentinelOne.com OR *Trellix.com OR *pandasecurity.com OR *ultraantivirus.com)` |
| 31 | **Firewall Vendors** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*Cisco.com OR *PaloAltoNetworks.com OR *Fortinet.com OR *CheckPoint.com OR *Sophos.com OR *Juniper.net OR *SonicWall.com OR *clavister.com)` |
| 32 | **US Vendors** | `/v3.0/search/networkActivities` | `hostName` | `(productCode:pdi OR productCode:xns) AND hostName:(*microsoft.com OR *apple.com OR *google.com OR *amazon.com OR *meta.com OR *ibm.com OR *oracle.com OR *salesforce.com OR *adobe.com OR *cisco.com ...)` [70 domains in us_vendors.txt] |

### External Threats

| # | Name | API Endpoint | Aggregate By | Raw TMV1 Query |
|---|------|-------------|-------------|----------------|
| 33 | **External Attacks** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi) AND tacticId:(TA0043 OR TA0042 OR TA0001 OR TA0002) AND filterRiskLevel:(critical OR high OR medium) AND tags:*inbound*` |
| 34 | **Web Rep RU** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND hostName:*.ru AND ruleName:*Web Reputation*` |
| 35 | **DNS Dead IP** | `/v3.0/search/detections` | `ruleName` | `(productCode:pdi OR productCode:xns) AND ruleName:"DNS response resolves to dead IP address"` |
| 36 | **External SSH** | `/v3.0/search/networkActivities` | `serverIp` | `(productCode:pdi OR productCode:xns) AND app:SSH AND NOT serverIp:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.*)` |
| 37 | **External Protocols** | `/v3.0/search/networkActivities` | `app` | `(productCode:pdi OR productCode:xns) AND NOT app:(TLS OR DNS OR HTTP OR TCP) AND NOT serverIp:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.*)` |
| 38 | **File Downloads** | `/v3.0/search/networkActivities` | `request` | `(productCode:pdi OR productCode:xns) AND request:(*.exe OR *.dll OR *.bat OR *.vbs OR *.jar OR *.scr OR *.ps1 OR *.iso OR *.apk OR *.zip OR *.rar OR *.msi OR *.cmd) AND requestMethod:GET` |
| 39 | **Cert Downloads** | `/v3.0/search/networkActivities` | `request` | `(productCode:pdi OR productCode:xns) AND request:*.crt` |

---

## How to Validate in Vision One Console

1. Go to **Search** in the Vision One console
2. Select the data source:
   - `networkActivities` for network searches
   - `detections` for detection searches
3. Paste the **Raw TMV1 Query** from the table above
4. Set the time range to match your assessment
5. Compare the results with the platform output

---

## CSV Format

File: `templates/searches.csv`

```
category,name,description,sorting,log_type,ppt_slide,enabled,query_type,query_value
```

| Column | Description |
|--------|-------------|
| `category` | Group: Network, SSH, PUA, RDP, Geo, Vendor, Threats |
| `name` | Unique display name |
| `description` | Human-readable description |
| `sorting` | API field to aggregate by (count occurrences of unique values) |
| `log_type` | `network` = networkActivities, `detections` = detections, `everything` = both |
| `ppt_slide` | Slide number in PowerPoint template (empty = Excel only) |
| `enabled` | `true` or `false` |
| `query_type` | How to build the query (see below) |
| `query_value` | Parameter for the query type |

### Query Types

| Type | How it works | Example query_value |
|------|-------------|---------------------|
| `base` | Just the base query, no filter | _(empty)_ |
| `filter` | base_query AND query_value | `app:RDP` |
| `domains` | base_query AND hostName:(*d1 OR *d2...) from file | `ai_services.txt` |
| `tlds` | base_query AND hostName:(*.tld1 OR *.tld2...) | `kp ru cu by sy ir ve sd` |
| `raw` | query_value used as-is (base query NOT prepended) | Full query string |

### Sorting Fields (API response fields)

| Field | Description | Example Values |
|-------|-------------|----------------|
| `ruleName` | Detection rule name | "Port Scan - TCP", "Unsuccessful logon - RDP" |
| `hostName` | HTTP Host header / DNS domain | "api.openai.com", "kremlin.ru" |
| `app` | Application / protocol | "HTTP", "SSH", "RDP", "DNS" |
| `suid` | Security user ID (account name) | "Administrator", "LAPTOP01$", "bob" |
| `serverPort` | Destination port number | "443", "22", "3389" |
| `clientIp` | Source IP address | "192.168.1.100" |
| `serverIp` | Destination IP address | "10.0.0.1" |
| `requestMethod` | HTTP method | "GET", "POST" |
| `respCode` | HTTP response code | "200", "404", "502" |
| `sslCertCommonName` | SSL certificate CN | "*.google.com" |
| `fileName` | Transferred file name | "document.pdf" |
| `fileType` | File extension/type | "PDF", "EXE" |
| `respAppVersion` | Application version string | "SSH-2.0-OpenSSH_9.6p1" |
| `request` | Full request URL | "http://example.com/file.exe" |

---

## PowerPoint Slide Mapping

| Search Name | Slide # | Template Title |
|-------------|---------|----------------|
| Network Detections | 6 | Network Detections |
| Top Accounts | 7 | Top Accounts used |
| Server Ports | 8 | Server ports used |
| Unsuccessful Logon | 9 | Unsuccessful logon |
| Protocols | 12 | Protocols used |
| Request Methods | 13 | Request method |
| Response Codes | 14 | Response Codes |
| SSL Certificates | 15 | SSL Cert Common Name |
| SSH Detections | 17 | SSH Detections |
| SSH Versions | 18 | SSH Versions |
| PUA AI Services | 20 | PUA AI Services |
| Root Detections | 21 | PUA root detections |
| PUA Remote Access | 22 | PUA Remote Access |
| PUA Cloud Storage | 23 | PUA Cloud Storage |
| PUA VPN Services | 24 | PUA country connections |
| PUA Pastebin | 25 | PUA email attachments |
| PUA Darknet | 26 | PUA Darknet links |
| PUA Admin Usage | 27 | PUA Administrator Usage |
| RDP Users | 29 | RDP user usage |
| RDP Source IPs | 30 | RDP source IP |
| RDP Dest IPs | 31 | RDP destination IP |
| Suspicious TLDs | 33 | .CH requests |
| Bad States | 34 | .RU requests |
| Russian IT | 35 | Russian IT-companies |
| Chinese IT | 36 | (data table) |
| Security Vendors | 37 | EPP/EDR/XDR Vendors |
| Firewall Vendors | 38 | Firewall Vendors |
| US Vendors | 39 | US Vendors |
| External Attacks | 40 | (data table) |
| RDP Detections | 42 | (data table) |

Searches without slides (Excel-only): Top Files, File Types, DNS Dead IP, File Downloads, Cert Downloads, External RDP, External SSH, External Protocols, Web Rep RU.
