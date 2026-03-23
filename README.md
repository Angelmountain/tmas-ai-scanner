# Security Assessment Platform

Unified web platform for **Trend Micro Vision One network security assessment** and **TMAS AI security scanning** of LLM endpoints.

**Live**: [https://secassess.nordicnetintruders.com](https://secassess.nordicnetintruders.com)

---

## What It Does

**Vision One Security Assessment** runs 39 pre-built searches against the Trend Micro Vision One API, covering network detections, account usage, protocols, SSH/RDP, potentially unwanted applications (AI services, remote access, cloud storage, VPN, pastebin, darknet), geographic risk (sanctioned countries, Russian/Chinese IT companies), vendor analysis, and external threats. Results are exported as Excel spreadsheets and a branded PowerPoint report.

**TMAS AI Security Scanning** tests LLM endpoints (OpenAI, Anthropic, Ollama, Azure, custom) against OWASP LLM Top 10 and MITRE ATT&CK frameworks using the Trend Micro Artifact Scanner CLI.

**GitHub Actions Integration** monitors workflow runs, displays step-by-step execution details, and triggers scans directly from the web UI.

---

## Architecture

```
Browser ──HTTPS──> AWS ALB (ACM TLS 1.3)
                        │
                        ▼ :3000
                   Node.js Express
                   ┌─────────────────────┐
                   │  /api/assessment/*   │──> python_scripts/run_assessment.py
                   │  /api/aiscan/*       │──> python_scripts/run_ai_scan.py
                   │  /api/github/*       │──> gh CLI
                   │  /api/csv/*          │──> CSV validation
                   │  Static: index.html  │──> Chart.js SPA
                   └─────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   Vision One API    TMAS CLI Binary    GitHub API
   (v3.0/search/*)   (aiscan llm)      (gh run/workflow)
          │                │
          ▼                ▼
   Excel + PowerPoint  JSON + HTML Report
```

| Layer | Tech | Purpose |
|-------|------|---------|
| Frontend | Vanilla JS, Chart.js | Single-file SPA, dark theme, interactive charts |
| Backend | Node.js 18, Express | REST API, Python subprocess orchestration |
| Assessment | Python 3, pandas, openpyxl | Vision One API search, Excel export |
| PowerPoint | python-pptx | Update chart data in branded v2.0 template |
| AI Scan | TMAS CLI, PyYAML | LLM endpoint security testing |
| GitHub | gh CLI | Workflow monitoring and dispatch |
| Infrastructure | Terraform, AWS | EC2 + ALB + ACM + Route53 |

---

## Quick Start

### Local Development

```bash
git clone https://github.com/Angelmountain/tmas-ai-scanner.git
cd tmas-ai-scanner

# Python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Node.js
cd web && npm install && cd ..

# Run
cd web && node server.js
# Open http://localhost:3000
```

### Deploy to AWS

```bash
cd terraform
terraform init
terraform plan
terraform apply
# Output: https://secassess.nordicnetintruders.com
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Vision One API
TREND_MICRO_API_KEY=your-key       # Required for assessments
TREND_MICRO_BASE_URL=https://api.eu.xdr.trendmicro.com

# TMAS AI Scanner
TMAS_API_KEY=your-key              # Required for AI scans
LLM_API_KEY=your-llm-key          # Required for non-Ollama providers

# Web Server
PORT=3000
```

---

## Project Structure

```
tmas-ai-scanner/
├── web/
│   ├── server.js                      # Express backend (all API routes)
│   ├── package.json
│   └── public/index.html              # Single-file SPA frontend
│
├── python_scripts/
│   ├── run_assessment.py              # Vision One search orchestrator
│   ├── run_ai_scan.py                 # TMAS CLI wrapper
│   └── generate_ppt_report.py         # PowerPoint chart updater
│
├── scripts/
│   ├── generate_config.py             # TMAS YAML config generator
│   └── run_scan.py                    # TMAS scan executor
│
├── templates/
│   ├── input.csv                      # 39 pre-built search definitions
│   ├── SEARCHES.md                    # Search documentation & reference
│   └── NDR_Security_Assessment.pptx   # PowerPoint template v2.0
│
├── terraform/
│   ├── main.tf                        # EC2 + ALB + ACM + Route53
│   ├── variables.tf                   # Config (domain, instance type, IP allowlist)
│   ├── outputs.tf                     # URL, IPs, cert ARN
│   └── userdata.sh                    # EC2 bootstrap script
│
├── .github/workflows/
│   └── ai-security-scan.yml          # GitHub Actions for AI scanning
│
├── requirements.txt                   # Python: pyyaml, requests, pandas, openpyxl, python-pptx
├── install.sh                         # Standalone Linux installer
├── scan.sh                            # Local scan wrapper
└── .env.example                       # Environment template
```

---

## API Reference

### Assessment

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/searches/prebuilt` | List all 39 pre-built searches from input.csv |
| POST | `/api/assessment/run` | Start assessment. Body: `{apiKey, baseUrl, timeInterval, searches}` |
| GET | `/api/assessment/status/:id` | Poll job progress `{status, progress, total, current, console}` |
| GET | `/api/assessment/results/:id` | Results with `{summary, excelFiles, hasPpt}` |
| GET | `/api/assessment/download/:id` | Download ZIP (all Excel + PowerPoint) |
| GET | `/api/assessment/excel/:id/:file` | Download individual Excel file |
| GET | `/api/assessment/ppt/:id` | Download PowerPoint report |

### CSV Upload

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/csv/upload` | Upload CSV file (multipart) or `{csvContent}` body |
| GET | `/api/csv/template/:cat` | Download template: `basic`, `ai_services`, `cloud_storage`, `remote_access`, `geographic` |

### AI Scan

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/aiscan/run` | Start scan. Body: `{provider, endpoint, model, llmApiKey, visionOneApiKey, region, preset, timeout}` |
| GET | `/api/aiscan/status/:id` | Poll scan progress |
| GET | `/api/aiscan/results/:id` | Scan findings with `{results, hasHtml}` |
| GET | `/api/aiscan/report/:id` | Download HTML report |

### GitHub Actions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/github/runs?repo=X` | List recent workflow runs |
| GET | `/api/github/runs/:id` | Run details with step breakdown |
| GET | `/api/github/workflows` | List available workflows |
| POST | `/api/github/dispatch/:wf` | Trigger workflow with `{inputs: {...}}` |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check `{status, uptime, jobs}` |
| GET | `/api/config` | Current config |
| POST | `/api/config` | Save config `{visionOneBaseUrl}` |
| GET | `/api/history` | Past operations |
| DELETE | `/api/history` | Clear history |

---

## Search Configuration

### How Searches Work

1. Each search in `templates/input.csv` defines a Vision One API query
2. The platform queries `/v3.0/search/networkActivities` or `/v3.0/search/detections`
3. Results are aggregated by the `sorting` field (e.g., count connections per hostname)
4. Aggregated data is exported to Excel (2 columns: Category, Count)
5. Charts in the PowerPoint template are updated with the Excel data

### Editing Searches

Edit `templates/input.csv` directly. See [`templates/SEARCHES.md`](templates/SEARCHES.md) for:
- Full field reference and valid sorting values
- Query syntax guide with examples
- Complete list of all 39 searches with descriptions
- PowerPoint slide mapping

### CSV Format

```csv
name,description,sorting,log_type,orientation,query
My Search,Description here,hostName,network,horizontal,"hostName:(*.example.com)"
```

| Column | Values | Description |
|--------|--------|-------------|
| `name` | any string | Unique display name |
| `sorting` | `hostName`, `ruleName`, `app`, `suid`, `serverPort`, `clientIp`, `serverIp`, `requestMethod`, `respCode`, `sslCertCommonName`, `fileName`, `fileType`, `respAppVersion`, `request` | Field to group results by |
| `log_type` | `network`, `detections` | API endpoint |
| `orientation` | `horizontal`, `vertical` | Chart style |
| `query` | TMV1 syntax | Search query |

### Query Syntax

```
hostName:(*.example.com)                    # Hostname wildcard
app:(RDP OR SSH)                            # Application match
dstPort:(22 OR 3389)                        # Port match
ruleName:(*attack*)                         # Detection rule match
(productCode:pdi OR productCode:xns)        # NDR sensor filter
NOT serverIp:(10.* OR 192.168.*)            # Exclude private IPs
```

---

## Infrastructure (Terraform)

### Resources Created

| Resource | Type | Purpose |
|----------|------|---------|
| EC2 | t3.medium (4GB, 30GB gp3) | Application server |
| ALB | Application LB | HTTPS termination, health checks |
| ACM | DNS-validated cert | TLS 1.3 for domain |
| Route53 | A record (alias) | `secassess.nordicnetintruders.com` -> ALB |
| Security Groups | ALB + EC2 | ALB: 80/443; EC2: 3000 from ALB + SSH |
| IAM | EC2 instance profile | SSM access for management |

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `eu-north-1` | AWS region |
| `domain_name` | `secassess.nordicnetintruders.com` | Platform domain |
| `hosted_zone_id` | `Z05323043AEFFK0DYL2D0` | Route53 zone |
| `instance_type` | `t3.medium` | EC2 size |
| `allowed_cidrs` | `[162.120.188.0/24, 94.254.60.123/32]` | IP allowlist |
| `admin_cidr` | `162.120.188.0/24` | SSH access CIDR |

### Updating the EC2

```bash
# Via SSM (no SSH needed)
aws ssm send-command --instance-ids <id> --document-name AWS-RunShellScript \
  --parameters 'commands=["cd /opt/secassess && git pull && systemctl restart secassess"]'

# Or SSH directly
ssh ubuntu@<ec2-ip> "cd /opt/secassess && git pull && sudo systemctl restart secassess"
```

---

## Supported LLM Providers (AI Scan)

| Provider | Default Endpoint | Default Model | Notes |
|----------|-----------------|---------------|-------|
| `openai` | `https://api.openai.com/v1` | gpt-4 | Requires LLM API key |
| `anthropic` | via LiteLLM proxy | claude-sonnet-4-6 | Auto-starts LiteLLM |
| `ollama` | `http://localhost:11434/v1` | llama3 | No API key needed |
| `azure_openai` | must provide | gpt-4 | Requires endpoint + key |
| `custom` | must provide | must provide | Any OpenAI-compatible |

---

## Security

- API keys passed per-request, stored in `sessionStorage` (cleared on tab close)
- Keys injected as environment variables to Python subprocesses, never written to disk
- All traffic encrypted with TLS 1.3 (ACM certificate, auto-renewed)
- HTTP automatically redirected to HTTPS
- EC2 accepts traffic only from ALB security group on port 3000
- Rate limiting: 5 req/min for run operations, 60 req/min for reads
- Process timeout: 2 hours max for spawned Python processes
- Input validation: CSV max 500KB, max 100 searches, time interval 1-8760h
- Subprocess spawning uses array args (no shell injection)

---

## Development

```bash
# Watch mode (auto-restart on changes)
cd web && npm run dev

# Run assessment locally (without web UI)
source .venv/bin/activate
export TREND_MICRO_API_KEY="your-key"
python3 python_scripts/run_assessment.py --csv templates/input.csv --output results --time-interval 720

# Run AI scan locally
export TMAS_API_KEY="your-key" LLM_API_KEY="your-key"
python3 python_scripts/run_ai_scan.py --provider openai --model gpt-4 --preset owasp --output results
```

---

## License

MIT
