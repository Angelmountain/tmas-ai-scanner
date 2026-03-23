# Security Assessment Platform

A unified web platform combining **Trend Micro Vision One API security assessment** with **TMAS AI security scanning** for LLM endpoints. Features a modern dark-themed UI, GitHub Actions integration, interactive charts, and downloadable Excel + PowerPoint reports.

**Live**: [https://secassess.nordicnetintruders.com](https://secassess.nordicnetintruders.com)

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │    Browser (HTTPS)           │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │  AWS ALB (ACM TLS 1.3)      │
                    │  secassess.nordicnetintruders│
                    └──────────┬──────────────────┘
                               │ :3000
                    ┌──────────▼──────────────────┐
                    │  Node.js Express Backend     │
                    │  (web/server.js)             │
                    │                              │
                    │  ┌────────────────────────┐  │
                    │  │ API Routes             │  │
                    │  │ /api/assessment/*      │  │
                    │  │ /api/aiscan/*          │  │
                    │  │ /api/github/*          │  │
                    │  │ /api/csv/*             │  │
                    │  └──────┬─────────────────┘  │
                    └─────────┼────────────────────┘
                              │ child_process.spawn
              ┌───────────────┼───────────────────┐
              ▼               ▼                   ▼
    ┌──────────────┐ ┌──────────────┐   ┌──────────────┐
    │run_assessment│ │run_ai_scan   │   │gh CLI        │
    │.py           │ │.py           │   │(GitHub API)  │
    │              │ │              │   │              │
    │Vision One API│ │TMAS CLI      │   │Workflow runs │
    │→ Excel       │ │→ JSON/HTML   │   │Dispatch      │
    │→ PowerPoint  │ │→ Findings    │   │Artifacts     │
    └──────────────┘ └──────────────┘   └──────────────┘
```

### Components

| Component | Tech | Purpose |
|-----------|------|---------|
| **Frontend** | Vanilla JS, Chart.js | Single HTML file SPA, dark theme, interactive charts |
| **Backend** | Node.js Express | REST API, Python process orchestration, file serving |
| **Assessment** | Python (requests, pandas) | Vision One API queries, Excel/PowerPoint report gen |
| **AI Scan** | Python + TMAS CLI | LLM endpoint security testing (OWASP/MITRE) |
| **GitHub** | gh CLI | Workflow monitoring, dispatch, artifact management |
| **Infra** | Terraform | EC2 + ALB + ACM + Route53 on AWS |

---

## Features

### Vision One Security Assessment
- **25 pre-built searches** covering network detections, account usage, protocols, RDP/SSH, PUA detection, geographic risks, and vendor analysis
- **Custom CSV upload** with full documentation, drag-and-drop, and template generators
- Real-time progress tracking with live console output
- Interactive **Chart.js bar charts** for each search result
- **Excel export** for every search + **PowerPoint report** generation from branded template

### TMAS AI Security Scanning
- Test LLM endpoints against **OWASP LLM Top 10** and **MITRE ATT&CK**
- Support for **OpenAI, Anthropic, Ollama, Azure OpenAI**, and custom endpoints
- Risk level assessment (Critical/High/Medium/Low) with doughnut charts
- Detailed findings table with pass/fail per test

### GitHub Actions Integration
- Monitor workflow runs across repositories with auto-refresh
- View step-by-step execution details
- Trigger AI scans and assessments directly from the UI
- Download artifacts from completed runs

---

## Quick Start

### Local Development

```bash
# Clone
git clone https://github.com/Angelmountain/tmas-ai-scanner.git
cd tmas-ai-scanner

# Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Node.js dependencies
cd web && npm install && cd ..

# Run (default port 3000)
cd web && node server.js
```

Open http://localhost:3000

### Deploy to AWS

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Creates: EC2 (t3.medium) + ALB + ACM certificate + Route53 DNS record.

---

## Project Structure

```
tmas-ai-scanner/
├── web/
│   ├── server.js              # Express backend (all API routes)
│   ├── package.json           # Node.js dependencies
│   └── public/
│       └── index.html         # Single-file SPA frontend
├── python_scripts/
│   ├── run_assessment.py      # Vision One API search orchestrator
│   ├── run_ai_scan.py         # TMAS CLI wrapper
│   └── generate_ppt_report.py # PowerPoint report generator
├── scripts/
│   ├── generate_config.py     # TMAS config YAML generator
│   └── run_scan.py            # TMAS scan executor
├── terraform/
│   ├── main.tf                # AWS infrastructure (EC2+ALB+ACM+R53)
│   ├── variables.tf           # Configuration variables
│   ├── outputs.tf             # Deployment outputs
│   └── userdata.sh            # EC2 bootstrap script
├── templates/
│   ├── input.csv              # 25 pre-built search definitions
│   └── NDR_Security_Assessment.pptx  # PowerPoint template v2.0
├── .github/workflows/
│   └── ai-security-scan.yml  # GitHub Actions workflow
├── requirements.txt           # Python dependencies
└── install.sh                 # Standalone Linux installer
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/searches/prebuilt` | List 25 pre-built searches |
| `POST` | `/api/assessment/run` | Start assessment (returns jobId) |
| `GET` | `/api/assessment/status/:id` | Poll job progress |
| `GET` | `/api/assessment/results/:id` | Get results + Excel file list |
| `GET` | `/api/assessment/download/:id` | Download ZIP (Excel + PPT) |
| `POST` | `/api/csv/upload` | Upload and validate custom CSV |
| `GET` | `/api/csv/template/:category` | Download CSV template |
| `POST` | `/api/aiscan/run` | Start TMAS AI scan |
| `GET` | `/api/aiscan/status/:id` | Poll scan progress |
| `GET` | `/api/aiscan/results/:id` | Get scan findings |
| `GET` | `/api/github/runs` | List GitHub Actions runs |
| `POST` | `/api/github/dispatch/:wf` | Trigger workflow |

---

## CSV Format for Custom Searches

Upload a CSV file with these columns:

| Column | Required | Description | Example |
|--------|----------|-------------|---------|
| `name` | Yes | Search display name | `AI_Usage_OpenAI` |
| `query` | Yes | TMV1 query syntax | `hostName:(*.openai.com)` |
| `description` | No | Human-readable description | `Monitor OpenAI usage` |
| `sorting` | No | Aggregation field | `hostnameDNS`, `ruleName`, `app` |
| `log_type` | No | API endpoint | `network`, `detections` |
| `orientation` | No | Chart orientation | `horizontal`, `vertical` |

### TMV1 Query Syntax

```
hostName:(*.example.com)              # Match hostnames
app:(RDP OR SSH)                      # Match applications
dstPort:(22 OR 3389)                  # Match ports
ruleName:(*SSH*)                      # Match detection rules
(productCode:pdi OR productCode:xns)  # Filter by sensor
```

---

## Infrastructure

### Terraform Resources

| Resource | Type | Purpose |
|----------|------|---------|
| EC2 Instance | t3.medium | Application server (4GB RAM, 30GB gp3) |
| ALB | Application | HTTPS termination, health checks |
| ACM Certificate | DNS-validated | TLS 1.3 for secassess.nordicnetintruders.com |
| Route53 Record | A (alias) | DNS pointing to ALB |
| Security Groups | ALB + EC2 | ALB: 80/443 public; EC2: 3000 from ALB only |
| IAM Role | EC2 profile | SSM access for management |

### HTTPS

All traffic is encrypted:
- **Browser → ALB**: TLS 1.3 (ACM certificate, auto-renewed)
- **HTTP → HTTPS**: Automatic 301 redirect
- **ALB → EC2**: HTTP on port 3000 (private network, SG-restricted)

---

## Pre-built Searches (25)

| Category | Searches |
|----------|----------|
| **Network** | Network Detections, Server Ports, Protocols, Request Methods, Response Codes, SSL Certs |
| **Accounts** | Top Accounts Used, Unsuccessful Logons |
| **Files** | Top Files, File Types |
| **SSH** | SSH Detections, SSH Versions |
| **RDP** | RDP Users, Source IPs, Destination IPs |
| **PUA** | AI Services, Remote Access, Cloud Storage, Darknet Links, Admin Usage |
| **Geographic** | Bad States (sanctioned countries), Russian IT, EPP/EDR/XDR Vendors, Firewall Vendors, US Vendors |

---

## Supported LLM Providers

| Provider | Default Endpoint | Default Model |
|----------|-----------------|---------------|
| OpenAI | `https://api.openai.com/v1` | gpt-4 |
| Anthropic | via LiteLLM proxy | claude-sonnet-4-6 |
| Ollama | `http://localhost:11434/v1` | llama3 |
| Azure OpenAI | (must provide) | gpt-4 |
| Custom | (must provide) | (must provide) |

---

## Security

- API keys are **never stored on disk** - passed per-request from frontend via `sessionStorage`
- Backend passes keys to Python scripts via **environment variables only**
- All public traffic **encrypted with TLS 1.3**
- EC2 only accepts traffic from **ALB security group** on port 3000
- Rate limiting: 5 req/min for scan/assessment, 60 req/min for reads
- Input validation: CSV max 2MB, script names regex-validated against path traversal

---

## License

MIT
