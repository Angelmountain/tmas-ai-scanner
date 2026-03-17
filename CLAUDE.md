# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TMAS AI Scanner is an automated security testing pipeline for OpenAI-compatible LLM endpoints using Trend Micro Artifact Scanner (TMAS). It tests endpoints against OWASP LLM Top 10 and MITRE ATT&CK frameworks via a GitHub Actions workflow or local shell script.

## How to Run

### Local
```bash
pip install -r requirements.txt
# Copy .env.example to .env and fill in values
./scan.sh
```

### GitHub Actions
Trigger manually via `workflow_dispatch` in `.github/workflows/ai-security-scan.yml`. Inputs: Vision One API key, region, LLM endpoint, LLM API key, model name, attack preset, optional system prompt.

## Architecture

The pipeline has three stages:

1. **Config generation** (`scripts/generate_config.py`) — Takes environment/input parameters and produces `config.yaml` with target endpoint, model, API key env var reference, and attack preset.

2. **Scan execution** (`scripts/run_scan.py`) — Runs `./tmas aiscan llm --config config.yaml`, captures stdout/stderr, parses findings (pass/fail + scores via regex), and generates reports.

3. **Report generation** (also in `run_scan.py`) — Produces timestamped + `latest.*` copies of both JSON and HTML reports in `results/`. HTML report uses dark theme with risk badge, stats cards, findings table, and raw output.

### Data Flow
```
User inputs → generate_config.py → config.yaml → run_scan.py → tmas CLI → results/*.{json,html}
```

### Key Design Decisions

- **`api_key_env` not `api_key`**: Config YAML references the environment variable name (`LLM_API_KEY`), not the secret itself. TMAS reads the actual key from the environment at runtime.
- **Endpoint is base URL**: TMAS appends `/chat/completions` automatically, so endpoints should be base URLs like `https://api.openai.com/v1`.
- **`target.name` required**: TMAS v2.198.0+ requires this field in config.
- **TMAS binary is downloaded dynamically**: From `https://ast-cli.xdr.trendmicro.com/tmas-cli/`, gitignored (63MB).

## Dependencies

- Python 3.10+ (CI uses 3.12)
- `pyyaml`, `jinja2` (see requirements.txt)
- TMAS CLI binary (auto-downloaded by scan.sh and the workflow)

## Attack Presets

- `owasp` — OWASP Top 10 for LLM Applications (LLM01–LLM10)
- `mitre` — MITRE ATT&CK framework mappings for AI/ML

## Risk Calculation

Based on failed check count: >5 → CRITICAL, >2 → HIGH, >0 → MEDIUM, 0 → LOW.

## Supported Providers

OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM, or any OpenAI-compatible endpoint.

## Default Scan Preferences

When triggering scans, use these defaults unless the user specifies otherwise:

- **LLM endpoint**: `https://api.openai.com/v1`
- **Region**: `eu-central-1`
- **Attack presets**: Run **both** `owasp` and `mitre` (two separate workflow runs)
- **Models**: Run **both** `gpt-4` and `gpt-4o` (separate runs per model)
- **Always ask for**: Vision One API key and LLM API key (never store these)

A full scan matrix is: 2 presets x 2 models = 4 workflow runs.

Use the `/scan` command to trigger scans quickly.

## Files That Are Gitignored

`config.yaml`, `results/`, `.env`, `tmas` binary — these contain secrets or large binaries and must not be committed.
