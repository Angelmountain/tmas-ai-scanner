# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TMAS AI Scanner is an automated security testing pipeline for OpenAI-compatible LLM endpoints using Trend Micro Artifact Scanner (TMAS). It tests endpoints against OWASP LLM Top 10 and MITRE ATT&CK frameworks via GitHub Actions, local install script, or direct CLI.

## How to Run

### Install & Run (any Linux server)
```bash
git clone https://github.com/Angelmountain/tmas-ai-scanner.git && cd tmas-ai-scanner && ./install.sh
```
The install script creates a `.venv`, installs deps, downloads TMAS CLI, and runs an interactive scan. Set env vars to skip prompts.

### Local Ollama Scan
```bash
source .venv/bin/activate
export TMAS_API_KEY="<vision-one-key>"
export LLM_API_KEY="not-needed"
python3 scripts/generate_config.py --provider ollama --model llama2-uncensored --preset owasp --output config.yaml
python3 scripts/run_scan.py --config config.yaml --region eu-central-1 --tmas-api-key "$TMAS_API_KEY" --output-dir results --verbose --timeout 3600
```

### GitHub Actions
Trigger manually via `workflow_dispatch` in `.github/workflows/ai-security-scan.yml`. Select provider (openai/anthropic/ollama/azure_openai/custom), region, model, and attack preset. For Ollama, models are pulled and run inside the CI runner. For Anthropic, a LiteLLM proxy is started automatically.

## Architecture

The pipeline has three stages:

1. **Config generation** (`scripts/generate_config.py`) — Produces `config.yaml` with target endpoint, model, API key env var reference, and attack preset. Supports provider presets (openai, anthropic, ollama, azure_openai, custom).

2. **Scan execution** (`scripts/run_scan.py`) — Runs `./tmas aiscan llm --config config.yaml`, captures stdout/stderr, parses findings. Default timeout: 3600s (1 hour) — local Ollama models are slow.

3. **Report generation** (also in `run_scan.py`) — Produces timestamped + `latest.*` copies of both JSON and HTML reports in `results/`.

### Data Flow
```
User inputs → generate_config.py → config.yaml → run_scan.py → tmas CLI → results/*.{json,html}
```

### Key Design Decisions

- **`api_key_env` not `api_key`**: Config YAML references the env var name (`LLM_API_KEY`), not the secret itself.
- **Endpoint is base URL**: TMAS appends `/chat/completions` automatically.
- **`target.name` required**: TMAS v2.198.0+ requires this field in config.
- **TMAS binary downloaded dynamically**: From `https://ast-cli.xdr.trendmicro.com/tmas-cli/`, gitignored (63MB). Supports x86_64 and arm64.
- **Anthropic via LiteLLM**: TMAS uses OpenAI-compatible format. Anthropic provider auto-starts a LiteLLM proxy to translate.
- **Ollama in CI**: When provider is `ollama`, the workflow installs Ollama, pulls the model, and runs it inside the GitHub Actions runner.
- **Virtual environment**: `install.sh` uses `.venv/` to avoid PEP 668 errors on modern Debian/Ubuntu.

## Provider Defaults

| Provider | Default Endpoint | Default Model |
|----------|-----------------|---------------|
| openai | `https://api.openai.com/v1` | gpt-4 |
| anthropic | `https://api.anthropic.com/v1` (via LiteLLM proxy) | claude-sonnet-4-6 |
| ollama | `http://localhost:11434/v1` | llama3 |
| azure_openai | (must provide) | gpt-4 |
| custom | (must provide) | (must provide) |

## Default Scan Preferences

When triggering scans, use these defaults unless the user specifies otherwise:

- **Region**: `eu-central-1`
- **Attack presets**: Run **both** `owasp` and `mitre`
- **Cloud models**: gpt-4, gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo, claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5-20251001
- **Ollama models for demo**: llama2-uncensored, llama3, mistral, phi3, gemma2
- **Always ask for**: Vision One API key and LLM API key (never store these)

Use the `/scan` command to trigger scans quickly.

## Recommended Ollama Models for Security Demo

These models are good for showcasing AI security vulnerabilities:
- `llama2-uncensored` — Deliberately unaligned, most findings
- `llama3` — Aligned baseline for comparison
- `mistral` — Popular, moderate safety
- `phi3` — Microsoft small model
- `gemma2` — Google's open model

Note: Ollama scans need long timeouts (use `--timeout 3600`). Models run on CPU in CI which is slower than local GPU.

## Files That Are Gitignored

`config.yaml`, `results/`, `.env`, `.venv/`, `tmas` binary — these contain secrets, environments, or large binaries and must not be committed.
