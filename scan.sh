#!/bin/bash
set -euo pipefail

# TMAS AI Scanner - Local Run Script
# Usage: ./scan.sh
# Requires: .env file with configuration (see .env.example)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load env
if [ -f .env ]; then
    set -a; source .env; set +a
else
    echo "ERROR: .env file not found. Copy .env.example to .env and fill in your keys."
    exit 1
fi

# Download TMAS if needed
if [ ! -f "./tmas" ]; then
    echo "Downloading TMAS CLI..."
    curl -sL https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/linux/x86_64/latest/tmas -o tmas
    chmod +x tmas
fi

echo "TMAS version: $(./tmas version 2>&1 | grep Version | head -1)"

# Generate config
python3 scripts/generate_config.py \
    --endpoint "${LLM_ENDPOINT}" \
    --llm-api-key "${LLM_API_KEY}" \
    --model "${LLM_MODEL}" \
    --preset "${ATTACK_PRESET:-owasp}" \
    --output config.yaml

# Run scan
python3 scripts/run_scan.py \
    --config config.yaml \
    --region "${TMAS_REGION:-us-east-1}" \
    --tmas-api-key "${TMAS_API_KEY}" \
    --output-dir results \
    --verbose

echo ""
echo "Results saved to results/"
echo "  - results/latest.json  (machine-readable)"
echo "  - results/latest.html  (open in browser)"
