#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# TMAS AI Security Scanner - Linux Server Install & Run Script
#
# Usage:
#   curl -sf https://raw.githubusercontent.com/Angelmountain/tmas-ai-scanner/master/install.sh | bash
#
# Or clone and run:
#   git clone https://github.com/Angelmountain/tmas-ai-scanner.git
#   cd tmas-ai-scanner
#   chmod +x install.sh
#   ./install.sh
# =============================================================================

echo "============================================"
echo "  TMAS AI Security Scanner - Installer"
echo "============================================"
echo ""

# --- Check/install prerequisites ---
install_prereqs() {
  echo "[1/4] Checking prerequisites..."

  # Python 3
  if ! command -v python3 &>/dev/null; then
    echo "  Installing Python 3..."
    if command -v apt-get &>/dev/null; then
      sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip python3-venv
    elif command -v yum &>/dev/null; then
      sudo yum install -y python3 python3-pip
    elif command -v dnf &>/dev/null; then
      sudo dnf install -y python3 python3-pip
    else
      echo "ERROR: Cannot install Python 3. Please install it manually."
      exit 1
    fi
  fi
  echo "  Python3: $(python3 --version)"

  # pip
  if ! python3 -m pip --version &>/dev/null; then
    echo "  Installing pip..."
    python3 -m ensurepip --upgrade 2>/dev/null || curl -sf https://bootstrap.pypa.io/get-pip.py | python3
  fi

  # jq
  if ! command -v jq &>/dev/null; then
    echo "  Installing jq..."
    if command -v apt-get &>/dev/null; then
      sudo apt-get install -y -qq jq
    elif command -v yum &>/dev/null; then
      sudo yum install -y jq
    else
      echo "ERROR: Cannot install jq. Please install it manually."
      exit 1
    fi
  fi

  echo "  All prerequisites OK"
  echo ""
}

# --- Clone repo if not already in it ---
setup_repo() {
  echo "[2/4] Setting up repository..."

  if [ -f "scripts/run_scan.py" ]; then
    echo "  Already in tmas-ai-scanner directory"
    SCAN_DIR="$(pwd)"
  elif [ -d "tmas-ai-scanner" ]; then
    echo "  Found existing clone"
    SCAN_DIR="$(pwd)/tmas-ai-scanner"
  else
    echo "  Cloning repository..."
    git clone --depth 1 https://github.com/Angelmountain/tmas-ai-scanner.git
    SCAN_DIR="$(pwd)/tmas-ai-scanner"
  fi

  cd "$SCAN_DIR"
  python3 -m pip install -q -r requirements.txt
  echo "  Dependencies installed"
  echo ""
}

# --- Download TMAS CLI ---
install_tmas() {
  echo "[3/4] Installing TMAS CLI..."

  if [ -x "./tmas" ]; then
    echo "  TMAS CLI already installed: $(./tmas version 2>&1 | head -1)"
  else
    METADATA=$(curl -sf https://ast-cli.xdr.trendmicro.com/tmas-cli/metadata.json)
    TMAS_VERSION=$(echo "$METADATA" | jq -r '.latestVersion' | sed 's/^v//')
    echo "  Latest version: ${TMAS_VERSION}"

    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64)  ARCH_NAME="x86_64" ;;
      aarch64) ARCH_NAME="arm64" ;;
      *)       echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    DOWNLOAD_URL="https://ast-cli.xdr.trendmicro.com/tmas-cli/${TMAS_VERSION}/tmas-cli_Linux_${ARCH_NAME}.tar.gz"
    echo "  Downloading from: ${DOWNLOAD_URL}"
    curl -sf "${DOWNLOAD_URL}" -o tmas.tar.gz
    tar -xzf tmas.tar.gz tmas
    rm tmas.tar.gz
    chmod +x tmas
    echo "  Installed: $(./tmas version 2>&1 | head -1)"
  fi
  echo ""
}

# --- Interactive scan setup ---
run_scan() {
  echo "[4/4] Configure and run scan"
  echo "============================================"
  echo ""

  # Vision One API Key
  if [ -z "${TMAS_API_KEY:-}" ] && [ -z "${VISION_ONE_API_KEY:-}" ]; then
    echo -n "Vision One API Key: "
    read -r TMAS_API_KEY
  else
    TMAS_API_KEY="${TMAS_API_KEY:-$VISION_ONE_API_KEY}"
    echo "Vision One API Key: [from environment]"
  fi
  export TMAS_API_KEY

  # Region
  if [ -z "${VISION_ONE_REGION:-}" ]; then
    echo ""
    echo "Regions: us-east-1, eu-central-1, ap-southeast-2, ap-south-1, ap-northeast-1, ap-southeast-1, me-central-1"
    echo -n "Region [eu-central-1]: "
    read -r REGION
    REGION="${REGION:-eu-central-1}"
  else
    REGION="$VISION_ONE_REGION"
    echo "Region: $REGION"
  fi

  # Provider
  if [ -z "${LLM_PROVIDER:-}" ]; then
    echo ""
    echo "Providers: openai, anthropic, ollama, azure_openai, custom"
    echo -n "Provider [openai]: "
    read -r PROVIDER
    PROVIDER="${PROVIDER:-openai}"
  else
    PROVIDER="$LLM_PROVIDER"
    echo "Provider: $PROVIDER"
  fi

  # Endpoint
  if [ -z "${LLM_ENDPOINT:-}" ]; then
    case "$PROVIDER" in
      openai)   DEFAULT_EP="https://api.openai.com/v1" ;;
      ollama)   DEFAULT_EP="http://localhost:11434/v1" ;;
      anthropic) DEFAULT_EP="https://api.anthropic.com/v1" ;;
      *)        DEFAULT_EP="" ;;
    esac
    echo -n "Endpoint [${DEFAULT_EP}]: "
    read -r ENDPOINT
    ENDPOINT="${ENDPOINT:-$DEFAULT_EP}"
  else
    ENDPOINT="$LLM_ENDPOINT"
    echo "Endpoint: $ENDPOINT"
  fi

  # API Key
  if [ -z "${LLM_API_KEY:-}" ]; then
    if [ "$PROVIDER" = "ollama" ]; then
      LLM_API_KEY="not-needed"
      echo "LLM API Key: not-needed (Ollama)"
    else
      echo -n "LLM API Key: "
      read -r LLM_API_KEY
    fi
  else
    echo "LLM API Key: [from environment]"
  fi
  export LLM_API_KEY

  # Model
  if [ -z "${LLM_MODEL:-}" ]; then
    case "$PROVIDER" in
      openai)    DEFAULT_MODEL="gpt-4o" ;;
      anthropic) DEFAULT_MODEL="claude-sonnet-4-6" ;;
      ollama)    DEFAULT_MODEL="llama3" ;;
      *)         DEFAULT_MODEL="" ;;
    esac
    echo -n "Model [${DEFAULT_MODEL}]: "
    read -r MODEL
    MODEL="${MODEL:-$DEFAULT_MODEL}"
  else
    MODEL="$LLM_MODEL"
    echo "Model: $MODEL"
  fi

  # Preset
  if [ -z "${ATTACK_PRESET:-}" ]; then
    echo -n "Attack preset (owasp/mitre) [owasp]: "
    read -r PRESET
    PRESET="${PRESET:-owasp}"
  else
    PRESET="$ATTACK_PRESET"
    echo "Preset: $PRESET"
  fi

  echo ""
  echo "============================================"
  echo "  Starting scan..."
  echo "  Provider: $PROVIDER"
  echo "  Endpoint: $ENDPOINT"
  echo "  Model:    $MODEL"
  echo "  Preset:   $PRESET"
  echo "============================================"
  echo ""

  # Handle Anthropic via LiteLLM proxy
  if [ "$PROVIDER" = "anthropic" ]; then
    echo "Starting LiteLLM proxy for Anthropic..."
    pip install -q 'litellm[proxy]'
    export ANTHROPIC_API_KEY="$LLM_API_KEY"
    nohup litellm --model "anthropic/${MODEL}" --port 4000 --host 0.0.0.0 > litellm.log 2>&1 &
    LITELLM_PID=$!
    for i in $(seq 1 30); do
      if curl -sf http://localhost:4000/health > /dev/null 2>&1; then
        echo "LiteLLM proxy ready"
        break
      fi
      sleep 2
    done
    ENDPOINT="http://localhost:4000/v1"
  fi

  # Generate config
  python3 scripts/generate_config.py \
    --endpoint "$ENDPOINT" \
    --model "$MODEL" \
    --api-key-env "LLM_API_KEY" \
    --preset "$PRESET" \
    --output config.yaml

  # Run scan
  mkdir -p results
  python3 scripts/run_scan.py \
    --config config.yaml \
    --region "$REGION" \
    --tmas-api-key "$TMAS_API_KEY" \
    --output-dir results \
    --verbose

  # Cleanup LiteLLM if started
  if [ -n "${LITELLM_PID:-}" ]; then
    kill "$LITELLM_PID" 2>/dev/null || true
  fi

  echo ""
  echo "============================================"
  echo "  Scan complete!"
  echo "  Results: results/latest.json"
  echo "  Report:  results/latest.html"
  echo "============================================"
}

# --- Main ---
install_prereqs
setup_repo
install_tmas
run_scan
