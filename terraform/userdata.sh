#!/bin/bash
set -euo pipefail

exec > /var/log/userdata.log 2>&1
echo "=== Security Assessment Platform Bootstrap ==="
echo "Started at: $(date)"

# ─── System updates ───────────────────────────────────────────────────────────
apt-get update -y
apt-get install -y curl git python3 python3-pip python3-venv python3-full jq unzip zip

# ─── Node.js 18 LTS ──────────────────────────────────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs
echo "Node.js version: $(node --version)"
echo "npm version: $(npm --version)"

# ─── GitHub CLI ───────────────────────────────────────────────────────────────
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt-get update -y
apt-get install -y gh

# ─── Clone repository ────────────────────────────────────────────────────────
APP_DIR="/opt/secassess"
git clone https://github.com/Angelmountain/tmas-ai-scanner.git "$APP_DIR"
cd "$APP_DIR"

# ─── Python virtual environment ──────────────────────────────────────────────
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pandas openpyxl python-pptx requests tldextract

# ─── Node.js dependencies ────────────────────────────────────────────────────
cd web
npm install --production
cd ..

# ─── Download TMAS binary ────────────────────────────────────────────────────
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  TMAS_ARCH="linux_x86_64"
elif [ "$ARCH" = "aarch64" ]; then
  TMAS_ARCH="linux_arm64"
fi

TMAS_URL="https://ast-cli.xdr.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_${TMAS_ARCH}.tar.gz"
echo "Downloading TMAS from: $TMAS_URL"
curl -sL "$TMAS_URL" -o /tmp/tmas.tar.gz
tar -xzf /tmp/tmas.tar.gz -C "$APP_DIR/"
chmod +x "$APP_DIR/tmas"
rm /tmp/tmas.tar.gz
echo "TMAS version: $($APP_DIR/tmas --version 2>/dev/null || echo 'installed')"

# ─── Add swap space (prevents OOM on t3.medium with 4GB RAM) ─────────────────
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "Swap enabled: 2G"
fi

# ─── Create data directories ─────────────────────────────────────────────────
mkdir -p "$APP_DIR/data/jobs"

# ─── Systemd service ─────────────────────────────────────────────────────────
cat > /etc/systemd/system/secassess.service << 'SERVICEEOF'
[Unit]
Description=Security Assessment Platform
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/secassess/web
ExecStart=/usr/bin/node /opt/secassess/web/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=PATH=/opt/secassess/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=NODE_OPTIONS=--max-old-space-size=512
MemoryMax=3G

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Fix ownership
chown -R ubuntu:ubuntu "$APP_DIR"

# Enable and start
systemctl daemon-reload
systemctl enable secassess
systemctl start secassess

echo "=== Bootstrap complete at $(date) ==="
echo "App running on port 3000"
