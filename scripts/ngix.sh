#!/usr/bin/env bash
set -e

# TsarChain — Nginx VPS Setup Script
# Auto-detect repo directory & frontend build path
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_DIR}/src/web/Frontend/dist"
IP_OR_DOMAIN="${1:-38.253.224.105}"

echo "[*] Setting up Nginx for TsarChain Explorer (${IP_OR_DOMAIN})..."

# 1. Install Nginx
if ! command -v nginx >/dev/null 2>&1; then
    echo "[*] Installing Nginx..."
    sudo apt update && sudo apt install -y nginx
fi

# 2. Verify frontend dist exists
if [ ! -d "${DIST_DIR}" ]; then
    echo "[!] Warning: ${DIST_DIR} not found!"
    echo "[!] Running 'npm run build' inside src/web/Frontend first is recommended."
fi

# 3. Create Nginx site configuration
CONFIG_PATH="/etc/nginx/sites-available/tsarchain"

sudo tee "${CONFIG_PATH}" >/dev/null <<EOF
server {
    listen 80;
    server_name ${IP_OR_DOMAIN};

    root ${DIST_DIR};
    index index.html;

    # SPA routing fallback for React Router
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Reverse proxy to TsarChain Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        client_max_body_size 160M;
        proxy_buffering off;
        proxy_read_timeout 120s;
    }
}
EOF

# 4. Enable site & disable default if present
sudo ln -sf "${CONFIG_PATH}" /etc/nginx/sites-enabled/tsarchain
sudo rm -f /etc/nginx/sites-enabled/default

# 5. Test & restart
echo "[*] Testing Nginx configuration..."
sudo nginx -t

echo "[*] Restarting Nginx service..."
sudo systemctl enable nginx
sudo systemctl restart nginx

# 6. Allow HTTP traffic on UFW if active
if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -qw "active"; then
    echo "[*] Updating firewall (UFW)..."
    sudo ufw allow 80/tcp
    sudo ufw reload
fi

echo "[✓] Nginx setup complete! Web Explorer active on http://${IP_OR_DOMAIN}"
