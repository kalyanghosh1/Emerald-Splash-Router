#!/bin/bash
set -e

# Update and install dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 nginx certbot python3-certbot-nginx sqlite3 git curl

# Stop Nginx
systemctl stop nginx || true

# Configure Nginx
cat << 'EOF' > /etc/nginx/sites-available/emeraldproxy
server {
    listen 80;
    
    # Storage optimization: Disable access logs
    access_log off;
    error_log /var/log/nginx/error.log warn;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Disable buffering for streaming (SSE)
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/emeraldproxy /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default || true
nginx -t
systemctl start nginx || true

# Bring up docker stack
docker compose up -d --build

echo "Setup complete! Emerald Splash Router is now running."
