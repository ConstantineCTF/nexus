# NEXUS Deployment Guide

Production deployment guide for NEXUS Secrets Manager.

---

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Prerequisites](#prerequisites)
- [Linux Deployment](#linux-deployment)
- [Windows Deployment](#windows-deployment)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Security Hardening](#security-hardening)
- [Monitoring and Operations](#monitoring-and-operations)
- [Backup Strategy](#backup-strategy)
- [Troubleshooting](#troubleshooting)

---

## Deployment Overview

### Deployment Options

| Option | Best For | Complexity |
|--------|----------|------------|
| Binary | Simple deployments, VMs | Low |
| Docker | Containerized environments | Medium |
| Kubernetes | Cloud-native, scaling | High |

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 256 MB | 512 MB+ |
| Disk | 100 MB | 1 GB+ |
| OS | Linux, Windows, macOS | Linux (Ubuntu 22.04+) |

---

## Prerequisites

### Build Requirements

- **Go 1.23+** for building from source
- **Make** for build automation
- **Git** for source code

### Runtime Requirements

- No external dependencies (statically compiled)
- SQLite included in binary

---

## Linux Deployment

### Step 1: Build or Download

**Build from source:**
```bash
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus
make build
```

**Binaries location:**
```
./bin/nexus      # Server
./bin/nexusctl   # CLI
```

### Step 2: Create System User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false nexus

# Create data directories
sudo mkdir -p /opt/nexus
sudo mkdir -p /var/lib/nexus
sudo mkdir -p /var/log/nexus

# Set ownership
sudo chown -R nexus:nexus /opt/nexus
sudo chown -R nexus:nexus /var/lib/nexus
sudo chown -R nexus:nexus /var/log/nexus
```

### Step 3: Install Binaries

```bash
# Copy binaries
sudo cp bin/nexus /opt/nexus/
sudo cp bin/nexusctl /opt/nexus/

# Make executable
sudo chmod +x /opt/nexus/nexus
sudo chmod +x /opt/nexus/nexusctl

# Create symlink for CLI
sudo ln -sf /opt/nexus/nexusctl /usr/local/bin/nexusctl
```

### Step 4: Configure Environment

Create `/etc/nexus/environment`:
```bash
sudo mkdir -p /etc/nexus
sudo tee /etc/nexus/environment << 'EOF'
NEXUS_KEY_PASSWORD=your-secure-keyring-password-here
EOF
sudo chmod 600 /etc/nexus/environment
sudo chown nexus:nexus /etc/nexus/environment
```

> ⚠️ **Important:** Use a strong, unique password for `NEXUS_KEY_PASSWORD`

### Step 5: Create Systemd Service

Create `/etc/systemd/system/nexus.service`:
```ini
[Unit]
Description=NEXUS Secrets Manager
Documentation=https://github.com/ConstantineCTF/nexus
After=network.target

[Service]
Type=simple
User=nexus
Group=nexus
WorkingDirectory=/var/lib/nexus
EnvironmentFile=/etc/nexus/environment

ExecStart=/opt/nexus/nexus \
    -addr :9000 \
    -storage sqlite \
    -db /var/lib/nexus/nexus.db

Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nexus /var/log/nexus
PrivateTmp=true

# Resource limits
LimitNOFILE=65535
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

### Step 6: Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable nexus
sudo systemctl start nexus

# Check status
sudo systemctl status nexus

# View logs
sudo journalctl -u nexus -f
```

### Step 7: Verify Installation

```bash
# Check health endpoint
curl http://localhost:9000/health

# Login
nexusctl login --server http://localhost:9000

# Test secret operations
nexusctl secret create test/hello "world"
nexusctl secret get test/hello
nexusctl secret delete test/hello
```

---

## Windows Deployment

### Step 1: Build or Download

**Build from source (PowerShell):**
```powershell
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus
go build -o bin\nexus.exe ./cmd/nexus
go build -o bin\nexusctl.exe ./cmd/nexusctl
```

### Step 2: Create Directory Structure

```powershell
# Create directories
New-Item -ItemType Directory -Path "C:\Program Files\NEXUS" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\NEXUS" -Force

# Copy binaries
Copy-Item bin\nexus.exe "C:\Program Files\NEXUS\"
Copy-Item bin\nexusctl.exe "C:\Program Files\NEXUS\"

# Add to PATH
[Environment]::SetEnvironmentVariable(
    "Path",
    $env:Path + ";C:\Program Files\NEXUS",
    "Machine"
)
```

### Step 3: Configure Environment

Set environment variable (PowerShell as Administrator):
```powershell
[Environment]::SetEnvironmentVariable(
    "NEXUS_KEY_PASSWORD",
    "your-secure-keyring-password-here",
    "Machine"
)
```

### Step 4: Create Windows Service

Using NSSM (Non-Sucking Service Manager):
```powershell
# Download NSSM from nssm.cc
# Install service
nssm install NEXUS "C:\Program Files\NEXUS\nexus.exe"
nssm set NEXUS AppParameters "-addr :9000 -storage sqlite -db C:\ProgramData\NEXUS\nexus.db"
nssm set NEXUS AppDirectory "C:\ProgramData\NEXUS"
nssm set NEXUS DisplayName "NEXUS Secrets Manager"
nssm set NEXUS Start SERVICE_AUTO_START

# Start service
nssm start NEXUS
```

### Step 5: Configure Windows Firewall

```powershell
New-NetFirewallRule -DisplayName "NEXUS Server" -Direction Inbound -LocalPort 9000 -Protocol TCP -Action Allow
```

---

## Docker Deployment

### Dockerfile

Create `Dockerfile` (if not already present):
```dockerfile
# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy source
COPY . .

# Build binaries
RUN CGO_ENABLED=1 go build -o /nexus ./cmd/nexus
RUN CGO_ENABLED=0 go build -o /nexusctl ./cmd/nexusctl

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 nexus && \
    adduser -u 1000 -G nexus -s /bin/sh -D nexus

# Create directories
RUN mkdir -p /var/lib/nexus && \
    chown -R nexus:nexus /var/lib/nexus

# Copy binaries
COPY --from=builder /nexus /usr/local/bin/nexus
COPY --from=builder /nexusctl /usr/local/bin/nexusctl

USER nexus
WORKDIR /var/lib/nexus

EXPOSE 9000

ENTRYPOINT ["nexus"]
CMD ["-addr", ":9000", "-storage", "sqlite", "-db", "/var/lib/nexus/nexus.db"]
```

### Build Docker Image

```bash
docker build -t nexus:latest .
```

### Run with Docker

```bash
# Create volume for persistence
docker volume create nexus-data

# Run container
docker run -d \
  --name nexus \
  -p 9000:9000 \
  -v nexus-data:/var/lib/nexus \
  -e NEXUS_KEY_PASSWORD="your-secure-password" \
  --restart unless-stopped \
  nexus:latest
```

### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  nexus:
    build: .
    container_name: nexus
    ports:
      - "9000:9000"
    volumes:
      - nexus-data:/var/lib/nexus
    environment:
      - NEXUS_KEY_PASSWORD=${NEXUS_KEY_PASSWORD}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:9000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  nexus-data:
```

Run with Docker Compose:
```bash
# Set password
export NEXUS_KEY_PASSWORD="your-secure-password"

# Start
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## Configuration

### Server Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-addr` | `:9000` | Listen address and port |
| `-storage` | `memory` | Storage backend (`memory` or `sqlite`) |
| `-db` | `./nexus.db` | SQLite database path |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXUS_KEY_PASSWORD` | Yes (production) | Keyring encryption password |

### CLI Configuration

The CLI uses `~/.nexus/config.yaml`:
```yaml
server: http://localhost:9000
token: <jwt-token>
user:
  id: admin-001
  name: Admin User
  role: admin
```

### Production Configuration Example

```bash
# Server startup
./nexus \
  -addr :9000 \
  -storage sqlite \
  -db /var/lib/nexus/nexus.db

# Environment
NEXUS_KEY_PASSWORD="$(openssl rand -base64 32)"
```

---

## Security Hardening

### Network Security

#### 1. Use HTTPS (Reverse Proxy)

NEXUS doesn't include built-in TLS. Use a reverse proxy:

**Nginx configuration:**
```nginx
upstream nexus {
    server 127.0.0.1:9000;
}

server {
    listen 443 ssl http2;
    server_name nexus.example.com;

    ssl_certificate /etc/letsencrypt/live/nexus.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nexus.example.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://nexus;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name nexus.example.com;
    return 301 https://$host$request_uri;
}
```

#### 2. Firewall Rules

```bash
# Allow only specific IPs
sudo ufw default deny incoming
sudo ufw allow from 10.0.0.0/8 to any port 9000
sudo ufw allow from 192.168.0.0/16 to any port 9000
sudo ufw enable
```

#### 3. Bind to Localhost

If using reverse proxy:
```bash
./nexus -addr 127.0.0.1:9000 -storage sqlite
```

### File Permissions

```bash
# Database file
chmod 600 /var/lib/nexus/nexus.db

# Keyring directory
chmod 700 /var/lib/nexus/data/keys
chmod 600 /var/lib/nexus/data/keys/*

# Environment file
chmod 600 /etc/nexus/environment
```

### Credential Management

1. **Change default admin password** (implement in production)
2. **Use strong keyring password**: 20+ characters, mixed case, numbers, symbols
3. **Rotate backup passwords**: Different password for each backup
4. **Use API keys for automation**: Don't share JWT tokens

### Security Checklist

- [ ] Changed default admin credentials
- [ ] Set strong `NEXUS_KEY_PASSWORD`
- [ ] HTTPS enabled via reverse proxy
- [ ] Firewall configured
- [ ] File permissions restricted
- [ ] Backups encrypted with strong passwords
- [ ] Audit logs reviewed regularly
- [ ] Network access limited to trusted IPs

---

## Monitoring and Operations

### Health Checks

```bash
# Basic health check
curl -s http://localhost:9000/health | jq .

# Expected response:
# {"status":"healthy","timestamp":"2025-12-04T00:18:24Z"}
```

### Monitoring Script

```bash
#!/bin/bash
# /opt/nexus/health-check.sh

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/health)

if [ "$RESPONSE" != "200" ]; then
    echo "NEXUS health check failed: HTTP $RESPONSE"
    # Send alert (email, Slack, PagerDuty, etc.)
    exit 1
fi
```

Add to crontab:
```bash
*/5 * * * * /opt/nexus/health-check.sh
```

### Log Management

**Systemd logs:**
```bash
# View logs
journalctl -u nexus -f

# Export logs
journalctl -u nexus --since "1 week ago" > nexus-logs.txt
```

**Docker logs:**
```bash
docker logs nexus -f
docker logs nexus --since 1h
```

### Performance Metrics

Monitor these key metrics:
- Response time (p50, p95, p99)
- Request rate (requests/second)
- Error rate
- Database size
- Memory usage
- CPU usage

---

## Backup Strategy

### Automated Daily Backups

Create `/opt/nexus/backup.sh`:
```bash
#!/bin/bash

BACKUP_DIR="/var/backups/nexus"
RETENTION_DAYS=30
DATE=$(date +%Y-%m-%d)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Change to data directory
cd /var/lib/nexus

# Create backup (requires password in env or stdin)
echo "$NEXUS_BACKUP_PASSWORD" | /opt/nexus/nexusctl backup create --output "$BACKUP_DIR"

# Remove old backups
find "$BACKUP_DIR" -name "*.tar.gz.enc" -mtime +$RETENTION_DAYS -delete

# Optional: Copy to remote storage
# aws s3 cp "$BACKUP_DIR/nexus-backup-$DATE-*.tar.gz.enc" s3://my-backups/nexus/
```

Schedule with cron:
```bash
# Daily at 2 AM
0 2 * * * NEXUS_BACKUP_PASSWORD="backup-password" /opt/nexus/backup.sh >> /var/log/nexus/backup.log 2>&1
```

### Backup Verification

Monthly restore test:
```bash
#!/bin/bash
# /opt/nexus/verify-backup.sh

# Stop test instance
docker stop nexus-test 2>/dev/null || true
docker rm nexus-test 2>/dev/null || true

# Get latest backup
LATEST=$(ls -t /var/backups/nexus/*.tar.gz.enc | head -1)

# Restore to test directory
cd /tmp
echo "$NEXUS_BACKUP_PASSWORD" | nexusctl backup restore --file "$LATEST"

# Start test instance
docker run -d --name nexus-test \
  -p 9001:9000 \
  -v /tmp/nexus.db:/var/lib/nexus/nexus.db:ro \
  -v /tmp/data:/var/lib/nexus/data:ro \
  -e NEXUS_KEY_PASSWORD="$NEXUS_KEY_PASSWORD" \
  nexus:latest

sleep 5

# Verify health
if curl -s http://localhost:9001/health | grep -q "healthy"; then
    echo "Backup verification: PASSED"
else
    echo "Backup verification: FAILED"
    exit 1
fi

# Cleanup
docker stop nexus-test
docker rm nexus-test
rm -rf /tmp/nexus.db /tmp/data
```

### Backup Rotation

| Backup Type | Retention | Schedule |
|-------------|-----------|----------|
| Daily | 30 days | Every day at 2 AM |
| Weekly | 12 weeks | Every Sunday |
| Monthly | 12 months | First of month |

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
journalctl -u nexus -n 50 --no-pager
```

**Common causes:**
1. Wrong keyring password
2. Database file locked
3. Port already in use
4. Permissions issue

**Fix port conflict:**
```bash
# Find what's using port 9000
sudo lsof -i :9000

# Use different port
./nexus -addr :9001 -storage sqlite
```

### Database Locked

**Symptom:**
```
Error: database is locked
```

**Solution:**
```bash
# Stop all NEXUS processes
sudo systemctl stop nexus
pkill -f nexus

# Remove lock files (if needed)
rm -f /var/lib/nexus/nexus.db-shm
rm -f /var/lib/nexus/nexus.db-wal

# Restart
sudo systemctl start nexus
```

### Memory Issues

**Symptom:**
```
fatal error: runtime: out of memory
```

**Solution:**
```bash
# Increase memory limit in systemd
sudo systemctl edit nexus

# Add:
[Service]
MemoryMax=1G
```

### Connection Refused

**Check if running:**
```bash
curl http://localhost:9000/health
```

**Check binding:**
```bash
sudo ss -tlnp | grep 9000
```

**Check firewall:**
```bash
sudo ufw status
sudo iptables -L -n
```

### Authentication Failures

**Token expired:**
```bash
# Re-login
nexusctl login --server http://localhost:9000
```

**Wrong credentials:**
- Default: `admin` / `admin`
- Check if using correct server URL

### Database Migration

When upgrading NEXUS:
1. Create backup before upgrade
2. Stop service
3. Replace binary
4. Start service (auto-migration)

```bash
# Backup first!
nexusctl backup create --output ./backups

# Stop service
sudo systemctl stop nexus

# Replace binary
sudo cp new-nexus /opt/nexus/nexus

# Start service
sudo systemctl start nexus

# Verify
curl http://localhost:9000/health
```
