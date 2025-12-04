<div align="center">

<h1>🔐 NEXUS</h1>

<h3>Production-Ready Secrets Management System</h3>

<p><em>Secure. Versioned. Encrypted.</em></p>

<p>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge" alt="Status"></a>
</p>

<p>
  <a href="#-quickstart"><strong>Quickstart</strong></a> •
  <a href="#-features"><strong>Features</strong></a> •
  <a href="#-cli-reference"><strong>CLI Reference</strong></a> •
  <a href="#-api-overview"><strong>API</strong></a> •
  <a href="docs/"><strong>Documentation</strong></a>
</p>

</div>

---

## 📖 Overview

NEXUS is a **production-ready secret management system** with encryption, versioning, and backup capabilities. It provides a secure way to store, manage, and access sensitive data like API keys, database credentials, and configuration secrets.

### Why NEXUS?

- **Security First**: Age encryption + AES-256-GCM for secrets at rest
- **Full Versioning**: Track every change to your secrets with version history
- **Encrypted Backups**: Backup and restore your entire vault with password protection
- **Simple CLI**: Intuitive command-line interface for all operations
- **REST API**: Full-featured API for programmatic access
- **Audit Logging**: Every action is logged with Ed25519 signatures for tamper-proof records
- **JWT Authentication**: Secure token-based authentication

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Secret Management** | Create, read, update, delete, and list secrets with hierarchical paths |
| 📜 **Version History** | Track all changes with full version history for each secret |
| 💾 **Backup/Restore** | Encrypted backup archives with AES-256-GCM and Argon2id key derivation |
| 📤 **Export/Import** | Export secrets to JSON and import them back |
| 🔑 **Age Encryption** | Modern encryption using age (by Filippo Valsorda) |
| 🛡️ **AES-256-GCM** | Additional encryption layer for backup files |
| 🖥️ **CLI & Server** | Separate CLI tool (`nexusctl`) and server (`nexus`) |
| 📝 **Audit Logging** | Every action logged with timestamps and Ed25519 signatures |
| 🎫 **JWT Authentication** | Secure token-based authentication with configurable expiry |
| 🔑 **API Keys** | Generate API keys for programmatic access |

---

## 🚀 Quickstart

### Prerequisites

- **Go 1.23+** (for building from source)
- **SQLite** (included, no setup required)

### Installation

#### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus

# Build binaries
make build

# Binaries are now in ./bin/
# - nexus (server)
# - nexusctl (CLI)
```

#### Option 2: Go Install

```bash
go install github.com/ConstantineCTF/nexus/cmd/nexus@latest
go install github.com/ConstantineCTF/nexus/cmd/nexusctl@latest
```

### Start the Server

```bash
# Start with SQLite storage (default)
./nexus -addr :9000 -storage sqlite -db ./nexus.db

# Output:
# ✓ Loaded existing keyring from ./data/keys
# Using SQLite storage: ./nexus.db
# Starting NEXUS server on :9000
```

### Login and Create Your First Secret

```bash
# Login to the server
nexusctl login --server http://localhost:9000
# Username: admin
# Password: admin

# Create a secret
nexusctl secret create prod/database/password "super-secret-password"
# ✓ Secret created: prod/database/password (version 1)

# Retrieve the secret
nexusctl secret get prod/database/password
# super-secret-password

# List all secrets
nexusctl secret list
# PATH                        VERSION  CREATED              CREATED BY
# prod/database/password      1        2025-12-04 00:15:00  admin-001
```

### Backup Your Vault

```bash
# Create an encrypted backup
nexusctl backup create --output ./backups
# Enter backup password: ********
# Confirm backup password: ********
# ✓ Backup created: ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc

# Restore from backup (server must be stopped)
nexusctl backup restore --file ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc
# Enter backup password: ********
# ✓ Restored successfully. Restart the server.
```

---

## ⚙️ Configuration

### Server Configuration

The server accepts command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:9000` | Server listen address |
| `-storage` | `memory` | Storage backend: `memory` or `sqlite` |
| `-db` | `./nexus.db` | SQLite database path (when storage=sqlite) |

**Environment Variables:**

| Variable | Description |
|----------|-------------|
| `NEXUS_KEY_PASSWORD` | Password for keyring encryption (default: `changeme-in-production`) |

### CLI Configuration

The CLI stores configuration in `~/.nexus/config.yaml`:

```yaml
server: http://localhost:9000
token: eyJhbGciOiJIUzI1NiIs...
user:
  id: admin-001
  name: Admin User
  role: admin
```

### Storage Configuration

**SQLite (Recommended for Production):**
```bash
./nexus -storage sqlite -db /var/lib/nexus/nexus.db
```

**In-Memory (Development Only):**
```bash
./nexus -storage memory
# WARNING: All data lost on restart!
```

---

## 📋 CLI Reference

### Authentication Commands

```bash
# Login to server
nexusctl login --server http://localhost:9000

# Check current user
nexusctl whoami

# Logout
nexusctl logout
```

### Secret Management

```bash
# Create a secret
nexusctl secret create <path> <value>
nexusctl secret create prod/api/key "my-api-key" --description "Production API key"

# Get a secret value
nexusctl secret get <path>

# Update a secret
nexusctl secret update <path> <new-value>

# Delete a secret
nexusctl secret delete <path>

# List all secrets
nexusctl secret list
nexusctl secret list --prefix prod/

# View version history
nexusctl secret versions <path>
```

### Backup & Restore

```bash
# Create encrypted backup
nexusctl backup create --output <directory>

# Restore from backup (stop server first!)
nexusctl backup restore --file <backup-file>
```

### Export & Import

```bash
# Export secrets to JSON
nexusctl export --output secrets.json

# Import secrets from JSON
nexusctl import --file secrets.json
nexusctl import --file secrets.json --overwrite  # Update existing
```

### API Keys

```bash
# Create an API key
nexusctl apikey create "CI/CD Pipeline"
nexusctl apikey create "Service Account" --expires 720h

# List API keys
nexusctl apikey list

# Revoke an API key
nexusctl apikey revoke <key-id>
```

### Audit & Health

```bash
# View audit logs (admin only)
nexusctl audit list
nexusctl audit list --limit 50

# Check server health
nexusctl health

# Show version info
nexusctl version
```

### Output Formats

```bash
# Table format (default)
nexusctl secret list

# JSON format
nexusctl secret list -o json

# YAML format
nexusctl secret list -o yaml
```

---

## 🌐 API Overview

NEXUS provides a REST API for programmatic access. Full documentation: [docs/API.md](docs/API.md)

### Base URL

```
http://localhost:9000/api/v1
```

### Authentication

```bash
# Login and get token
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Use token in subsequent requests
curl http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer <token>"
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | Authenticate and get JWT token |
| `POST` | `/api/v1/auth/refresh` | Refresh authentication token |
| `GET` | `/api/v1/secrets` | List all secrets |
| `POST` | `/api/v1/secrets` | Create a new secret |
| `GET` | `/api/v1/secrets/{path}` | Get a secret by path |
| `PUT` | `/api/v1/secrets/{path}` | Update a secret |
| `DELETE` | `/api/v1/secrets/{path}` | Delete a secret |
| `GET` | `/api/v1/secrets/{path}/versions` | Get secret version history |
| `GET` | `/api/v1/audit` | List audit logs (admin only) |
| `GET/POST/DELETE` | `/api/v1/apikeys` | Manage API keys |
| `GET` | `/health` | Health check (no auth required) |

---

## 🔒 Best Practices

### Security Recommendations

1. **Change Default Credentials**: Never use `admin/admin` in production
2. **Set Strong Keyring Password**: Use `NEXUS_KEY_PASSWORD` environment variable
3. **Use HTTPS**: Deploy behind a reverse proxy with TLS
4. **Rotate Backup Passwords**: Use different passwords for each backup
5. **Restrict Network Access**: Use firewall rules to limit API access
6. **Monitor Audit Logs**: Regularly review audit logs for suspicious activity

### Deployment Recommendations

1. **Use SQLite Storage**: More reliable than in-memory storage
2. **Regular Backups**: Schedule daily encrypted backups
3. **Backup Rotation**: Keep last 30 days of backups
4. **Test Restores**: Regularly test backup restoration process
5. **Secure File Permissions**: Restrict access to database and key files

### Key Rotation

```bash
# The keyring is automatically created on first run
# To rotate keys, delete the keyring and restart:
rm -rf ./data/keys
./nexus -storage sqlite -db ./nexus.db
# WARNING: Existing secrets will become unreadable!
# Always backup before key rotation
```

---

## 🔧 Troubleshooting

### Common Errors

#### Connection Refused

```
Error: connection refused
```

**Solution**: Ensure the server is running and accessible:
```bash
# Check if server is running
curl http://localhost:9000/health

# Start the server
./nexus -addr :9000 -storage sqlite
```

#### Authentication Failed

```
Error: invalid credentials
```

**Solution**: Verify username and password, or re-login:
```bash
nexusctl login --server http://localhost:9000
```

#### Database Locked

```
Error: database is locked
```

**Solution**: Ensure only one server instance is running:
```bash
# Find and stop other instances
ps aux | grep nexus
kill <pid>
```

#### Decryption Failed

```
Error: failed to decrypt (wrong password?)
```

**Solution**: Verify the keyring password or backup password is correct.

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete REST API documentation |
| [Backup Guide](docs/BACKUP.md) | Backup, restore, export, and import guide |
| [Architecture](docs/ARCHITECTURE.md) | System design and security model |
| [Deployment](docs/DEPLOYMENT.md) | Production deployment guide |

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus
go mod tidy
make test
make build
```

---

## 📜 License

NEXUS is licensed under the [MIT License](LICENSE).
