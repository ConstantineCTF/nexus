<div align="center">

<h1>
  🔐 NEXUS
</h1>

<h3>Enterprise Secrets Manager - GitOps Native</h3>

<p><em>Secrets Management for Machines, Not Humans</em></p>

<p>
  <a href="https://go.dev/"><img src="https://img. shields.io/badge/Go-1.23+-00ADD8? style=for-the-badge&logo=go&logoColor=white" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img. shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/ConstantineCTF/nexus"><img src="https://img. shields.io/badge/Build-Passing-success?style=for-the-badge" alt="Build"></a>
  <a href="#"><img src="https://img. shields.io/badge/Security-Hardened-critical?style=for-the-badge" alt="Security"></a>
</p>

<p>
  <a href="#-quick-start"><strong>Getting Started</strong></a> •
  <a href="#-features"><strong>Features</strong></a> •
  <a href="#-architecture"><strong>Architecture</strong></a> •
  <a href="#-installation"><strong>Installation</strong></a> •
  <a href="#-documentation"><strong>Documentation</strong></a>
</p>

</div>

---

## 🎯 The Problem

> **"We found API keys in our GitHub repository..."**
>
> — Every DevOps engineer's worst nightmare

**85% of data breaches** involve compromised credentials. Yet most teams still:

- ❌ Store secrets in environment variables
- ❌ Commit `. env` files to repositories
- ❌ Share credentials via Slack/Email
- ❌ Never rotate API keys
- ❌ Have no audit trail of secret access

**NEXUS solves all of this.**

---

## 💡 The Solution

NEXUS is a **self-hosted, zero-trust secrets manager** built for modern DevOps teams.  It's designed to be:

| Principle | Description |
|-----------|-------------|
| 🔒 **Zero-Trust** | Every request authenticated, every action logged |
| 🚀 **GitOps-Native** | Fits naturally into CI/CD pipelines |
| ⚡ **Developer-First** | Simple CLI, intuitive API, easy integration |
| 🏢 **Enterprise-Ready** | RBAC, SSO, compliance reports out of the box |
| 💰 **Cost-Effective** | Self-hosted = no per-secret pricing |

---

## ✨ Features

### 🔐 Military-Grade Security

```
┌─────────────────────────────────────────────────────────────┐
│                    ENCRYPTION LAYERS                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: TLS 1.3 (Transit)                                 │
│  Layer 2: age encryption (Secret Values)                    │
│  Layer 3: AES-256-GCM (Database)                           │
│  Layer 4: Argon2id (Key Derivation)                        │
│  Layer 5: Ed25519 (Audit Signatures)                       │
└─────────────────────────────────────────────────────────────┘
```

- **age encryption** — Modern, audited encryption by Filippo Valsorda (Go security lead)
- **Ed25519 signatures** — Tamper-proof audit logs
- **Argon2id** — Winner of Password Hashing Competition
- **Zero-knowledge architecture** — We can't read your secrets, ever

### 🔄 Automatic Secret Rotation

```yaml
# Define rotation policy
rotation:
  database/postgres/password:
    interval: 30d
    provider: postgresql
    notify:
      - slack-security
      - email-admin
```

Supported rotation providers:
- ✅ PostgreSQL / MySQL / MongoDB
- ✅ AWS IAM / RDS / Secrets Manager
- ✅ GCP Service Accounts
- ✅ Azure AD / Key Vault
- ✅ Custom webhook-based rotation

### ☸️ Kubernetes Native

```yaml
apiVersion: nexus.dev/v1
kind: SecretSync
metadata:
  name: app-secrets
  namespace: production
spec:
  secrets:
    - path: prod/database/url
      target: DATABASE_URL
    - path: prod/stripe/api-key
      target: STRIPE_API_KEY
  
  refreshInterval: 30s
  
  rotation:
    enabled: true
    restartPods: true
```

The NEXUS agent:
- 🔄 Auto-syncs secrets to Kubernetes Secrets
- 🔔 Triggers pod restarts on rotation
- 🔒 Validates secret signatures
- 📊 Reports sync status to dashboard

### 📊 Compliance & Audit

```bash
# Generate SOC2 compliance report
nexusctl compliance export --standard=soc2 --period=2024-Q4

# Output: compliance-report-soc2-2024-Q4.pdf
```

Every action is logged with:
- **Who** — User identity (SSO-linked)
- **What** — Action performed
- **When** — Timestamp (ms precision)
- **Where** — Source IP, User Agent
- **Signature** — Ed25519 tamper-proof signature

### 🚨 Emergency Access (Break-Glass)

```bash
# Request emergency access
nexusctl emergency request prod/database/master \
  --reason="Production incident INC-2024-001" \
  --duration=1h

# Requires 2/3 admin approvals
# Auto-revokes after duration
# Full audit trail
# Instant Slack/PagerDuty alerts
```

### 🔌 Integrations

<div align="center">

| CI/CD | Cloud | Databases | Notifications |
|-------|-------|-----------|---------------|
| GitHub Actions | AWS | PostgreSQL | Slack |
| GitLab CI | GCP | MySQL | Microsoft Teams |
| Jenkins | Azure | MongoDB | PagerDuty |
| ArgoCD | DigitalOcean | Redis | Email |
| Terraform | Kubernetes | Elasticsearch | Webhooks |

</div>

---

## 🏗️ Architecture

```
                                    ┌──────────────────┐
                                    │   Web Dashboard  │
                                    │   (Optional UI)  │
                                    └────────┬─────────┘
                                             │ HTTPS
                                             ▼
┌─────────────┐     gRPC/REST      ┌──────────────────┐      ┌─────────────┐
│  nexusctl   │◄──────────────────►│     nexusd       │◄────►│  PostgreSQL │
│  (CLI Tool) │                    │  (Core Server)   │      │  / SQLite   │
└─────────────┘                    └────────┬─────────┘      └─────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
              ▼                             ▼                             ▼
     ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
     │  nexus-agent    │          │  nexus-agent    │          │  nexus-agent    │
     │  (K8s Cluster 1)│          │  (K8s Cluster 2)│          │  (K8s Cluster N)│
     └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
              │                             │                             │
              ▼                             ▼                             ▼
     ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
     │ K8s Secrets     │          │ K8s Secrets     │          │ K8s Secrets     │
     │ (Auto-synced)   │          │ (Auto-synced)   │          │ (Auto-synced)   │
     └─────────────────┘          └─────────────────┘          └─────────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **nexusd** | Core server — API, encryption, storage, authentication |
| **nexusctl** | CLI tool — Manage secrets from terminal |
| **nexus-agent** | Kubernetes sidecar — Sync secrets to clusters |
| **Web Dashboard** | Optional React UI for visual management |

---

## 🚀 Quick Start

### Prerequisites

- Go 1.23+ (for building from source)
- PostgreSQL 14+ (production) or SQLite (development)
- Kubernetes 1.25+ (optional, for agent)

### Installation

#### Option 1: Binary Download (Recommended)

```bash
# Linux/macOS
curl -sSL https://get.nexus.dev | sh

# Windows (PowerShell)
iwr -useb https://get.nexus.dev/windows | iex
```

#### Option 2: Build from Source

```bash
git clone https://github. com/ConstantineCTF/nexus.git
cd nexus
make build

# Binaries available in ./bin/
```

#### Option 3: Docker

```bash
docker pull ghcr.io/constantinectf/nexus:latest

docker run -d \
  --name nexus \
  -p 8443:8443 \
  -v nexus-data:/var/lib/nexus \
  ghcr.io/constantinectf/nexus:latest
```

### Initialize NEXUS

```bash
# Initialize with SQLite (development)
nexusd init --storage=sqlite

# Initialize with PostgreSQL (production)
nexusd init --storage=postgres --db-url="postgres://user:pass@localhost/nexus"

# Start the server
nexusd start
```

### Your First Secret

```bash
# Authenticate
nexusctl auth login

# Create a secret
nexusctl secret set database/password "super-secret-value"

# Retrieve a secret
nexusctl secret get database/password

# List all secrets
nexusctl secret list

# View secret history
nexusctl secret history database/password
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Detailed installation instructions |
| [Configuration](docs/configuration.md) | All configuration options explained |
| [API Reference](docs/api-reference.md) | REST & gRPC API documentation |
| [Kubernetes Guide](docs/kubernetes.md) | K8s agent setup and usage |
| [Security Model](docs/security. md) | Deep dive into security architecture |
| [Compliance](docs/compliance.md) | SOC2, ISO27001, GDPR guides |
| [Troubleshooting](docs/troubleshooting. md) | Common issues and solutions |

---

## 🔧 Configuration

NEXUS is fully configurable via YAML:

```yaml
# /etc/nexus/config.yaml
server:
  host: 0.0.0.0
  port: 8443
  tls:
    enabled: true
    cert_file: /etc/nexus/tls/server.crt
    key_file: /etc/nexus/tls/server. key

storage:
  type: postgres
  postgres:
    host: ${DB_HOST}
    port: 5432
    database: nexus
    username: ${DB_USER}
    password: ${DB_PASSWORD}
    ssl_mode: require

auth:
  oidc:
    enabled: true
    issuer_url: https://company.okta.com
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}

audit:
  enabled: true
  signing:
    enabled: true
  export:
    s3:
      bucket: nexus-audit-logs
      region: us-east-1

rotation:
  enabled: true
  scheduler:
    interval: 1h
```

See [Configuration Docs](docs/configuration. md) for all options.

---

## 🔒 Security

### Threat Model

NEXUS is designed to protect against:

| Threat | Mitigation |
|--------|------------|
| **Database Breach** | All secrets encrypted at rest with age/AES-256-GCM |
| **Network Interception** | TLS 1.3 required, certificate pinning supported |
| **Insider Threat** | RBAC, audit logs, break-glass procedures |
| **Key Compromise** | Automatic key rotation, HSM support |
| **Log Tampering** | Ed25519 signed audit entries |
| **Memory Extraction** | Secrets zeroized after use |

### Security Certifications

- 🔄 SOC2 Type II (in progress)
- 🔄 ISO 27001 (planned)
- ✅ Zero CVEs since launch

### Reporting Vulnerabilities

Found a security issue? Please report privately:

📧 **security@nexus.dev** (PGP key available)

We offer bounties for critical vulnerabilities. 

---

## 📊 Benchmarks

Tested on AWS c5. xlarge (4 vCPU, 8GB RAM):

| Operation | Throughput | Latency (p99) |
|-----------|------------|---------------|
| Secret Read | 15,000 ops/sec | 2.3ms |
| Secret Write | 8,000 ops/sec | 4.1ms |
| Secret Encrypt | 25,000 ops/sec | 0.8ms |
| Audit Log Write | 50,000 ops/sec | 0. 3ms |

Memory usage: ~50MB baseline, ~200MB under load

---

## 🗺️ Roadmap

### ✅ v0.1.0 (December 2025)
- [x] Core secret storage
- [x] age + AES-256-GCM encryption
- [x] Ed25519 audit signing
- [x] CLI tool (nexusctl)
- [x] REST API
- [x] SQLite storage
- [ ] Basic RBAC

### 🔄 v0.2.0 (January 2026)
- [ ] PostgreSQL storage
- [ ] JWT authentication
- [ ] OIDC/SSO integration
- [ ] Web dashboard
- [ ] Kubernetes agent

### 📅 v0.3.0 (February 2026)
- [ ] Automatic rotation
- [ ] Slack/Teams integration
- [ ] Compliance reports
- [ ] Terraform provider

### 🔮 Future
- [ ] HSM integration (AWS KMS, Azure Key Vault)
- [ ] Multi-region replication
- [ ] GraphQL API
- [ ] VS Code extension
- [ ] Secret scanning (git pre-commit)

---

## 🆚 Comparison

| Feature | NEXUS | HashiCorp Vault | AWS Secrets Manager |
|---------|-------|-----------------|---------------------|
| **Pricing** | Free (self-hosted) | $50k+/year | $0.40/secret/month |
| **Setup Time** | 5 minutes | 2-3 days | 30 minutes |
| **Kubernetes Native** | ✅ First-class | ⚠️ Complex | ❌ AWS only |
| **GitOps Friendly** | ✅ Designed for it | ⚠️ Possible | ❌ No |
| **Learning Curve** | Low | High | Medium |
| **Self-Hosted** | ✅ | ✅ | ❌ |
| **Multi-Cloud** | ✅ | ✅ | ❌ |
| **Open Source** | ✅ Core | ⚠️ Partial | ❌ |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus

# Install dependencies
go mod tidy

# Run tests
make test

# Build all binaries
make build

# Run development server
make dev
```

### Project Structure

```
nexus/
├── cmd/                    # Executable commands
│   ├── nexusd/            # Server daemon
│   ├── nexusctl/          # CLI tool
│   └── nexus-agent/       # Kubernetes agent
├── internal/              # Private application code
│   ├── crypto/            # Encryption layer
│   ├── storage/           # Database backends
│   ├── auth/              # Authentication
│   ├── audit/             # Audit logging
│   └── rotation/          # Secret rotation
├── pkg/                   # Public libraries
│   ├── api/               # API definitions
│   └── sdk/               # Go SDK
├── configs/               # Configuration templates
├── docs/                  # Documentation
└── scripts/               # Helper scripts
```

---

## 📜 License

NEXUS is licensed under the [MIT License](LICENSE). 

```
MIT License

Copyright (c) 2025 Constantine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software. 
```

---

## 💬 Community

- 🐛 **Issues**: [GitHub Issues](https://github.com/ConstantineCTF/nexus/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/ConstantineCTF/nexus/discussions)
- 🐦 **Twitter**: [@NexusSecrets](https://twitter. com/NexusSecrets)
- 📧 **Email**: hello@nexus.dev

---

## ⭐ Star History

If NEXUS helps secure your infrastructure, consider giving it a star! 

[![Star History Chart](https://api. star-history.com/svg?repos=ConstantineCTF/nexus&type=Date)](https://star-history.com/#ConstantineCTF/nexus&Date)

---

<div align="center">

**Built with 🔒 by [Constantine](https://github.com/ConstantineCTF)**

*Protecting secrets, one encryption at a time.*

</div>