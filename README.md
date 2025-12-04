<div align="center">

# NEXUS

### Enterprise-Grade Secrets Management for Production Systems

**Secure • Versioned • Encrypted • Production-Ready**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge)](https://github.com/ConstantineCTF/nexus)

[**Get Started Free**](#-quickstart) • [**Pricing**](#-pricing) • [**Features**](#-features) • [**Documentation**](docs/) • [**Enterprise Support**](#-enterprise-support)

</div>

---

## 🎯 What is NEXUS?

**NEXUS** is an **enterprise-grade secret management system** trusted by companies to secure API keys, database passwords, certificates, and sensitive data with military-grade encryption, full audit trails, and disaster recovery. 

Unlike complex solutions like HashiCorp Vault, NEXUS delivers **enterprise security with startup simplicity** - deploy in minutes, not weeks. 

### 🚀 Why Enterprises Choose NEXUS

| Enterprise Challenge | NEXUS Solution |
|---------------------|----------------|
| **Compliance requirements (SOC 2, ISO 27001)** | Full audit logs with tamper-proof Ed25519 signatures |
| **Credential leaks & breaches** | Age encryption + AES-256-GCM, zero plaintext storage |
| **Complex onboarding (weeks of setup)** | Deploy in 5 minutes with single binary |
|  **High licensing costs ($50K+/year)** | Start free, scale with transparent pricing |
| **Vendor lock-in** | Open-source core, self-hosted, own your data |
| **Lost credentials after rotation** | Complete version history for compliance |

---

## ✨ Features

###  **Enterprise Security**

- ✅ **Age Encryption** - Modern cryptography by [Filippo Valsorda](https://github.com/FiloSottile/age)
- ✅ **AES-256-GCM** - Military-grade backup encryption
- ✅ **Argon2id Key Derivation** - OWASP-recommended password hashing
- ✅ **Ed25519 Signatures** - Tamper-proof audit logs for compliance
- ✅ **JWT Authentication** - Industry-standard token security
- ✅ **Zero-Knowledge Architecture** - We never see your secrets

###  **Compliance & Auditing**

- ✅ **Complete audit trail** - Every action logged with timestamps
- ✅ **Immutable logs** - Ed25519 signatures prevent tampering
- ✅ **Version history** - Track every change for SOC 2 compliance
- ✅ **RBAC support** - Role-based access control (Enterprise)
- ✅ **Compliance reports** - Pre-built reports for auditors (Enterprise)

###  **Disaster Recovery**

- ✅ **One-command backups** - `nexusctl backup create`
- ✅ **Encrypted archives** - AES-256-GCM + password protection
- ✅ **Tested in production** - Proven restore process
- ✅ **Point-in-time recovery** - Restore to any backup
- ✅ **Export to JSON** - Migrate between environments

### 🛠 **Developer Experience**

- ✅ **Beautiful CLI** - Intuitive commands, colored output
- ✅ **Full REST API** - Automate with any language
- ✅ **Go SDK included** - Official client library
- ✅ **Docker support** - Deploy anywhere
- ✅ **Single binary** - No dependencies, no complexity

---

## 💰 Pricing

<table>
<tr>
<td width="25%" align="center">

### Community
**FREE**

Perfect for startups & OSS

- ✅ All core features
- ✅ Unlimited secrets
- ✅ Self-hosted
- ✅ Community support
- ✅ MIT License

<br>

**[Get Started →](#-quickstart)**

</td>
<td width="25%" align="center">

### Pro
**$49/month**

For small teams

- ✅ Everything in Community
- ✅ **Email support** (48h SLA)
- ✅ Up to 10 users
- ✅ Deployment guides
- ✅ Priority bug fixes

<br>

**[Contact Sales →](#-enterprise-support)**

</td>
<td width="25%" align="center">

### Business
**$199/month**

For growing companies

- ✅ Everything in Pro
- ✅ **Priority support** (24h SLA)
- ✅ Up to 50 users
- ✅ LDAP/SSO integration*
- ✅ Compliance reports
- ✅ Security reviews

<br>

**[Contact Sales →](#-enterprise-support)**

</td>
<td width="25%" align="center">

### Enterprise
**Custom Pricing**

For large organizations

- ✅ Everything in Business
- ✅ **24/7 support** (1h SLA)
- ✅ Unlimited users
- ✅ Custom integrations
- ✅ On-premise deployment
- ✅ Dedicated engineer
- ✅ Custom SLA

<br>

**[Contact Sales →](#-enterprise-support)**

</td>
</tr>
</table>

<div align="center">

**All plans include: Encryption, Backups, Audit Logs, CLI & API**

*_Coming soon features marked with asterisk_

</div>

---

## 📦 Installation

### Quick Start (5 minutes)

```bash
# Download latest release
# (Coming soon: Pre-built binaries)

# Or build from source
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus
go build -o nexus.exe ./cmd/nexus
go build -o nexusctl.exe ./cmd/nexusctl

# Start server
./nexus -addr :9000 -storage sqlite -db ./nexus.db

# Login and create first secret
./nexusctl login --server http://localhost:9000
./nexusctl secret create prod/api/key "my-secret-value"
```

---

## 🚀 Quickstart

### 1️⃣ Start the Server

```bash
# Production-ready SQLite storage
./nexus -addr :9000 -storage sqlite -db ./nexus.db
```

**Output:**
```
2025/12/04 01:00:00 ✓ Loaded existing keyring from ./data/keys
2025/12/04 01:00:00 Using SQLite storage: ./nexus.db
2025/12/04 01:00:00 Starting NEXUS server on :9000
```

### 2️⃣ Login from CLI

```bash
nexusctl login --server http://localhost:9000
```

**Prompt:**
```
Username: admin
Password: ****
✓ Logged in successfully as Admin User (admin-001)
```

### 3️⃣ Create Your First Secret

```bash
# Store a database password
nexusctl secret create prod/database/password "super-secret-db-pass"
```

**Output:**
```
✓ Secret created: prod/database/password (version 1)
```

### 4️⃣ Retrieve the Secret

```bash
nexusctl secret get prod/database/password
```

**Output:**
```
super-secret-db-pass
```

### 5️⃣ Create an Encrypted Backup

```bash
nexusctl backup create --output ./backups
```

**Output:**
```
Enter backup password: ********
Confirm backup password: ********
✓ Backup created: backups/nexus-backup-2025-12-04-011500.tar.gz. enc
```

**Full documentation:** [**Quickstart Guide →**](docs/DEPLOYMENT.md)

---

## 📖 CLI Reference

### Authentication

```bash
nexusctl login --server http://localhost:9000
nexusctl whoami
nexusctl logout
```

### 🗂Secret Management

```bash
# Create, get, update, delete secrets
nexusctl secret create <path> <value>
nexusctl secret get <path>
nexusctl secret update <path> <new-value>
nexusctl secret delete <path>

# List and search
nexusctl secret list
nexusctl secret list --prefix prod/

# Version history
nexusctl secret versions <path>
```

### Backup & Recovery

```bash
# Create encrypted backup
nexusctl backup create --output ./backups

# Restore from backup
nexusctl backup restore --file <backup-file>

# Export to JSON
nexusctl export --output secrets.json

# Import from JSON
nexusctl import --file secrets.json --overwrite
```

### Audit & Monitoring

```bash
# View audit logs (admin only)
nexusctl audit list --limit 100

# Health check
nexusctl health

# Version info
nexusctl version
```

**Full CLI documentation:** [**CLI Reference →**](docs/API.md)

---

## 🌐 REST API

Full API documentation: **[docs/API.md](docs/API.md)**

### Authentication

```bash
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### Create a Secret

```bash
curl -X POST http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"path":"prod/api/key","value":"secret-value"}'
```

---

## 🏗️ Architecture

```
┌─────────────────┐
│   Enterprise    │
│     Client      │
└────────┬────────┘
         │ HTTPS + JWT
         ▼
┌─────────────────┐
│  NEXUS Server   │
│   (Go Binary)   │
├─────────────────┤
│ Authentication  │ ◄── JWT + API Keys + RBAC
│   Middleware    │
├─────────────────┤
│ Secret Handlers │ ◄── CRUD + Versioning
├─────────────────┤
│ Audit Logger    │ ◄── Ed25519 Signatures
├─────────────────┤
│ SQLite Storage  │ ◄── Age Encrypted Secrets
│   + Keyring     │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Encrypted       │
│ Backups         │ ◄── AES-256-GCM + Argon2id
│ (Disaster       │
│  Recovery)      │
└─────────────────┘
```

**Read more:** [**Architecture Guide →**](docs/ARCHITECTURE.md)

---

## 🔒 Security & Compliance

### Encryption Standards

| Layer | Technology | Standard |
|-------|-----------|----------|
| **Secrets at Rest** | Age Encryption | X25519 + ChaCha20-Poly1305 |
| **Backup Archives** | AES-256-GCM | NIST FIPS 140-2 |
| **Key Derivation** | Argon2id | OWASP Recommended |
| **Audit Signatures** | Ed25519 | RFC 8032 |
| **API Auth** | JWT | RFC 7519 |

### Compliance Support

✅ **SOC 2 Type II** - Audit logs + access controls  
✅ **ISO 27001** - Security best practices  
✅ **GDPR** - Self-hosted, data sovereignty  
✅ **HIPAA** - Encryption at rest + in transit  

**Enterprise customers:** Compliance reports available on request. 

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **[Quickstart Guide](docs/DEPLOYMENT.md)** | Get started in 5 minutes |
| **[API Reference](docs/API.md)** | Complete REST API documentation |
| **[Backup & Recovery](docs/BACKUP.md)** | Disaster recovery workflows |
| **[Architecture](docs/ARCHITECTURE.md)** | System design & security model |
| **[Deployment Guide](docs/DEPLOYMENT.md)** | Production deployment (Docker, Linux, Windows) |

---

## 💼 Enterprise Support

### Get Professional Support

**For businesses that need guaranteed uptime and expert assistance.**

#### What's Included:

✅ **Priority Email Support** - 24-48h response time (Pro), 1-24h (Business/Enterprise)  
✅ **Deployment Assistance** - Help with production setup  
✅ **Security Reviews** - Annual security audits  
✅ **Custom Integrations** - LDAP, SSO, custom auth  
✅ **SLA Guarantees** - Contractual uptime commitments  
✅ **Dedicated Engineer** - (Enterprise only) Direct Slack/Teams access  

---

### 📧 Contact Sales

**Ready to secure your enterprise secrets?**

📩 **Email:** [constantine.ctf@proton.me](mailto:constantine.ctf@proton.me)

**Include in your message:**
- Company name & size
- Current secret management solution
- Compliance requirements (SOC 2, ISO, HIPAA, etc.)
- Preferred deployment method (cloud/on-premise)
- Expected number of users

**We typically respond within 24 hours.**

---

## 🤝 Contributing

**Community contributions are welcome!**

The Community Edition (MIT License) is open source.  We accept:

- 🐛 Bug fixes
- 📖 Documentation improvements
- ✨ Feature requests (via GitHub Issues)
- 🔧 Performance optimizations

```bash
# Development setup
git clone https://github.com/ConstantineCTF/nexus.git
cd nexus
go mod tidy
go test ./... 
make build
```

**For enterprise feature development**, please contact us first.

---

## 📜 License

- **Community Edition:** [MIT License](LICENSE) - Free for personal and commercial use
- **Enterprise Edition:** Commercial license with SLA and support

See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **[age](https://github.com/FiloSottile/age)** - Modern encryption by Filippo Valsorda
- **[Cobra](https://github.com/spf13/cobra)** - CLI framework
- **[SQLite](https://www.sqlite.org/)** - Embedded database

---

## 💬 Support & Community

### Community Support (Free)

- **GitHub Issues:** [Report bugs](https://github.com/ConstantineCTF/nexus/issues)
- **GitHub Discussions:** [Ask questions](https://github.com/ConstantineCTF/nexus/discussions)
- **Documentation:** [Read the docs](docs/)

### Enterprise Support (Paid)

- **Email:** [constantine.ctf@proton.me](mailto:constantine.ctf@proton.me)
- **Priority Support:** Pro, Business, Enterprise customers
- **SLA:** 1-48h response time (depending on plan)

---

<div align="center">

**Built with ❤️ by [ConstantineCTF](https://github.com/ConstantineCTF)**

⭐ **Star this repo** if you find it useful!

**[Get Started Free](#-quickstart)** • **[View Pricing](#-pricing)** • **[Contact Sales](mailto:constantine.ctf@proton.me)**

</div>
