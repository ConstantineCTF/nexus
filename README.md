# NEXUS 🔐

**Enterprise Secrets Manager - GitOps Native**

> Secrets Management for Machines, Not Humans

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Go Version](https://img.shields.io/badge/go-1.23-blue)
![License](https://img.shields. io/badge/license-MIT-green)

---

## 🚀 What is NEXUS? 

NEXUS is a modern, self-hosted secrets management platform designed for DevOps teams. Built with security-first principles and zero-trust architecture. 

### ✨ Key Features

- 🔒 **Military-grade encryption** - AES-256-GCM + age encryption
- 🔄 **Automatic secret rotation** - AWS, PostgreSQL, MySQL support
- ☸️ **Kubernetes native** - Sidecar agent with auto-sync
- 📊 **Compliance ready** - SOC2/ISO27001 audit trails
- 🎯 **Configuration-driven** - Adapts to any infrastructure
- 🆓 **Zero vendor lock-in** - Self-hosted, open-core

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   nexusctl  │─────▶│   nexusd     │◀─────│ nexus-agent │
│  (CLI Tool) │      │   (Server)   │      │ (K8s Sidecar)│
└─────────────┘      └──────┬───────┘      └─────────────┘
                            │
                     ┌──────▼───────┐
                     │  SQLite/     │
                     │  PostgreSQL  │
                     └──────────────┘
```

---

## 🛠️ Tech Stack

- **Language**: Go 1.23+
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Crypto**: filippo.io/age + Ed25519
- **API**: gRPC + REST
- **Deployment**: Single binary / Docker / Kubernetes

---

## 📦 Quick Start

```bash
# Install (coming soon)
curl -sSL https://get.nexus.dev | sh

# Initialize
nexusd init

# Start server
nexusd start

# Create a secret
nexusctl secret set database/password "super-secret"

# Retrieve a secret
nexusctl secret get database/password
```

---

## 🗓️ Development Roadmap

### Week 1: Foundation ✅
- [x] Project architecture
- [x] Configuration system
- [ ] Crypto layer
- [ ] Storage layer

### Week 2: Core Features
- [ ] gRPC API
- [ ] JWT authentication
- [ ] Audit logging
- [ ] CLI tool

### Week 3: Kubernetes
- [ ] nexus-agent (sidecar)
- [ ] Secret rotation engine
- [ ] K8s operator

### Week 4: Polish
- [ ] Documentation
- [ ] Docker images
- [ ] Release v0.1.0

---

## 🤝 Contributing

This project is currently under active development. Stay tuned for contribution guidelines!

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 👨‍💻 Author

**Constantine** ([@ConstantineCTF](https://github.com/ConstantineCTF))

*Building the future of secrets management, one commit at a time. * 🚀

---

## ⭐ Star This Repo!

If you find NEXUS interesting, give it a star to follow the development journey! 
