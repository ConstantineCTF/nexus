# NEXUS Architecture Documentation

System design, security model, and component overview for NEXUS.

---

## Table of Contents

- [System Design Overview](#system-design-overview)
- [Component Overview](#component-overview)
- [Security Model](#security-model)
- [Data Flows](#data-flows)
- [Storage Architecture](#storage-architecture)

---

## System Design Overview

NEXUS follows a client-server architecture with a clear separation between the CLI tool and the server.

```
┌─────────────────────────────────────────────────────────────────────┐
│                           NEXUS System                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌──────────────┐          HTTP/REST          ┌──────────────┐    │
│   │              │◄───────────────────────────►│              │    │
│   │   nexusctl   │         JSON + JWT          │    nexus     │    │
│   │   (CLI)      │                             │   (Server)   │    │
│   │              │                             │              │    │
│   └──────────────┘                             └──────┬───────┘    │
│                                                       │            │
│                                                       │            │
│                              ┌────────────────────────┼────────┐   │
│                              │                        │        │   │
│                              ▼                        ▼        │   │
│                        ┌──────────┐           ┌────────────┐   │   │
│                        │  SQLite  │           │  Keyring   │   │   │
│                        │ Database │           │ (./data/   │   │   │
│                        │          │           │   keys/)   │   │   │
│                        └──────────┘           └────────────┘   │   │
│                                                                │   │
│                        Storage Layer ──────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Security First** | Encryption at rest, JWT authentication, audit logging |
| **Simplicity** | Single binary deployment, SQLite storage |
| **Separation** | CLI and server are independent components |
| **Stateless API** | JWT tokens, no server-side sessions |
| **Auditability** | Every action logged with Ed25519 signatures |

---

## Component Overview

### CLI: nexusctl

The command-line interface for interacting with NEXUS.

```
nexusctl/
├── cmd/
│   ├── root.go        # Root command and global flags
│   ├── login.go       # Authentication commands
│   ├── secret.go      # Secret management
│   ├── backup.go      # Backup and restore
│   ├── export.go      # Export/import operations
│   ├── audit.go       # Audit log viewing
│   ├── apikey.go      # API key management
│   ├── health.go      # Health check
│   └── version.go     # Version information
└── config/
    └── config.go      # Configuration file handling
```

**Responsibilities:**
- User authentication and token management
- Secret CRUD operations via REST API
- Local backup/restore operations
- Configuration storage (`~/.nexus/config.yaml`)

**Key Libraries:**
- `spf13/cobra` - CLI framework
- `golang.org/x/term` - Terminal password input
- `golang.org/x/crypto/argon2` - Backup encryption

---

### Server: nexus

The core server providing the REST API and encryption services.

```
internal/
├── server/
│   ├── server.go      # HTTP server setup and routing
│   ├── handlers.go    # API endpoint handlers
│   ├── middleware.go  # Authentication middleware
│   └── types.go       # Request/response types
├── storage/
│   ├── storage.go     # Storage interface
│   ├── memory.go      # In-memory storage
│   └── sqlite.go      # SQLite storage
├── crypto/
│   ├── keyring.go     # Key management
│   ├── age.go         # Age encryption
│   ├── aes.go         # AES-256-GCM encryption
│   └── signing.go     # Ed25519 signing
└── auth/
    ├── jwt.go         # JWT token management
    └── apikey.go      # API key authentication
```

**Responsibilities:**
- REST API endpoints
- Secret encryption/decryption
- User authentication
- Audit logging
- Database operations

**Key Libraries:**
- `filippo.io/age` - Age encryption
- `crypto/aes` - AES-256-GCM
- `crypto/ed25519` - Audit log signing
- `mattn/go-sqlite3` - SQLite database

---

### SQLite Database

The persistent storage for secrets, versions, and audit logs.

**Schema:**

```sql
-- Secrets table
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    value BLOB NOT NULL,           -- AES-encrypted
    metadata TEXT,                  -- JSON
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP,
    created_by TEXT,
    updated_at TIMESTAMP,
    updated_by TEXT,
    deleted_at TIMESTAMP           -- Soft delete
);

-- Secret versions table
CREATE TABLE secret_versions (
    id TEXT PRIMARY KEY,
    secret_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    value BLOB NOT NULL,           -- AES-encrypted
    created_at TIMESTAMP,
    created_by TEXT,
    FOREIGN KEY (secret_id) REFERENCES secrets(id)
);

-- Audit logs table
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    action TEXT NOT NULL,
    user TEXT NOT NULL,
    secret_id TEXT,
    secret_path TEXT,
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN,
    error TEXT,
    metadata TEXT,                 -- JSON
    signature TEXT                 -- Ed25519 signature
);
```

---

### Keyring

The cryptographic key storage system.

```
./data/keys/
├── master.key      # AES-256 master key (encrypted with password)
├── signing.key     # Ed25519 private key for audit signing
├── verify.key      # Ed25519 public key for audit verification
└── age.key         # Age X25519 identity for secret encryption
```

**Key Types:**

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| Master Key | 256-bit random | AES-256-GCM encryption for secrets |
| Signing Key | Ed25519 private | Sign audit log entries |
| Verify Key | Ed25519 public | Verify audit log signatures |
| Age Identity | X25519 | Age encryption for additional layer |

**Key Storage Encryption:**

Keys are stored encrypted using Argon2id key derivation from `NEXUS_KEY_PASSWORD`:

```
[Salt: 16 bytes][AES-256-GCM encrypted key]
```

---

### REST API

All endpoints under `/api/v1/`:

```
Authentication:
  POST   /api/v1/auth/login      # Get JWT token
  POST   /api/v1/auth/refresh    # Refresh token

Secrets:
  GET    /api/v1/secrets         # List secrets
  POST   /api/v1/secrets         # Create secret
  GET    /api/v1/secrets/{path}  # Get secret
  PUT    /api/v1/secrets/{path}  # Update secret
  DELETE /api/v1/secrets/{path}  # Delete secret
  GET    /api/v1/secrets/{path}/versions  # Get versions

Audit:
  GET    /api/v1/audit           # List audit logs (admin only)

API Keys:
  GET    /api/v1/apikeys         # List API keys
  POST   /api/v1/apikeys         # Create API key
  DELETE /api/v1/apikeys         # Revoke API key

Health:
  GET    /health                 # Health check (no auth)
```

---

## Security Model

### Encryption Layers

NEXUS uses multiple layers of encryption:

```
┌─────────────────────────────────────────────────────────┐
│                    Security Layers                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Transport Layer (TLS - when behind reverse proxy)   │
│     └─► HTTPS encryption in transit                     │
│                                                         │
│  2. Application Layer (JWT)                             │
│     └─► Authenticated API access                        │
│                                                         │
│  3. Data Layer (AES-256-GCM)                           │
│     └─► Secrets encrypted before storage                │
│                                                         │
│  4. Key Layer (Age + Argon2id)                         │
│     └─► Encryption keys protected by password           │
│                                                         │
│  5. Audit Layer (Ed25519)                              │
│     └─► Tamper-proof audit log signatures               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  POST /api/v1/auth/login               │
     │  {username, password}                   │
     │────────────────────────────────────────►│
     │                                         │
     │         Verify credentials              │
     │         Generate JWT token              │
     │                                         │
     │  {token, expires_at, user}             │
     │◄────────────────────────────────────────│
     │                                         │
     │  GET /api/v1/secrets                   │
     │  Authorization: Bearer <token>          │
     │────────────────────────────────────────►│
     │                                         │
     │         Validate JWT signature          │
     │         Check token expiry              │
     │         Extract user ID and role        │
     │                                         │
     │  {secrets: [...]}                       │
     │◄────────────────────────────────────────│
     │                                         │
```

### JWT Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "admin-001",    // User ID
    "role": "admin",       // User role
    "exp": 1733356704,     // Expiry timestamp
    "iat": 1733270304      // Issued at timestamp
  }
}
```

### Role-Based Access Control

| Role | Secrets | Audit Logs | API Keys |
|------|---------|------------|----------|
| `admin` | Full access | Read access | Full access |
| `user` | Full access | No access | Own keys only |

---

## Data Flows

### Secret Storage Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────►│   API    │────►│ Encrypt  │────►│ Database │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     │  secret value  │                │                │
     │────────────────►                │                │
     │                │  validate      │                │
     │                │  request       │                │
     │                │────────────────►                │
     │                │                │  AES-256-GCM   │
     │                │                │  encrypt with  │
     │                │                │  master key    │
     │                │                │────────────────►
     │                │                │                │  store
     │                │                │                │  encrypted
     │                │                │                │  blob
     │  success       │                │                │
     │◄────────────────────────────────────────────────│
```

**Steps:**
1. Client sends secret value via API
2. Server validates JWT and request
3. Server encrypts value with AES-256-GCM using master key
4. Encrypted blob stored in SQLite
5. Version record created
6. Audit log entry created (signed)
7. Success response returned

### Secret Retrieval Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────►│   API    │────►│ Database │────►│ Decrypt  │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     │  GET secret    │                │                │
     │────────────────►                │                │
     │                │  validate JWT  │                │
     │                │────────────────►                │
     │                │                │  fetch blob    │
     │                │                │────────────────►
     │                │                │                │  AES-256-GCM
     │                │                │                │  decrypt with
     │                │                │                │  master key
     │  secret value  │◄────────────────────────────────│
     │◄────────────────                │                │
```

### Backup Flow

```
┌──────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│   CLI    │────►│  Tar/Gzip │────►│ Encrypt   │────►│   File    │
└──────────┘     └───────────┘     └───────────┘     └───────────┘
     │                │                 │                 │
     │  backup        │                 │                 │
     │  create        │                 │                 │
     │────────────────►                 │                 │
     │                │  bundle:        │                 │
     │                │  - nexus.db     │                 │
     │                │  - data/keys/   │                 │
     │                │─────────────────►                 │
     │                │                 │  Argon2id key   │
     │                │                 │  derivation     │
     │                │                 │  from password  │
     │                │                 │                 │
     │                │                 │  AES-256-GCM    │
     │                │                 │  encrypt        │
     │                │                 │─────────────────►
     │                │                 │                 │  write
     │  success       │                 │                 │  .tar.gz.enc
     │◄────────────────────────────────────────────────────
```

### Restore Flow

```
┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│   File    │────►│  Decrypt  │────►│  Untar    │────►│   Files   │
└───────────┘     └───────────┘     └───────────┘     └───────────┘
     │                 │                 │                 │
     │  read           │                 │                 │
     │  .tar.gz.enc    │                 │                 │
     │─────────────────►                 │                 │
     │                 │  Argon2id key   │                 │
     │                 │  derivation     │                 │
     │                 │  from password  │                 │
     │                 │                 │                 │
     │                 │  AES-256-GCM    │                 │
     │                 │  decrypt        │                 │
     │                 │─────────────────►                 │
     │                 │                 │  extract:       │
     │                 │                 │  - nexus.db     │
     │                 │                 │  - data/keys/   │
     │                 │                 │─────────────────►
     │                 │                 │                 │  overwrite
     │  success        │                 │                 │  existing
     │◄────────────────────────────────────────────────────
```

---

## Storage Architecture

### SQLite Configuration

```go
// Database initialization
db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")

// Write-Ahead Logging for better concurrency
// 5-second busy timeout for lock contention
```

### Data Organization

```
Working Directory/
├── nexus.db           # Main SQLite database
├── nexus.db-wal       # Write-Ahead Log (runtime)
├── nexus.db-shm       # Shared memory (runtime)
└── data/
    └── keys/
        ├── master.key     # Encrypted master key
        ├── signing.key    # Encrypted signing key
        ├── verify.key     # Encrypted verify key
        └── age.key        # Encrypted age identity
```

### Secret Value Encryption

```
┌─────────────────────────────────────────────────────────┐
│                  Encrypted Secret Value                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┬──────────┬─────────────────────────────┐  │
│  │  Nonce   │  Cipher  │         Auth Tag            │  │
│  │ 12 bytes │  text    │         16 bytes            │  │
│  └──────────┴──────────┴─────────────────────────────┘  │
│                                                         │
│  Algorithm: AES-256-GCM                                 │
│  Key: 32-byte master key from keyring                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Audit Log Signing

```
┌─────────────────────────────────────────────────────────┐
│                    Audit Log Entry                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Signed Data = action + userID + secretPath + timestamp │
│                                                         │
│  Signature = Ed25519.Sign(SigningKey, SignedData)       │
│                                                         │
│  Verification:                                          │
│  Ed25519.Verify(VerifyKey, SignedData, Signature)       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Performance Considerations

### SQLite Optimizations

- **WAL Mode**: Enables concurrent reads during writes
- **Busy Timeout**: 5 seconds to handle lock contention
- **Index on path**: Fast secret lookup by path

### Memory Management

- **Keyring in memory**: Keys loaded once at startup
- **Connection pooling**: Handled by sql.DB
- **Zero-copy encryption**: Direct byte slice operations

### Scalability Limits

| Metric | Recommended Limit |
|--------|-------------------|
| Secrets | < 100,000 |
| Secret size | < 1 MB |
| Concurrent users | < 100 |
| Database size | < 1 GB |

For larger deployments, consider:
- PostgreSQL backend (future feature)
- Multiple NEXUS instances with load balancing
- External key management (HSM)
