# NEXUS Backup and Restore Guide

This guide covers backup, restore, export, and import operations for NEXUS.

---

## Table of Contents

- [Overview](#overview)
- [Encrypted Backups](#encrypted-backups)
  - [How Backups Work](#how-backups-work)
  - [Creating a Backup](#creating-a-backup)
  - [Restoring from Backup](#restoring-from-backup)
- [Export and Import](#export-and-import)
  - [Export Workflow](#export-workflow)
  - [Import Workflow](#import-workflow)
- [Best Practices](#best-practices)
- [Known Issues](#known-issues)

---

## Overview

NEXUS provides two mechanisms for data portability:

| Feature | Purpose | Encryption | Includes |
|---------|---------|------------|----------|
| **Backup/Restore** | Full disaster recovery | AES-256-GCM | Database + Keyring |
| **Export/Import** | Data migration | None (plaintext JSON) | Secrets only |

### When to Use Each

- **Backup**: Disaster recovery, server migration, preserving encryption keys
- **Export**: Moving secrets between NEXUS instances, data inspection

---

## Encrypted Backups

### How Backups Work

NEXUS backups are encrypted archives containing:

1. **nexus.db** - SQLite database with all secrets (encrypted at rest)
2. **data/keys/** - Encryption keyring (Age keys, master key, signing keys)

#### Encryption Details

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Derivation | **Argon2id** | Derive encryption key from password |
| Encryption | **AES-256-GCM** | Encrypt backup archive |
| Compression | **gzip** | Compress data before encryption |
| Archive | **tar** | Bundle files into single archive |

#### Argon2id Parameters

```
Time:    1 iteration
Memory:  64 MB
Threads: 4
Key:     32 bytes (256 bits)
Salt:    16 bytes (random)
```

#### Backup File Format

```
[Salt: 16 bytes][Nonce: 12 bytes][Encrypted tar.gz + GCM tag]
```

File extension: `.tar.gz.enc`

---

### Creating a Backup

#### Step-by-Step

1. **Open a terminal** in the directory containing your NEXUS data

2. **Run the backup command:**
   ```bash
   nexusctl backup create --output ./backups
   ```

3. **Enter a strong backup password when prompted:**
   ```
   Enter backup password: ********
   Confirm backup password: ********
   ```
   
   > ⚠️ **Important:** Remember this password! Without it, you cannot restore the backup.

4. **Wait for completion:**
   ```
   Creating backup archive...
   Encrypting backup...
   ✓ Backup created: ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc
   ```

#### Command Reference

```bash
nexusctl backup create [flags]

Flags:
  -o, --output string   Output directory for the backup file (default ".")
  -h, --help            Help for backup create
```

#### Example Output

```bash
$ nexusctl backup create --output ./backups
Enter backup password: 
Confirm backup password: 
Creating backup archive...
Encrypting backup...
✓ Backup created: ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc
```

#### What Gets Backed Up

| Path | Description |
|------|-------------|
| `./nexus.db` | SQLite database with encrypted secrets |
| `./data/keys/master.key` | Master encryption key (encrypted) |
| `./data/keys/signing.key` | Ed25519 signing key for audit logs |
| `./data/keys/verify.key` | Ed25519 verify key |
| `./data/keys/age.key` | Age encryption identity |

---

### Restoring from Backup

#### Prerequisites

⚠️ **The NEXUS server MUST be stopped before restoring.**

```bash
# Stop the server (Ctrl+C or kill the process)
# Verify it's stopped
curl http://localhost:9000/health
# Should return "connection refused"
```

#### Step-by-Step

1. **Stop the NEXUS server**

2. **Run the restore command:**
   ```bash
   nexusctl backup restore --file ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc
   ```

3. **Enter the backup password:**
   ```
   ⚠ Server must be stopped before restore
   Enter backup password: ********
   ```

4. **Review the files to be restored:**
   ```
   Decrypting backup...
   Extracting backup...
   
   Files in backup:
     nexus.db (1.2MB)
     data/keys/master.key (128B)
     data/keys/signing.key (96B)
     data/keys/verify.key (64B)
     data/keys/age.key (192B)
   
   Total: 5 files, 1.2MB
   ```

5. **Confirm the restore:**
   ```
   Overwrite current data? (yes/no): yes
   ```

6. **Wait for completion:**
   ```
   Restoring files...
   ✓ Restored successfully. Restart the server.
   ```

7. **Restart the NEXUS server:**
   ```bash
   ./nexus -addr :9000 -storage sqlite -db ./nexus.db
   ```

#### Command Reference

```bash
nexusctl backup restore [flags]

Flags:
  -f, --file string   Backup file to restore from (required)
  -h, --help          Help for backup restore
```

#### Example Output

```bash
$ nexusctl backup restore --file ./backups/nexus-backup-2025-12-04-001500.tar.gz.enc
⚠ Server must be stopped before restore
Enter backup password: 
Decrypting backup...
Extracting backup...

Files in backup:
  nexus.db (45.1KB)
  data/keys (directory)
  data/keys/master.key (145B)
  data/keys/signing.key (209B)
  data/keys/verify.key (113B)
  data/keys/age.key (218B)

Total: 5 files, 45.8KB

Overwrite current data? (yes/no): yes
Restoring files...
✓ Restored successfully. Restart the server.
```

---

## Export and Import

### Export Workflow

Export creates a **plaintext JSON file** containing all secrets with their values and metadata.

> ⚠️ **Security Warning:** Export files contain unencrypted secrets. Handle with care!

#### Step-by-Step

1. **Ensure the server is running** and you are logged in

2. **Run the export command:**
   ```bash
   nexusctl export --output secrets.json
   ```

3. **Wait for completion:**
   ```
   Fetching secrets...
   Exporting secret 1/10...
   Exporting secret 2/10...
   ...
   ✓ Exported 10 secrets to secrets.json
   ```

#### Command Reference

```bash
nexusctl export [flags]

Flags:
  -o, --output string   Output JSON file (required)
  -h, --help            Help for export
```

#### Export File Format

```json
{
  "exported_at": "2025-12-04T00:18:24Z",
  "secrets": [
    {
      "path": "prod/database/password",
      "value": "actual-secret-value",
      "version": 3,
      "created_at": "2025-12-01T10:00:00Z",
      "created_by": "admin-001",
      "metadata": {
        "description": "Production database password"
      }
    },
    {
      "path": "prod/api/key",
      "value": "api-key-value-here",
      "version": 1,
      "created_at": "2025-12-02T09:00:00Z",
      "created_by": "admin-001",
      "metadata": {}
    }
  ]
}
```

---

### Import Workflow

Import reads secrets from a JSON export file and creates them in NEXUS.

#### Step-by-Step

1. **Ensure the server is running** and you are logged in

2. **Run the import command:**
   ```bash
   nexusctl import --file secrets.json
   ```

3. **Wait for completion:**
   ```
   Importing 10 secrets...
   Processing secret 1/10...
   Processing secret 2/10...
   ...
   
   ✓ Import complete:
     Created: 8
     Skipped: 2
   ```

#### Command Reference

```bash
nexusctl import [flags]

Flags:
  -f, --file string   JSON file to import from (required)
  --overwrite         Overwrite existing secrets (default: false)
  -h, --help          Help for import
```

#### Import Behavior

| Scenario | Without `--overwrite` | With `--overwrite` |
|----------|----------------------|-------------------|
| Secret doesn't exist | Created | Created |
| Secret exists | Skipped | Updated |

#### Example with Overwrite

```bash
$ nexusctl import --file secrets.json --overwrite
Importing 10 secrets...
Processing secret 1/10...
Processing secret 2/10...
...

✓ Import complete:
  Created: 3
  Updated: 5
  Skipped: 0
  Failed:  2
```

---

## Best Practices

### Backup Best Practices

1. **Schedule Regular Backups**
   ```bash
   # Add to crontab for daily backups at 2 AM
   0 2 * * * /path/to/nexusctl backup create --output /backups/nexus
   ```

2. **Use Strong Passwords**
   - Minimum 16 characters
   - Mix of uppercase, lowercase, numbers, symbols
   - Unique password for each backup (or rotate regularly)

3. **Backup Rotation**
   - Keep last 30 days of backups
   - Archive monthly backups for 1 year
   ```bash
   # Delete backups older than 30 days
   find /backups/nexus -name "*.tar.gz.enc" -mtime +30 -delete
   ```

4. **Test Restores Regularly**
   - Monthly restore test to verify backup integrity
   - Document the restore procedure

5. **Off-Site Storage**
   - Copy backups to cloud storage (S3, GCS, etc.)
   - Encrypt in transit and at rest

### Export Best Practices

1. **Limit Export Use**
   - Only export when migrating between instances
   - Delete export files immediately after import

2. **Secure Export Files**
   ```bash
   # Set restrictive permissions
   chmod 600 secrets.json
   
   # Encrypt with GPG before transfer
   gpg --encrypt --recipient your@email.com secrets.json
   
   # Securely delete after use
   shred -u secrets.json
   ```

3. **Audit Export Operations**
   - All exports are logged in audit logs
   - Review audit logs for unexpected exports

---

## Known Issues

### Import Command Failures

**Issue:** The import command may fail to create some secrets due to server-side validation or timing issues.

**Symptoms:**
```
Processing secret 5/10...
⚠ Failed to create secret prod/some/path: failed to create secret
```

**Workaround:**
1. Note the failed secrets from the import output
2. Create them manually:
   ```bash
   nexusctl secret create prod/some/path "value"
   ```

**Status:** Known bug, documented as a caveat.

---

### SQLite WAL Timing Issues

**Issue:** Backups taken while the server is under heavy write load may have inconsistent data due to SQLite Write-Ahead Logging (WAL).

**Symptoms:**
- Restored database may be missing recent changes
- WAL file not included in backup

**Workaround:**
1. **Best:** Stop the server before backup
   ```bash
   # Stop server
   # Create backup
   nexusctl backup create --output ./backups
   # Start server
   ```

2. **Alternative:** Ensure a quiet period before backup
   - Schedule backups during low-traffic windows
   - Wait a few seconds after last write before backup

3. **Checkpoint WAL manually:**
   ```bash
   sqlite3 nexus.db "PRAGMA wal_checkpoint(TRUNCATE);"
   ```

**Status:** Known limitation of SQLite WAL mode with file-based backups.

---

### Keyring Password Dependency

**Issue:** The restored keyring requires the same `NEXUS_KEY_PASSWORD` environment variable that was used when the keyring was created.

**Symptoms:**
```
Failed to load keyring: failed to decrypt master key (wrong password?)
```

**Solution:**
1. Ensure `NEXUS_KEY_PASSWORD` matches the original value
2. If unknown, you cannot decrypt the restored keyring
3. You would need to recreate the keyring (losing access to old secrets)

**Prevention:**
- Document the keyring password securely
- Use a password manager or secrets vault
- Store password separately from backups

---

## Disaster Recovery Procedure

### Full Recovery Steps

1. **Provision new server**

2. **Install NEXUS binaries**
   ```bash
   make build
   ```

3. **Transfer backup file to new server**

4. **Restore from backup**
   ```bash
   nexusctl backup restore --file nexus-backup-YYYY-MM-DD-HHMMSS.tar.gz.enc
   ```

5. **Set environment variables**
   ```bash
   export NEXUS_KEY_PASSWORD="your-keyring-password"
   ```

6. **Start server**
   ```bash
   ./nexus -addr :9000 -storage sqlite -db ./nexus.db
   ```

7. **Verify recovery**
   ```bash
   nexusctl login --server http://localhost:9000
   nexusctl secret list
   ```

### Recovery Time Objectives

| Data Size | Backup Time | Restore Time |
|-----------|-------------|--------------|
| < 10 MB | < 5 seconds | < 5 seconds |
| 10-100 MB | < 30 seconds | < 30 seconds |
| 100 MB - 1 GB | 1-5 minutes | 1-5 minutes |

Actual times depend on disk I/O and CPU performance.
