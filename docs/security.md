# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### How to Report

Email security vulnerabilities to: **constantine.ctf@proton.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **48-hour response** - We'll acknowledge your report
- **Confidentiality** - We'll keep your report private until fixed
- **Credit** - We'll credit you in the fix announcement (if desired)
- **Fix timeline** - Critical issues fixed within 7 days

### Security Best Practices

When deploying NEXUS in production:

1. ✅ Use HTTPS (reverse proxy with TLS)
2. ✅ Set strong `NEXUS_KEY_PASSWORD` environment variable
3. ✅ Change default admin credentials immediately
4. ✅ Restrict network access (firewall rules)
5. ✅ Regular encrypted backups with rotation
6. ✅ Monitor audit logs for suspicious activity
7. ✅ Keep NEXUS updated to latest version

## Known Issues

See [docs/BACKUP.md](docs/BACKUP. md) for known limitations:
- Import command server-side failures
- SQLite WAL timing issues with backups

---

**For enterprise support with SLA guarantees:** [constantine.ctf@proton.me](mailto:constantine.ctf@proton.me)