# NEXUS API Reference

Complete REST API documentation for the NEXUS Secrets Manager.

---

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Endpoints](#endpoints)
  - [Health](#health)
  - [Authentication](#authentication-endpoints)
  - [Secrets](#secrets)
  - [Secret Versions](#secret-versions)
  - [Audit Logs](#audit-logs)
  - [API Keys](#api-keys)
- [Error Codes](#error-codes)
- [Examples](#examples)

---

## Overview

### Base URL

```
http://localhost:9000
```

### API Versioning

All API endpoints are prefixed with `/api/v1`.

### Content Type

All requests and responses use JSON:

```
Content-Type: application/json
```

### Authentication Header

After login, include the JWT token in all requests:

```
Authorization: Bearer <token>
```

Or use an API key:

```
X-Nexus-API-Key: <api-key>
```

---

## Authentication

NEXUS uses JWT (JSON Web Token) authentication with optional API key support.

### Authentication Flow

1. **Login**: Send credentials to `/api/v1/auth/login`
2. **Receive Token**: Get a JWT token valid for 24 hours
3. **Use Token**: Include token in `Authorization` header for all requests
4. **Refresh**: Use `/api/v1/auth/refresh` to get a new token before expiry

### Token Expiry

Tokens expire after **24 hours** by default. Monitor the `expires_at` field in login response.

---

## Endpoints

### Health

#### GET /health

Check server health status. **No authentication required.**

**Request:**
```bash
curl http://localhost:9000/health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-04T00:18:24Z"
}
```

**Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "timestamp": "2025-12-04T00:18:24Z",
  "error": "database connection failed"
}
```

---

### Authentication Endpoints

#### POST /api/v1/auth/login

Authenticate with username and password.

**Request:**
```bash
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Username |
| `password` | string | Yes | Password |

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-12-05T00:18:24Z",
  "user": {
    "id": "admin-001",
    "name": "Admin User",
    "role": "admin"
  }
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "Unauthorized",
  "message": "invalid credentials"
}
```

---

#### POST /api/v1/auth/refresh

Refresh an authentication token. **Requires authentication.**

**Request:**
```bash
curl -X POST http://localhost:9000/api/v1/auth/refresh \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-12-05T00:18:24Z"
}
```

---

### Secrets

#### GET /api/v1/secrets

List all secrets, optionally filtered by prefix.

**Request:**
```bash
# List all secrets
curl http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer <token>"

# Filter by prefix
curl "http://localhost:9000/api/v1/secrets?prefix=prod/" \
  -H "Authorization: Bearer <token>"
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prefix` | string | No | Filter secrets by path prefix |

**Response (200 OK):**
```json
{
  "secrets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "path": "prod/database/password",
      "metadata": {
        "description": "Production database password"
      },
      "version": 3,
      "created_at": "2025-12-01T10:00:00Z",
      "created_by": "admin-001",
      "updated_at": "2025-12-03T15:30:00Z",
      "updated_by": "admin-001"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "path": "prod/api/key",
      "metadata": {},
      "version": 1,
      "created_at": "2025-12-02T09:00:00Z",
      "created_by": "admin-001",
      "updated_at": "2025-12-02T09:00:00Z",
      "updated_by": "admin-001"
    }
  ],
  "total": 2
}
```

> **Note:** Secret values are NOT included in list responses for security.

---

#### POST /api/v1/secrets

Create a new secret.

**Request:**
```bash
curl -X POST http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "prod/database/password",
    "value": "super-secret-password",
    "metadata": {
      "description": "Production database password",
      "owner": "dba-team"
    }
  }'
```

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Unique path for the secret (e.g., `prod/database/password`) |
| `value` | string | Yes | The secret value to store |
| `metadata` | object | No | Key-value pairs for additional information |

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "prod/database/password",
  "metadata": {
    "description": "Production database password",
    "owner": "dba-team"
  },
  "version": 1,
  "created_at": "2025-12-04T00:18:24Z",
  "created_by": "admin-001",
  "updated_at": "2025-12-04T00:18:24Z",
  "updated_by": "admin-001"
}
```

**Response (409 Conflict):**
```json
{
  "error": "Conflict",
  "message": "secret already exists"
}
```

---

#### GET /api/v1/secrets/{path}

Retrieve a secret by its path. **Returns the decrypted value.**

**Request:**
```bash
curl http://localhost:9000/api/v1/secrets/prod/database/password \
  -H "Authorization: Bearer <token>"
```

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | The secret path |

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "prod/database/password",
  "value": "super-secret-password",
  "metadata": {
    "description": "Production database password"
  },
  "version": 3,
  "created_at": "2025-12-01T10:00:00Z",
  "created_by": "admin-001",
  "updated_at": "2025-12-03T15:30:00Z",
  "updated_by": "admin-001"
}
```

**Response (404 Not Found):**
```json
{
  "error": "Not Found",
  "message": "secret not found"
}
```

---

#### PUT /api/v1/secrets/{path}

Update an existing secret. Creates a new version automatically.

**Request:**
```bash
curl -X PUT http://localhost:9000/api/v1/secrets/prod/database/password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "new-super-secret-password",
    "metadata": {
      "description": "Updated production database password",
      "rotated": "2025-12-04"
    }
  }'
```

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `value` | string | No | New secret value (if omitted, value unchanged) |
| `metadata` | object | No | New metadata (replaces existing if provided) |

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "prod/database/password",
  "metadata": {
    "description": "Updated production database password",
    "rotated": "2025-12-04"
  },
  "version": 4,
  "created_at": "2025-12-01T10:00:00Z",
  "created_by": "admin-001",
  "updated_at": "2025-12-04T00:18:24Z",
  "updated_by": "admin-001"
}
```

---

#### DELETE /api/v1/secrets/{path}

Delete a secret by its path.

**Request:**
```bash
curl -X DELETE http://localhost:9000/api/v1/secrets/prod/database/password \
  -H "Authorization: Bearer <token>"
```

**Response (204 No Content):**
No response body on success.

**Response (404 Not Found):**
```json
{
  "error": "Not Found",
  "message": "secret not found"
}
```

---

### Secret Versions

#### GET /api/v1/secrets/{path}/versions

Get version history for a secret.

**Request:**
```bash
curl http://localhost:9000/api/v1/secrets/prod/database/password/versions \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**
```json
{
  "versions": [
    {
      "id": "version-uuid-1",
      "secret_id": "550e8400-e29b-41d4-a716-446655440000",
      "version": 3,
      "created_at": "2025-12-03T15:30:00Z",
      "created_by": "admin-001"
    },
    {
      "id": "version-uuid-2",
      "secret_id": "550e8400-e29b-41d4-a716-446655440000",
      "version": 2,
      "created_at": "2025-12-02T10:00:00Z",
      "created_by": "admin-001"
    },
    {
      "id": "version-uuid-3",
      "secret_id": "550e8400-e29b-41d4-a716-446655440000",
      "version": 1,
      "created_at": "2025-12-01T10:00:00Z",
      "created_by": "admin-001"
    }
  ],
  "total": 3
}
```

> **Note:** Version values are not returned for security. Use backups to restore previous versions.

---

### Audit Logs

#### GET /api/v1/audit

List audit log entries. **Requires admin role.**

**Request:**
```bash
# List recent audit logs
curl http://localhost:9000/api/v1/audit \
  -H "Authorization: Bearer <token>"

# With filters
curl "http://localhost:9000/api/v1/audit?user=admin-001&action=secret.read&limit=50" \
  -H "Authorization: Bearer <token>"
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | integer | No | Maximum entries to return (default: no limit) |
| `offset` | integer | No | Number of entries to skip |
| `user` | string | No | Filter by user ID |
| `action` | string | No | Filter by action type |
| `secret_path` | string | No | Filter by secret path |
| `start_time` | string | No | Filter by start time (RFC3339) |
| `end_time` | string | No | Filter by end time (RFC3339) |

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "audit-uuid-1",
      "timestamp": "2025-12-04T00:18:24Z",
      "action": "secret.read",
      "user": "admin-001",
      "secret_id": "550e8400-e29b-41d4-a716-446655440000",
      "secret_path": "prod/database/password",
      "ip_address": "192.168.1.100",
      "user_agent": "nexusctl/1.0.0",
      "success": true,
      "metadata": {}
    },
    {
      "id": "audit-uuid-2",
      "timestamp": "2025-12-04T00:15:00Z",
      "action": "auth.login",
      "user": "admin",
      "secret_id": "",
      "secret_path": "",
      "ip_address": "192.168.1.100",
      "user_agent": "nexusctl/1.0.0",
      "success": true,
      "metadata": {}
    }
  ],
  "total": 2
}
```

**Response (403 Forbidden):**
```json
{
  "error": "Forbidden",
  "message": "admin access required"
}
```

**Audit Action Types:**
| Action | Description |
|--------|-------------|
| `auth.login` | User login attempt |
| `auth.refresh` | Token refresh |
| `secret.list` | List secrets |
| `secret.read` | Read a secret |
| `secret.create` | Create a secret |
| `secret.update` | Update a secret |
| `secret.delete` | Delete a secret |
| `secret.versions` | View secret versions |
| `audit.list` | View audit logs |
| `apikey.create` | Create API key |
| `apikey.revoke` | Revoke API key |

---

### API Keys

#### GET /api/v1/apikeys

List all API keys for the current user.

**Request:**
```bash
curl http://localhost:9000/api/v1/apikeys \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**
```json
{
  "keys": [
    {
      "id": "key-uuid-1",
      "name": "CI/CD Pipeline",
      "prefix": "nx_k8j3h",
      "created_at": "2025-12-01T10:00:00Z",
      "expires_at": "2026-01-01T10:00:00Z",
      "last_used": "2025-12-03T15:30:00Z"
    },
    {
      "id": "key-uuid-2",
      "name": "Service Account",
      "prefix": "nx_9f2kd",
      "created_at": "2025-12-02T09:00:00Z",
      "expires_at": null,
      "last_used": null
    }
  ],
  "total": 2
}
```

---

#### POST /api/v1/apikeys

Create a new API key.

**Request:**
```bash
curl -X POST http://localhost:9000/api/v1/apikeys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "expires_in": 2592000000000000
  }'
```

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name for the key |
| `expires_in` | integer | No | Expiry duration in nanoseconds (e.g., 720h = 30 days) |

**Response (201 Created):**
```json
{
  "id": "key-uuid-new",
  "name": "CI/CD Pipeline",
  "key": "nx_k8j3hf92kd8h3f9dk2h3f9d8k2h3f9d8k2h3f9d",
  "prefix": "nx_k8j3h",
  "created_at": "2025-12-04T00:18:24Z",
  "expires_at": "2026-01-03T00:18:24Z"
}
```

> **⚠️ Important:** The `key` field is only returned once at creation. Store it securely!

---

#### DELETE /api/v1/apikeys

Revoke an API key.

**Request:**
```bash
curl -X DELETE "http://localhost:9000/api/v1/apikeys?id=key-uuid-1" \
  -H "Authorization: Bearer <token>"
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | The API key ID to revoke |

**Response (204 No Content):**
No response body on success.

---

## Error Codes

### HTTP Status Codes

| Code | Description |
|------|-------------|
| `200` | OK - Request succeeded |
| `201` | Created - Resource created successfully |
| `204` | No Content - Request succeeded, no response body |
| `400` | Bad Request - Invalid request body or parameters |
| `401` | Unauthorized - Missing or invalid authentication |
| `403` | Forbidden - Insufficient permissions |
| `404` | Not Found - Resource not found |
| `405` | Method Not Allowed - HTTP method not supported |
| `409` | Conflict - Resource already exists |
| `500` | Internal Server Error - Server error |
| `503` | Service Unavailable - Server unhealthy |

### Error Response Format

All errors return a JSON object:

```json
{
  "error": "HTTP Status Text",
  "message": "Human-readable error description"
}
```

---

## Examples

### Complete Workflow Example

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}' | jq -r '.token')

# 2. Create a secret
curl -X POST http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "myapp/database/password",
    "value": "db-password-123",
    "metadata": {"environment": "production"}
  }'

# 3. Read the secret
curl http://localhost:9000/api/v1/secrets/myapp/database/password \
  -H "Authorization: Bearer $TOKEN"

# 4. Update the secret
curl -X PUT http://localhost:9000/api/v1/secrets/myapp/database/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "new-db-password-456"}'

# 5. View version history
curl http://localhost:9000/api/v1/secrets/myapp/database/password/versions \
  -H "Authorization: Bearer $TOKEN"

# 6. List all secrets
curl http://localhost:9000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN"

# 7. Delete the secret
curl -X DELETE http://localhost:9000/api/v1/secrets/myapp/database/password \
  -H "Authorization: Bearer $TOKEN"
```

### Using API Keys

```bash
# 1. Create an API key
API_KEY=$(curl -s -X POST http://localhost:9000/api/v1/apikeys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Service"}' | jq -r '.key')

# 2. Use the API key instead of JWT
curl http://localhost:9000/api/v1/secrets \
  -H "X-Nexus-API-Key: $API_KEY"

# 3. List your API keys
curl http://localhost:9000/api/v1/apikeys \
  -H "Authorization: Bearer $TOKEN"
```

### Filtering Audit Logs

```bash
# Get failed login attempts in the last 24 hours
curl "http://localhost:9000/api/v1/audit?action=auth.login&start_time=2025-12-03T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN"

# Get all actions by a specific user
curl "http://localhost:9000/api/v1/audit?user=admin-001&limit=100" \
  -H "Authorization: Bearer $TOKEN"

# Get all access to a specific secret
curl "http://localhost:9000/api/v1/audit?secret_path=prod/database/password" \
  -H "Authorization: Bearer $TOKEN"
```
