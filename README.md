# VaultCare — Secure Credential Management

VaultCare is a portfolio MVP for managing credential *records* securely. It demonstrates a .NET 8 API, React/TypeScript UI, PostgreSQL persistence, Redis-backed cache infrastructure, JWT authentication, role-based authorization, audit events, and AES-GCM encryption for stored secret values.

## Security and honest scope
- The API encrypts secret values with AES-GCM before persistence; the encryption key is supplied by `VAULTCARE_ENCRYPTION_KEY` (base64 encoding of exactly 32 random bytes).
- JWT signing uses `VAULTCARE_JWT_KEY` (at least 32 characters in this demo).
- The seeded demo user is `admin@vaultcare.local` / `ChangeMe123!`. Change it immediately for any use beyond a local demo.
- This is an educational MVP, not a production password manager. Do not store real credentials. Production requires a managed key vault/KMS, hardened authentication and recovery, MFA, rate limits, penetration testing, secret rotation, security review, and secure deployment configuration.
- Redis is wired as a cache dependency; the current UI/API primarily use PostgreSQL and do not cache secret values.

## Requirements
.NET 8 SDK, Node.js 20+, Docker Desktop.

## Run with Docker
Create a `.env` file from `.env.example`, then run:
```powershell
docker compose up --build
```
API: `http://localhost:8080`; React UI: `http://localhost:5173`.

## Run locally without Docker
Start PostgreSQL and Redis separately, set environment variables from `.env.example`, then:
```powershell
cd backend/VaultCare.Api
dotnet restore
dotnet run
```
In another terminal:
```powershell
cd frontend/vaultcare-ui
npm install
npm run dev
```

## API overview
- `POST /api/auth/login`
- `GET /api/credentials` — list metadata, never returns decrypted secret values
- `POST /api/credentials` — encrypt and store a record
- `GET /api/credentials/{id}/reveal` — decrypt after authorization; emits an audit event
- `PUT /api/credentials/{id}` — update metadata and optionally rotate secret
- `DELETE /api/credentials/{id}` — delete record
- `GET /api/audit` — admin-only audit trail
- `GET /health`

The database is migrated/created at startup for a simple local demo. For production, use reviewed EF migrations and managed secrets.
