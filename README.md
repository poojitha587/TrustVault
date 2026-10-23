# TrustVault — Secure Document Sharing with Real Audit Trail

TrustVault is an enterprise-grade document sharing platform built with FastAPI, SQLAlchemy, and SQLite/PostgreSQL. It enforces strict, zero-trust server-side authorization checks on every file operation and maintains an append-only, tamper-evident audit trail for all access and authorization attempts.

- **Live URL:** [https://trustvault-4bgd.onrender.com](https://trustvault-4bgd.onrender.com)
- **API Documentation:** [https://trustvault-4bgd.onrender.com/docs](https://trustvault-4bgd.onrender.com/docs)

---

## 1. Test Credentials (Seed Accounts)

The system automatically initializes three baseline roles with pre-hashed credentials:

| Role | Email | Password | Allowed Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.com` | `AdminPass123!` | System monitoring, view full audit logs, manage permissions |
| **Owner** | `owner@trustvault.com` | `OwnerPass123!` | Upload documents, view own files, grant/revoke user access |
| **Viewer** | `viewer@trustvault.com` | `ViewerPass123!` | Read/download explicitly permitted files only. Uploads blocked (403) |

---

## 2. Core Architectural Principles

1. **Zero-Trust Server-Side Authorization:** Access decisions are never cached in JWT claims or delegated to the frontend. Every file download verifies direct ownership or live records in the `document_permissions` table.
2. **Instant Permission Revocation:** Revoking a record in the database terminates access on the immediate next request.
3. **Immutable Audit Logging:** Every document creation, download success, and unauthorized download attempt is permanently logged with timestamps, actor IDs, and IP addresses.

---

## 3. Local Setup & Execution

### Prerequisites
- Python 3.10+
- pip

### Installation & Running Locally
```bash
# Clone the repository
git clone [https://github.com/poojitha587/TrustVault.git](https://github.com/poojitha587/TrustVault.git)
cd TrustVault

# Install dependencies
pip install -r requirements.txt

# Start the application on port 5000
uvicorn app.main:app --host 127.0.0.1 --port 5000 --reload