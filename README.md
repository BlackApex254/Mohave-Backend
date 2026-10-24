# Hearthstone Lending — Standalone Backend Service

This directory contains the independent, standalone backend service for Hearthstone Lending.

## Features
- **Duplicate Registration Prevention**: Normalizes email and enforces unique client data records with HTTP 409 Conflict.
- **Cryptographic Security**: Node.js `crypto.scryptSync` with unique 16-byte cryptographic salts.
- **2FA OTP Engine**: Generates 6-digit one-time security passcodes with 10-minute expiry and attempt tracking.
- **Email Service & Outbox**: Automatic dispatch and audit log for:
  - Security OTP Passcodes
  - Welcome & Registration Confirmation
  - Loan Application Received (with 1–3 Business Day SLA Commitment)
  - Underwriting Decision Notices (Approval / Adverse Action with ECOA disclosures)
- **Loan Underwriting Workflow**: Full lifecycle from borrower intake to Admin Underwriting decision point.
- **Persistent Storage**: File-backed storage in `.data/hearthstone_db.json`.

## Quick Start
```bash
# In the backend directory:
npm start

# Or custom port:
PORT=4000 node server.js
```

## Environment Variables
- `PORT` — Port number (defaults to 4000).
- `DATA_DIR` — Custom path for persistent data storage if desired.
