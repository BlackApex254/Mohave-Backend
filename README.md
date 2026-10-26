# Mohave Backend — Standalone Backend Service

This repository contains the independent backend service for Hearthstone Lending.

## Features
- **Duplicate Registration Prevention**: Normalizes email and enforces unique client records with HTTP 409 Conflict.
- **Cryptographic Security**: Node.js `crypto.scryptSync` with unique 16-byte cryptographic salts and constant-time comparison.
- **2FA OTP Engine**: Generates 6-digit one-time security passcodes with 10-minute expiry and attempt tracking.
- **Email Service & Outbox**: Automatic dispatch and audit log for:
  - Security OTP Passcodes
  - Welcome & Registration Confirmation
  - Loan Application Received (with 1–3 Business Day SLA Commitment)
  - Underwriting Decision Notices (Approval / Adverse Action with ECOA disclosures)
- **Loan Underwriting Workflow**: Full lifecycle from borrower intake to Admin Underwriting decision point.
- **KYC Document Validation Engine**: Validates identity documents (driver's licenses front/back, facial liveness video) with sharpness and brightness checks.
- **Commitment Bank Configuration**: Admin endpoints to configure bank details for borrower fee disbursements.
- **Partial Application Updates**: Full support for updating underwriting notes, approval status, document status, disbursement accounts, and fee receipts.
- **Persistent Storage**: File-backed storage in `.data/hearthstone_db.json` with fallback support.

## Quick Start
```bash
# In this directory:
npm start

# Or custom port:
PORT=4000 node server.js
```

## Environment Variables
- `PORT` — Port number (defaults to 4000).
- `DATA_DIR` — Custom path for persistent data storage if desired.
- `DATABASE_URL` — PostgreSQL connection string (optional).
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` — SMTP credentials for live transactional emails.
