# AuditLock (auditlock-js)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg)](package.json)
[![RFC 6962](https://img.shields.io/badge/Specification-RFC%206962-orange.svg)](https://tools.ietf.org/html/rfc6962)
[![Compliance Ready](https://img.shields.io/badge/Compliance-SOC2%20%7C%20HIPAA%20%7C%20GDPR-brightgreen.svg)](#compliance-mappings)

**AuditLock** is an ultra-fast, zero-dependency cryptographic audit ledger and Merkle compliance engine for Node.js. It provides tamper-evident, append-only event logging with mathematical inclusion proofs and signed root state, designed to satisfy SOC2 Type II, HIPAA, ISO 27001, and GDPR compliance audit requirements.

---

## The Real-World Problem

In traditional database systems (Postgres, MySQL, MongoDB), audit logs are stored as plain rows. Even with restrictive database roles, any user or process with database administration credentials can silently execute `UPDATE` or `DELETE` statements, alter timestamps, or modify historical records without leaving a trace. During compliance audits (SOC2 CC6.8, HIPAA § 164.312(b)), organizations must prove to external auditors that audit records **could not have been tampered with**.

### How AuditLock Solves This
1. **RFC 6962 Merkle Tree**: Every audit event is hashed with a `0x00` domain separator prefix. Interior nodes use `0x01` to mathematically eliminate second-preimage collision attacks.
2. **Cryptographic Inclusion Proofs (Audit Paths)**: Any single event can be proven to exist in the global ledger in $O(\log N)$ hash steps without exposing other tenant records.
3. **Signed State Roots**: Every state change signs the cumulative Merkle root using asymmetric Ed25519 digital signatures.
4. **Append-Only Write-Ahead Log (WAL)**: Crash-resilient binary storage with per-record SHA-256 checksums that trigger instantaneous tamper alerts if disk bytes are modified.
5. **Zero External Dependencies**: Pure vanilla modern JavaScript (Node.js ES modules).

---

## Architecture

```
  [ Application Event ]
           │
           ▼
  ┌───────────────────┐
  │   AuditLedger     │
  └────────┬──────────┘
           ├────────────────────────────┬────────────────────────────┐
           ▼                            ▼                            ▼
  ┌───────────────────┐        ┌───────────────────┐        ┌───────────────────┐
  │  AppendOnlyStorage│        │  RFC 6962 Merkle  │        │   Ed25519 Signer  │
  │     (WAL + SHA)   │        │   Binary Tree     │        │  (Signed Receipt) │
  └───────────────────┘        └────────┬──────────┘        └───────────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                Inclusion Proof               Consistency Proof
             (Audit Path in O(log N))     (M-size historic prefix of N)
```

---

## Quickstart

### 1. Installation
AuditLock has **zero dependencies**:
```bash
git clone https://github.com/davidselorm/auditlock-js.git
cd auditlock-js
```

### 2. Programmatic Usage
```javascript
import { AuditLedger } from 'auditlock-js';

const ledger = new AuditLedger('./data/production_audit');

// 1. Record an audit event
const { event, receipt } = ledger.record({
  actor: 'alice@enterprise.com',
  action: 'database.credential_rotate',
  resource: 'prod-rds-primary',
  metadata: { ip: '10.0.4.12', mfaVerified: true }
});

console.log('Event Recorded:', event.id);
console.log('Merkle Root:', receipt.root);

// 2. Cryptographically verify event integrity
const isValid = ledger.verifyEvent(event.id);
console.log('Is Event Valid & Untampered?', isValid); // true
```

### 3. CLI Usage
```bash
# Append an audit log
node src/cli.js log --actor "sec-team" --action "access.grant" --resource "vault-role"

# Verify event inclusion
node src/cli.js verify --id <EVENT_UUID>

# Export auditor package for compliance review
node src/cli.js export --out compliance_package.json

# Run HTTP REST API
node src/cli.js serve --port 8080
```

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/events` | Ingest an audit event (`actor`, `action`, `resource`, `metadata`) |
| `GET` | `/api/v1/events/:id` | Fetch stored audit event record |
| `GET` | `/api/v1/proofs/inclusion/:id` | Return cryptographic Merkle inclusion proof |
| `GET` | `/api/v1/root` | Return latest Merkle root and signed Ed25519 receipt |
| `GET` | `/api/v1/export` | Export complete self-verifying compliance bundle |
| `GET` | `/health` | Service healthcheck |

---

## Compliance Mappings

- **SOC2 Common Criteria CC6.8**: Unauthorized modification of audit records is mathematically prevented by Merkle tree hash chaining and Ed25519 signature checks.
- **HIPAA Security Rule § 164.312(b)**: Establishes hardware/software mechanisms to record and examine activity in information systems containing EPHI.
- **ISO/IEC 27001 Control A.12.4**: Ensures event logs recording user activities, exceptions, and security events are protected against tampering.

---

## Tests & Benchmarks

Run the built-in native test runner:
```bash
npm test
```

Run the high-throughput performance benchmark:
```bash
npm run benchmark
```

---

## License
MIT © David Selorm Walker
