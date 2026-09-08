import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { AuditLedger } from '../src/ledger.js';
import { AuditSigner } from '../src/signer.js';

describe('AuditLedger End-to-End Compliance Verification', () => {
  const testDir = './data/test_ledger_' + Date.now();

  it('should record events and return valid signed receipts', () => {
    const ledger = new AuditLedger(testDir);
    const res = ledger.record({
      actor: 'admin@company.com',
      action: 'policy.update',
      resource: 'iam/roles/production-access',
      metadata: { ip: '192.168.1.100' }
    });

    assert.ok(res.event.id);
    assert.strictEqual(res.event.action, 'policy.update');
    assert.strictEqual(typeof res.receipt.signature, 'string');

    const isSigValid = AuditSigner.verifyRootSignature(res.receipt);
    assert.strictEqual(isSigValid, true, 'Root signature must be valid Ed25519');
  });

  it('should verify event inclusion against current Merkle root', () => {
    const ledger = new AuditLedger(testDir);
    const r1 = ledger.record({ actor: 'svc_auth', action: 'login.success', resource: 'user_42' });
    const r2 = ledger.record({ actor: 'svc_billing', action: 'invoice.paid', resource: 'inv_99' });

    assert.strictEqual(ledger.verifyEvent(r1.event.id), true);
    assert.strictEqual(ledger.verifyEvent(r2.event.id), true);
  });

  it('should export complete self-verifying compliance audit package', () => {
    const ledger = new AuditLedger(testDir);
    const bundle = ledger.exportComplianceBundle();

    assert.strictEqual(bundle.specVersion, 'AuditLock-RFC6962-v1');
    assert.ok(bundle.treeSize >= 3);
    assert.strictEqual(bundle.events.length, bundle.treeSize);
  });

  // Cleanup test files
  it('cleanup test artifacts', () => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });
});
