import { randomUUID } from 'node:crypto';
import { MerkleTree } from './merkle.js';
import { AppendOnlyStorage } from './storage.js';
import { AuditSigner } from './signer.js';

/**
 * High-Level Audit Ledger Engine
 */
export class AuditLedger {
  constructor(storageDir = './data/audit_ledger') {
    this.storage = new AppendOnlyStorage(storageDir);
    this.signer = new AuditSigner();
    this.merkle = new MerkleTree();
    this.events = [];

    this.recover();
  }

  recover() {
    this.events = this.storage.readAllRecords();
    if (this.events.length > 0) {
      this.merkle.build(this.events);
    }
  }

  /**
   * Appends an immutable audit event and signs the resulting Merkle root.
   */
  record({ actor, action, resource, metadata = {} }) {
    const timestamp = new Date().toISOString();
    const id = randomUUID();

    const event = {
      id,
      timestamp,
      actor,
      action,
      resource,
      metadata
    };

    // 1. Persist to WAL
    this.storage.appendRecord(event);
    this.events.push(event);

    // 2. Increment Merkle Tree
    const leafHash = this.merkle.append(event);
    const root = this.merkle.getRoot();
    const treeSize = this.merkle.leaves.length;

    // 3. Generate Signed Receipt
    const receipt = this.signer.signRoot(root, treeSize, timestamp);

    return {
      event,
      leafHash,
      leafIndex: treeSize - 1,
      receipt
    };
  }

  /**
   * Generates cryptographic inclusion proof for an event ID.
   */
  getInclusionProof(eventId) {
    const idx = this.events.findIndex(e => e.id === eventId);
    if (idx === -1) {
      throw new Error(`Event '${eventId}' not found in ledger`);
    }
    return this.merkle.getInclusionProof(idx);
  }

  /**
   * Verifies an event exists and has not been altered.
   */
  verifyEvent(eventId) {
    const idx = this.events.findIndex(e => e.id === eventId);
    if (idx === -1) return false;

    const event = this.events[idx];
    const proof = this.merkle.getInclusionProof(idx);
    return MerkleTree.verifyInclusion(event, proof);
  }

  /**
   * Generates a self-verifying export bundle for external compliance auditors (SOC2/HIPAA).
   */
  exportComplianceBundle() {
    const currentRoot = this.merkle.getRoot();
    const treeSize = this.events.length;
    const signedReceipt = this.signer.signRoot(currentRoot, treeSize, new Date().toISOString());

    return {
      specVersion: 'AuditLock-RFC6962-v1',
      generatedAt: new Date().toISOString(),
      treeSize,
      merkleRoot: currentRoot,
      signature: signedReceipt.signature,
      publicKey: signedReceipt.publicKey,
      events: this.events.map((e, idx) => ({
        index: idx,
        event: e,
        leafHash: this.merkle.leaves[idx],
        inclusionProof: this.merkle.getInclusionProof(idx)
      }))
    };
  }
}
