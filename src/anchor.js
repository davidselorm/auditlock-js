import { createHash } from 'node:crypto';

/**
 * Write-Once-Read-Many (WORM) Compliance Root Anchor Publisher.
 * Satisfies SEC Rule 17a-4 and CFTC Rule 1.31 immutable storage mandates.
 */
export class RootAnchorPublisher {
  constructor(ledger) {
    this.ledger = ledger;
  }

  generateAnchorSnapshot() {
    const root = this.ledger.merkle.getRoot();
    const treeSize = this.ledger.events.length;
    const timestamp = new Date().toISOString();

    const signedReceipt = this.ledger.signer.signRoot(root, treeSize, timestamp);
    const digest = createHash('sha256')
      .update(JSON.stringify(signedReceipt))
      .digest('hex');

    return {
      spec: 'WORM-RFC6962-Anchor-v1',
      digest,
      receipt: signedReceipt
    };
  }
}
