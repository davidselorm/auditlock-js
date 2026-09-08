import { generateKeyPairSync, sign, verify } from 'node:crypto';

/**
 * Asymmetric Ed25519 cryptographic key generator and root signer.
 */
export class AuditSigner {
  constructor(privateKeyPem = null, publicKeyPem = null) {
    if (privateKeyPem && publicKeyPem) {
      this.privateKey = privateKeyPem;
      this.publicKey = publicKeyPem;
    } else {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }
  }

  signRoot(rootHex, treeSize, timestamp) {
    const payload = Buffer.from(`AUDITLOCK_ROOT:${rootHex}:${treeSize}:${timestamp}`, 'utf8');
    const signature = sign(null, payload, this.privateKey);
    return {
      root: rootHex,
      treeSize,
      timestamp,
      signature: signature.toString('hex'),
      publicKey: this.publicKey
    };
  }

  static verifyRootSignature(signedReceipt) {
    const { root, treeSize, timestamp, signature, publicKey } = signedReceipt;
    const payload = Buffer.from(`AUDITLOCK_ROOT:${root}:${treeSize}:${timestamp}`, 'utf8');
    const sigBuffer = Buffer.from(signature, 'hex');
    return verify(null, payload, publicKey, sigBuffer);
  }
}
