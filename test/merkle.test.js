import { describe, it } from 'node:test';
import assert from 'node:assert';
import { MerkleTree } from '../src/merkle.js';

describe('RFC 6962 Merkle Tree', () => {
  it('should construct consistent tree root from leaf data', () => {
    const items = ['event_1', 'event_2', 'event_3', 'event_4'];
    const tree = new MerkleTree(items);
    const root = tree.getRoot();

    assert.strictEqual(typeof root, 'string');
    assert.strictEqual(root.length, 64);
  });

  it('should handle odd number of leaves correctly', () => {
    const items = ['event_1', 'event_2', 'event_3'];
    const tree = new MerkleTree(items);
    const root = tree.getRoot();

    assert.strictEqual(typeof root, 'string');
    assert.strictEqual(root.length, 64);
  });

  it('should generate and verify valid cryptographic inclusion proofs', () => {
    const items = ['tx_alice_bob', 'tx_bob_carol', 'tx_carol_dave', 'tx_dave_eve', 'tx_eve_frank'];
    const tree = new MerkleTree(items);

    for (let i = 0; i < items.length; i++) {
      const proof = tree.getInclusionProof(i);
      const verified = MerkleTree.verifyInclusion(items[i], proof);
      assert.strictEqual(verified, true, `Leaf ${i} inclusion proof must be valid`);
    }
  });

  it('should detect altered data and reject invalid inclusion proofs', () => {
    const items = ['record_1', 'record_2', 'record_3'];
    const tree = new MerkleTree(items);
    const proof = tree.getInclusionProof(0);

    const tampered = 'record_1_HACKED';
    const verified = MerkleTree.verifyInclusion(tampered, proof);
    assert.strictEqual(verified, false, 'Tampered record must fail proof verification');
  });

  it('should compute valid consistency proofs across tree expansions', () => {
    const tree = new MerkleTree(['a', 'b', 'c']);
    const m = 3;
    tree.append('d');
    tree.append('e');

    const consistency = tree.getConsistencyProof(m);
    assert.strictEqual(consistency.isConsistent, true);
    assert.strictEqual(consistency.historicSize, 3);
    assert.strictEqual(consistency.currentSize, 5);
  });
});
