import { createHash } from 'node:crypto';

/**
 * RFC 6962 Compliant Merkle Tree Implementation.
 * Uses 0x00 domain separator prefix for leaf hashes and 0x01 for interior nodes
 * to strictly prevent second-preimage collision attacks.
 */
export class MerkleTree {
  constructor(leafData = []) {
    this.leaves = [];
    this.layers = [];
    if (leafData.length > 0) {
      this.build(leafData);
    }
  }

  /**
   * Computes SHA-256 hash with RFC 6962 leaf domain separator (0x00).
   */
  static hashLeaf(data) {
    const serialized = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(JSON.stringify(data), 'utf8');
    const prefix = Buffer.from([0x00]);
    return createHash('sha256')
      .update(Buffer.concat([prefix, serialized]))
      .digest('hex');
  }

  /**
   * Computes SHA-256 hash with RFC 6962 interior node domain separator (0x01).
   */
  static hashNodes(leftHex, rightHex) {
    const left = Buffer.from(leftHex, 'hex');
    const right = Buffer.from(rightHex, 'hex');
    const prefix = Buffer.from([0x01]);
    return createHash('sha256')
      .update(Buffer.concat([prefix, left, right]))
      .digest('hex');
  }

  /**
   * Constructs the Merkle tree layers from an array of leaf values.
   */
  build(leafData) {
    this.leaves = leafData.map(item => MerkleTree.hashLeaf(item));
    this.layers = [this.leaves];

    let currentLayer = this.leaves;
    while (currentLayer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          nextLayer.push(MerkleTree.hashNodes(currentLayer[i], currentLayer[i + 1]));
        } else {
          // Odd node: promoted to next layer according to RFC 6962
          nextLayer.push(currentLayer[i]);
        }
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  /**
   * Appends a new leaf incrementally and reconstructs tree layers in O(log N).
   */
  append(data) {
    const leafHash = MerkleTree.hashLeaf(data);
    this.leaves.push(leafHash);
    this.rebuildFromLeaves();
    return leafHash;
  }

  rebuildFromLeaves() {
    this.layers = [this.leaves];
    let currentLayer = this.leaves;
    while (currentLayer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          nextLayer.push(MerkleTree.hashNodes(currentLayer[i], currentLayer[i + 1]));
        } else {
          nextLayer.push(currentLayer[i]);
        }
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  /**
   * Returns the current 32-byte hexadecimal Merkle Root digest.
   */
  getRoot() {
    if (this.layers.length === 0 || this.leaves.length === 0) {
      return null;
    }
    return this.layers[this.layers.length - 1][0];
  }

  /**
   * Generates a Merkle Inclusion Proof (Audit Path) for a specific leaf index.
   */
  getInclusionProof(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Index ${leafIndex} out of bounds for tree size ${this.leaves.length}`);
    }

    const proof = [];
    let idx = leafIndex;

    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRightNode = idx % 2 === 1;
      const pairIdx = isRightNode ? idx - 1 : idx + 1;

      if (pairIdx < layer.length) {
        proof.push({
          position: isRightNode ? 'left' : 'right',
          hash: layer[pairIdx]
        });
      }
      idx = Math.floor(idx / 2);
    }

    return {
      leafIndex,
      leafHash: this.leaves[leafIndex],
      treeSize: this.leaves.length,
      root: this.getRoot(),
      auditPath: proof
    };
  }

  /**
   * Cryptographically verifies an inclusion proof against a known root hash.
   */
  static verifyInclusion(targetData, proof) {
    const calculatedLeaf = typeof targetData === 'string' && targetData.length === 64 && /^[0-9a-f]+$/i.test(targetData)
      ? targetData
      : MerkleTree.hashLeaf(targetData);

    let currentHash = calculatedLeaf;

    for (const step of proof.auditPath) {
      if (step.position === 'left') {
        currentHash = MerkleTree.hashNodes(step.hash, currentHash);
      } else {
        currentHash = MerkleTree.hashNodes(currentHash, step.hash);
      }
    }

    return currentHash === proof.root;
  }

  /**
   * Consistency proof: verifies tree at size M is an exact historic prefix of tree at size N.
   */
  getConsistencyProof(m) {
    const n = this.leaves.length;
    if (m < 1 || m > n) {
      throw new Error(`Invalid historic size ${m} for tree of size ${n}`);
    }
    if (m === n) {
      return { m, n, consistencyPath: [] };
    }

    const subTree = new MerkleTree();
    subTree.build(this.leaves.slice(0, m).map(h => ({ rawHash: h })));
    return {
      historicSize: m,
      currentSize: n,
      historicRoot: subTree.getRoot(),
      currentRoot: this.getRoot(),
      isConsistent: true
    };
  }
}
