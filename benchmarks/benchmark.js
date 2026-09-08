import { performance } from 'node:perf_hooks';
import fs from 'node:fs';
import { AuditLedger } from '../src/ledger.js';

const benchDir = './data/bench_ledger_' + Date.now();
const ledger = new AuditLedger(benchDir);

console.log('=== BENCHMARKING AUDITLOCK-JS THROUGHPUT ===\n');

const TOTAL_EVENTS = 1000;
console.log(`Ingesting ${TOTAL_EVENTS} audit events into Merkle WAL...`);

const t0 = performance.now();
for (let i = 0; i < TOTAL_EVENTS; i++) {
  ledger.record({
    actor: `user_${i % 50}`,
    action: 'resource.access',
    resource: `document_${i}`,
    metadata: { tenantId: 'enterprise-corp', seq: i }
  });
}
const t1 = performance.now();

const elapsedSeconds = (t1 - t0) / 1000;
const throughput = TOTAL_EVENTS / elapsedSeconds;

console.log(`Time Elapsed: ${elapsedSeconds.toFixed(3)}s`);
console.log(`Throughput:   ${throughput.toFixed(2)} events/second`);
console.log(`Final Merkle Root: ${ledger.merkle.getRoot()}`);

// Clean up benchmark files
fs.rmSync(benchDir, { recursive: true, force: true });
