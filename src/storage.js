import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

/**
 * Crash-resilient append-only Write-Ahead Log (WAL) with SHA-256 checksums per record.
 */
export class AppendOnlyStorage {
  constructor(storageDir) {
    this.storageDir = storageDir;
    this.logPath = path.join(storageDir, 'audit_ledger.wal');
    this.indexPath = path.join(storageDir, 'audit_index.wal');
    fs.mkdirSync(storageDir, { recursive: true });

    this.index = [];
    this.loadIndex();
  }

  loadIndex() {
    if (fs.existsSync(this.indexPath)) {
      try {
        const lines = fs.readFileSync(this.indexPath, 'utf8').trim().split('\n').filter(Boolean);
        this.index = lines.map(l => JSON.parse(l));
      } catch (e) {
        this.index = [];
      }
    }
  }

  appendRecord(record) {
    const serialized = JSON.stringify(record);
    const checksum = createHash('sha256').update(serialized).digest('hex');
    const line = JSON.stringify({ checksum, record }) + '\n';

    const currentOffset = fs.existsSync(this.logPath) ? fs.statSync(this.logPath).size : 0;
    fs.appendFileSync(this.logPath, line, 'utf8');

    const entry = {
      id: record.id,
      offset: currentOffset,
      length: Buffer.byteLength(line, 'utf8'),
      checksum
    };
    this.index.push(entry);
    fs.appendFileSync(this.indexPath, JSON.stringify(entry) + '\n', 'utf8');
    return entry;
  }

  readAllRecords() {
    if (!fs.existsSync(this.logPath)) return [];
    const lines = fs.readFileSync(this.logPath, 'utf8').trim().split('\n').filter(Boolean);
    const records = [];

    for (const line of lines) {
      const parsed = JSON.parse(line);
      const computed = createHash('sha256').update(JSON.stringify(parsed.record)).digest('hex');
      if (computed !== parsed.checksum) {
        throw new Error(`FATAL: Tamper detected in record ${parsed.record.id}! Checksum mismatch.`);
      }
      records.push(parsed.record);
    }
    return records;
  }

  getRecordById(id) {
    const entry = this.index.find(e => e.id === id);
    if (!entry) return null;

    const fd = fs.openSync(this.logPath, 'r');
    const buffer = Buffer.alloc(entry.length);
    fs.readSync(fd, buffer, 0, entry.length, entry.offset);
    fs.closeSync(fd);

    const parsed = JSON.parse(buffer.toString('utf8').trim());
    return parsed.record;
  }
}
