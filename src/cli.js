#!/usr/bin/env node
import { AuditLedger } from './ledger.js';
import { server } from './server.js';
import fs from 'node:fs';

const args = process.argv.slice(2);
const command = args[0];

const ledger = new AuditLedger();

function printHelp() {
  console.log(`
AuditLock CLI - Tamper-Evident Cryptographic Audit Ledger

Usage:
  auditlock log --actor <name> --action <action> --resource <res>
  auditlock verify --id <eventId>
  auditlock root
  auditlock export --out <file.json>
  auditlock serve [--port <number>]
`);
}

switch (command) {
  case 'log': {
    let actor = 'system';
    let action = 'event';
    let resource = 'generic';

    for (let i = 1; i < args.length; i += 2) {
      if (args[i] === '--actor') actor = args[i + 1];
      if (args[i] === '--action') action = args[i + 1];
      if (args[i] === '--resource') resource = args[i + 1];
    }

    const res = ledger.record({ actor, action, resource });
    console.log(`[AUDIT RECORDED] ID: ${res.event.id}`);
    console.log(`Leaf Hash:   ${res.leafHash}`);
    console.log(`Merkle Root: ${res.receipt.root}`);
    console.log(`Signature:   ${res.receipt.signature.slice(0, 32)}...`);
    break;
  }

  case 'verify': {
    let id = null;
    for (let i = 1; i < args.length; i += 2) {
      if (args[i] === '--id') id = args[i + 1];
    }
    if (!id) {
      console.error('Error: specify --id <eventId>');
      process.exit(1);
    }
    const isValid = ledger.verifyEvent(id);
    if (isValid) {
      console.log(`[VERIFIED] Event ${id} is cryptographically valid and untampered!`);
    } else {
      console.error(`[FAILED] Cryptographic verification failed for event ${id}!`);
      process.exit(1);
    }
    break;
  }

  case 'root': {
    const root = ledger.merkle.getRoot();
    console.log(`Tree Size:   ${ledger.events.length}`);
    console.log(`Merkle Root: ${root || 'Empty tree'}`);
    break;
  }

  case 'export': {
    let out = 'audit_bundle.json';
    for (let i = 1; i < args.length; i += 2) {
      if (args[i] === '--out') out = args[i + 1];
    }
    const bundle = ledger.exportComplianceBundle();
    fs.writeFileSync(out, JSON.stringify(bundle, null, 2), 'utf8');
    console.log(`[EXPORTED] Compliance audit package written to ${out} (${bundle.treeSize} events)`);
    break;
  }

  case 'serve': {
    const port = process.env.PORT || 8080;
    server.listen(port, () => {
      console.log(`[AuditLock Server] Listening on http://localhost:${port}`);
    });
    break;
  }

  default:
    printHelp();
    break;
}
