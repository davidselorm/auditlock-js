import http from 'node:http';
import { AuditLedger } from './ledger.js';

const PORT = process.env.PORT || 8080;
const ledger = new AuditLedger();

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data, null, 2));
}

export const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  try {
    // Healthcheck
    if (method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, { status: 'HEALTHY', engine: 'auditlock-js' });
    }

    // Ingest Event
    if (method === 'POST' && url.pathname === '/api/v1/events') {
      const body = await parseBody(req);
      if (!body.actor || !body.action || !body.resource) {
        return sendJson(res, 400, { error: 'Missing required fields: actor, action, resource' });
      }
      const result = ledger.record(body);
      return sendJson(res, 201, result);
    }

    // Get Merkle Root & Signed Receipt
    if (method === 'GET' && url.pathname === '/api/v1/root') {
      const root = ledger.merkle.getRoot();
      const receipt = ledger.signer.signRoot(root, ledger.events.length, new Date().toISOString());
      return sendJson(res, 200, receipt);
    }

    // Get Event by ID
    if (method === 'GET' && url.pathname.startsWith('/api/v1/events/')) {
      const id = url.pathname.split('/')[4];
      const record = ledger.storage.getRecordById(id);
      if (!record) return sendJson(res, 404, { error: 'Event not found' });
      return sendJson(res, 200, record);
    }

    // Get Cryptographic Inclusion Proof
    if (method === 'GET' && url.pathname.startsWith('/api/v1/proofs/inclusion/')) {
      const id = url.pathname.split('/')[5];
      try {
        const proof = ledger.getInclusionProof(id);
        return sendJson(res, 200, proof);
      } catch (e) {
        return sendJson(res, 404, { error: e.message });
      }
    }

    // Export Compliance Bundle
    if (method === 'GET' && url.pathname === '/api/v1/export') {
      const bundle = ledger.exportComplianceBundle();
      return sendJson(res, 200, bundle);
    }

    sendJson(res, 404, { error: 'Route not found' });
  } catch (err) {
    sendJson(res, 500, { error: err.message });
  }
});

if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  server.listen(PORT, () => {
    console.log(`[AuditLock] Cryptographic Audit Ledger API running on http://localhost:${PORT}`);
  });
}
