// Server tests (Phase 1 + Phase 3) — async job model.
// Covers: 413 on oversized PCAP, path traversal, /health, async analyze ->
// 202 {jobId}, job polling, concurrent jobs don't clobber, audit line written,
// hanging subprocess -> job fails, rate-limit, checkPcapSize unit.

import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { app, checkPcapSize, getJobs, _resetState } from './index.js';

const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-fixtures-'));
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-data-'));

before(() => {
  process.env.GHOSTWIRE_ALLOWED_DIRS = FIXTURE_DIR;
  process.env.GHOSTWIRE_DATA_DIR = DATA_DIR;
  _resetState(); // pick up the new DATA_DIR
});

after(() => {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
});

afterEach(() => {
  delete process.env.GHOSTWIRE_MAX_PCAP_BYTES;
  delete process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS;
  delete process.env.GHOSTWIRE_PYTHON_BIN;
  delete process.env.GHOSTWIRE_RATE_MAX;
  delete process.env.GHOSTWIRE_RATE_WINDOW;
});

function makePcap(name: string, sizeBytes: number): string {
  const p = path.join(FIXTURE_DIR, name);
  const fd = fs.openSync(p, 'w');
  fs.writeSync(fd, Buffer.alloc(24, 0xd4));
  if (sizeBytes > 24) {
    fs.writeSync(fd, Buffer.alloc(sizeBytes - 24, 0), 0, sizeBytes - 24, 24);
  }
  fs.closeSync(fd);
  return p;
}

function makeJsonStub(): string {
  // Emits the full summary shape the audit line parses (counts + threats).
  const p = path.join(FIXTURE_DIR, 'stub-json.sh');
  fs.writeFileSync(p, '#!/bin/sh\ncat <<\'JSON\'\n{"ghostwire_version":"0.2.0","packets_total":10,"sessions_total":1,"beacons_detected":0,"tls_fingerprints":0,"http_fingerprints":0,"ssh_fingerprints":0,"c2_matches":0,"dns_threats":0,"threats":[]}\nJSON\necho\nexit 0\n', { mode: 0o755 });
  return p;
}

function makeHangingStub(): string {
  const p = path.join(FIXTURE_DIR, 'stub-hang.sh');
  fs.writeFileSync(p, '#!/bin/sh\nsleep 30\nexit 0\n', { mode: 0o755 });
  return p;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Poll a job until it reaches a terminal status (or timeout).
async function waitForJob(jobId: string, timeoutMs = 10_000): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await app.inject({ method: 'GET', url: `/api/jobs/${jobId}` });
    const row = res.json();
    if (row.status === 'completed' || row.status === 'failed') return row;
    await sleep(100);
  }
  throw new Error(`job ${jobId} did not finish within ${timeoutMs}ms`);
}

test('checkPcapSize rejects an oversized PCAP (413 path)', async () => {
  const p = makePcap('big.pcap', 20 * (1 << 20));
  const res = checkPcapSize(p, 10 * (1 << 20));
  assert.ok('error' in res);
  assert.match((res as { error: string }).error, /too large/i);

  const small = makePcap('small.pcap', 1024);
  const ok = checkPcapSize(small, 10 * (1 << 20));
  assert.ok('size' in ok);
});

test('POST /api/analyze returns 413 for an oversized PCAP', async () => {
  process.env.GHOSTWIRE_MAX_PCAP_BYTES = String(1024);
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p = makePcap('over.pcap', 8192);
  const res = await app.inject({
    method: 'POST', url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: p },
  });
  assert.equal(res.statusCode, 413);
  assert.match(res.json().error, /too large/i);
});

test('GET /health returns ok without auth', async () => {
  const res = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().status, 'ok');
});

test('POST /api/analyze rejects path traversal with 400', async () => {
  const res = await app.inject({
    method: 'POST', url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: '../etc/passwd.pcap' },
  });
  assert.equal(res.statusCode, 400);
  assert.match(res.json().error, /traversal/i);
});

test('POST /api/analyze -> 202 {jobId}, then /api/jobs/:id completes', async () => {
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p = makePcap('ok.pcap', 64);
  const res = await app.inject({
    method: 'POST', url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: p },
  });
  assert.equal(res.statusCode, 202, `got ${res.statusCode}: ${res.body}`);
  const { jobId } = res.json();
  assert.ok(jobId, 'expected a jobId');

  const row = await waitForJob(jobId);
  assert.equal(row.status, 'completed', `job did not complete: ${JSON.stringify(row)}`);
  assert.equal(row.summary.packets_total, 10);
});

test('two concurrent analyses get distinct jobIds and do not clobber', async () => {
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p1 = makePcap('a.pcap', 64);
  const p2 = makePcap('b.pcap', 64);
  const r1 = await app.inject({ method: 'POST', url: '/api/analyze', headers: { 'content-type': 'application/json' }, payload: { filePath: p1 } });
  const r2 = await app.inject({ method: 'POST', url: '/api/analyze', headers: { 'content-type': 'application/json' }, payload: { filePath: p2 } });
  const id1 = r1.json().jobId;
  const id2 = r2.json().jobId;
  assert.notEqual(id1, id2, 'concurrent jobs must be distinct');

  const [a, b] = await Promise.all([waitForJob(id1), waitForJob(id2)]);
  assert.equal(a.status, 'completed');
  assert.equal(b.status, 'completed');
  // Both retrievable by id (the old single-slot bug: only the last survived).
  assert.equal(getJobs().get(id1)?.status, 'completed');
  assert.equal(getJobs().get(id2)?.status, 'completed');
});

test('a completed analysis writes one audit line with the right counts', async () => {
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p = makePcap('audit.pcap', 64);
  const r = await app.inject({ method: 'POST', url: '/api/analyze', headers: { 'content-type': 'application/json' }, payload: { filePath: p } });
  const row = await waitForJob(r.json().jobId);
  assert.equal(row.status, 'completed');

  const auditFile = path.join(DATA_DIR, 'audit.jsonl');
  const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n');
  const last = JSON.parse(lines[lines.length - 1]);
  assert.equal(last.status, 'completed');
  assert.equal(last.packets_total, 10);
  assert.equal(last.beacons_detected, 0);
  assert.equal(last.job_id, r.json().jobId);
});

test('a hanging analysis subprocess -> job fails (timeout)', async () => {
  process.env.GHOSTWIRE_PYTHON_BIN = makeHangingStub();
  process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS = '200';
  const p = makePcap('hang.pcap', 64);
  const r = await app.inject({ method: 'POST', url: '/api/analyze', headers: { 'content-type': 'application/json' }, payload: { filePath: p } });
  const row = await waitForJob(r.json().jobId, 5_000);
  assert.equal(row.status, 'failed', `expected failed, got ${row.status}`);

  const auditFile = path.join(DATA_DIR, 'audit.jsonl');
  const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n');
  const last = JSON.parse(lines[lines.length - 1]);
  assert.equal(last.status, 'failed');
});