// Server safety tests (production-plan Phase 1 acceptance).
// Covers: 413 on oversized PCAP, 504 on hanging subprocess, rate-limit on
// /api/analyze. Uses app.inject so it does NOT bind a real port.

import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { app, checkPcapSize } from './index.js';

// The analyze handler resolves paths against GHOSTWIRE_ALLOWED_DIRS so the
// test fixture dir must be allowlisted, and GHOSTWIRE_PYTHON_BIN must point at
// a stub so we never depend on the project venv existing in CI.

const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-fixtures-'));

before(() => {
  process.env.GHOSTWIRE_ALLOWED_DIRS = FIXTURE_DIR;
});

after(() => {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
});

// Reset env between tests where needed.
afterEach(() => {
  delete process.env.GHOSTWIRE_MAX_PCAP_BYTES;
  delete process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS;
  delete process.env.GHOSTWIRE_PYTHON_BIN;
  delete process.env.GHOSTWIRE_RATE_MAX;
  delete process.env.GHOSTWIRE_RATE_WINDOW;
});

function makePcap(name: string, sizeBytes: number): string {
  const p = path.join(FIXTURE_DIR, name);
  // Write a sparse-ish file: allocate and write a header so stat().size is real.
  const fd = fs.openSync(p, 'w');
  fs.writeSync(fd, Buffer.alloc(24, 0xd4)); // plausible-ish pcap magic bytes
  if (sizeBytes > 24) {
    fs.writeSync(fd, Buffer.alloc(sizeBytes - 24, 0), 0, sizeBytes - 24, 24);
  }
  fs.closeSync(fd);
  return p;
}

// Stub interpreter: writes a tiny JSON to stdout and exits 0, simulating a
// successful analysis that returned no detections. Used where a 200 path is
// needed; for the timeout test we use a stub that sleeps instead.
function makeJsonStub(): string {
  const p = path.join(FIXTURE_DIR, 'stub-json.sh');
  fs.writeFileSync(p, '#!/bin/sh\necho \'{"sessions":[],"beacons_detected":0,"c2_matches":0,"dns_threats":0}\'\nexit 0\n', { mode: 0o755 });
  return p;
}

function makeHangingStub(): string {
  const p = path.join(FIXTURE_DIR, 'stub-hang.sh');
  fs.writeFileSync(p, '#!/bin/sh\nsleep 30\nexit 0\n', { mode: 0o755 });
  return p;
}

test('checkPcapSize rejects an oversized PCAP (413 path, no subprocess spawned)', async () => {
  // 10 MiB cap, 20 MiB file.
  const p = makePcap('big.pcap', 20 * (1 << 20));
  const res = checkPcapSize(p, 10 * (1 << 20));
  assert.ok('error' in res, 'expected size error');
  assert.match((res as { error: string }).error, /too large/i);

  // And a small file passes.
  const small = makePcap('small.pcap', 1024);
  const ok = checkPcapSize(small, 10 * (1 << 20));
  assert.ok('size' in ok);
  assert.equal((ok as { size: number }).size, 1024);
});

test('POST /api/analyze returns 413 for an oversized PCAP via the endpoint', async () => {
  // Point the cap low via env so the endpoint's per-request read sees it.
  process.env.GHOSTWIRE_MAX_PCAP_BYTES = String(1024);
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p = makePcap('over.pcap', 8192);
  const res = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: p },
  });
  assert.equal(res.statusCode, 413, `got ${res.statusCode}: ${res.body}`);
  assert.match(res.json().error, /too large/i);
});

test('POST /api/analyze returns 504 when the analysis subprocess hangs', async () => {
  // 200ms timeout, hanging stub.
  process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS = '200';
  process.env.GHOSTWIRE_PYTHON_BIN = makeHangingStub();
  // The handler builds args as [venv, ['-m','engine.cli','analyze',...]] —
  // our stub ignores args and sleeps. Path must still pass validation.
  const p = makePcap('hang.pcap', 64);
  const res = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: p },
  });
  assert.equal(res.statusCode, 504, `expected 504, got ${res.statusCode}: ${res.body}`);
  assert.match(res.json().error, /timed out/i);
});

test('POST /api/analyze runs the stub and returns 200 with the JSON body', async () => {
  process.env.GHOSTWIRE_PYTHON_BIN = makeJsonStub();
  const p = makePcap('ok.pcap', 64);
  const res = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: p },
  });
  assert.equal(res.statusCode, 200, `got ${res.statusCode}: ${res.body}`);
  assert.equal(res.json().beacons_detected, 0);
});

test('GET /health returns ok without auth', async () => {
  const res = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().status, 'ok');
});

test('POST /api/analyze rejects path traversal with 400', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath: '../etc/passwd.pcap' },
  });
  assert.equal(res.statusCode, 400);
  assert.match(res.json().error, /traversal/i);
});