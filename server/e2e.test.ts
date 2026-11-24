// End-to-end workflow: real Python engine → Fastify job → stored result → API.
//
// The 0.2.x success-path tests substituted a shell stub for the engine, which
// proved the plumbing but never that a real capture produces the evidence the
// API promises. These tests invoke the engine for real. They are skipped (with
// a reason) when the virtualenv or the fixtures cannot be built, so `npm test`
// still works on a Node-only checkout.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { app, getJobs, _resetState } from './index.js';

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PYTHON = process.env.GHOSTWIRE_E2E_PYTHON
  || path.join(PROJECT_ROOT, '.venv', 'bin', 'python3');

const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-e2e-fixtures-'));
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-e2e-data-'));

const DNS_DOMAIN = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil.com';
const CS_UA = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)';

const BUILD_FIXTURES = `
import sys
sys.path.insert(0, ${JSON.stringify(PROJECT_ROOT)})
from scapy.all import wrpcap
from tests.conftest import _build_dns_packets, _build_c2_http_packets
wrpcap(${JSON.stringify(path.join(FIXTURE_DIR, 'dns.pcap'))}, _build_dns_packets())
wrpcap(${JSON.stringify(path.join(FIXTURE_DIR, 'http.pcap'))}, _build_c2_http_packets())
`;

let engineReady = false;
let skipReason = '';
const dnsPcap = path.join(FIXTURE_DIR, 'dns.pcap');
const httpPcap = path.join(FIXTURE_DIR, 'http.pcap');

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function submit(filePath: string): Promise<string> {
  const res = await app.inject({
    method: 'POST', url: '/api/analyze',
    headers: { 'content-type': 'application/json' },
    payload: { filePath },
  });
  assert.equal(res.statusCode, 202, res.body);
  return res.json().jobId;
}

async function waitForJob(jobId: string, timeoutMs = 120_000): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await app.inject({ method: 'GET', url: `/api/jobs/${jobId}` });
    const row = res.json();
    if (row.status === 'completed' || row.status === 'failed') return row;
    await sleep(200);
  }
  throw new Error(`job ${jobId} did not finish within ${timeoutMs}ms`);
}

async function completedResult(jobId: string): Promise<any> {
  const res = await app.inject({ method: 'GET', url: `/api/jobs/${jobId}/result` });
  assert.equal(res.statusCode, 200, res.body);
  return res.json();
}

function cliAnalysis(filePath: string): any {
  const proc = spawnSync(
    PYTHON,
    ['-m', 'engine.cli', 'analyze', filePath, '--output', 'json',
      '--min-score', '0.25', '--min-packets', '10'],
    { cwd: PROJECT_ROOT, encoding: 'utf8', timeout: 120_000 },
  );
  assert.equal(proc.status, 0, proc.stderr);
  return JSON.parse(proc.stdout);
}

before(() => {
  if (!fs.existsSync(PYTHON)) {
    skipReason = `real engine unavailable (${PYTHON} not found)`;
    return;
  }
  const build = spawnSync(PYTHON, ['-c', BUILD_FIXTURES], {
    cwd: PROJECT_ROOT, encoding: 'utf8', timeout: 120_000,
  });
  if (build.status !== 0) {
    skipReason = `could not build fixtures: ${build.stderr}`;
    return;
  }
  process.env.GHOSTWIRE_ALLOWED_DIRS = FIXTURE_DIR;
  process.env.GHOSTWIRE_DATA_DIR = DATA_DIR;
  process.env.GHOSTWIRE_PYTHON_BIN = PYTHON;
  _resetState();
  engineReady = true;
});

after(() => {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
});

test('real engine: DNS-only capture through the API keeps the observed domain', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const jobId = await submit(dnsPcap);
  const row = await waitForJob(jobId);
  assert.equal(row.status, 'completed', row.error);
  assert.equal(row.schema_version, '1.0');
  assert.equal(row.engine_version, '0.3.0');
  assert.equal(row.capture_sha256,
    'a2f6299ae1ab35675896658119ce0bf6f4265adcf8076a875463730de5ad9ff8');

  const payload = await completedResult(jobId);
  assert.equal(payload.compatibility.status, 'current');
  const result = payload.result;

  assert.equal(result.schema_version, '1.0');
  assert.equal(result.packets_total, 1);
  assert.equal(result.sessions_total, 0);
  assert.equal(result.coverage.status, 'complete');
  assert.equal(result.run.capture.parser_used, 'dpkt');
  assert.equal(result.selection.counts.sessions_total, 0);

  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.kind, 'dns');
  assert.equal(finding.subject.value, DNS_DOMAIN);
  assert.equal(finding.rule.id, 'dns.tunneling_heuristic');
  assert.equal(finding.reasons.length, 2);

  const obs = result.observations.find(
    (o: any) => o.observation_id === finding.observation_ids[0],
  );
  assert.equal(obs.frame, 1);
  assert.equal(obs.field, 'dns.query_name');
  assert.equal(obs.value, DNS_DOMAIN);
  assert.equal(obs.src.ip, '192.168.1.50');
  assert.equal(obs.dst.ip, '8.8.8.8');

  // 0.2.x fields still present for an older client.
  assert.equal(result.dns_threats, 1);
  assert.deepEqual(result.threats, []);
  assert.equal(result.protocol_counts.DNS, 1);
});

test('real engine: HTTP capture keeps the header and the 0.315 score', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const jobId = await submit(httpPcap);
  const row = await waitForJob(jobId);
  assert.equal(row.status, 'completed', row.error);

  const result = (await completedResult(jobId)).result;
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.kind, 'http_header');
  assert.equal(finding.subject.value, CS_UA);
  assert.equal(finding.rule.id, 'c2.http_user_agent_exact');
  assert.equal(finding.score, 0.9);

  assert.equal(result.threats.length, 1);
  assert.equal(result.threats[0].overall_score, 0.315);
  assert.equal(result.threats[0].confidence, 'LOW');
  assert.equal(result.threats[0].finding_ids[0], finding.finding_id);
  assert.equal(result.c2_matches, 1);
  // No "Known C2" wording; the match is described as an inference.
  assert.match(result.threats[0].summary, /rule/i);
  assert.doesNotMatch(result.threats[0].summary, /Known C2/);

  const obs = result.observations.find(
    (o: any) => o.observation_id === finding.observation_ids[0],
  );
  assert.equal(obs.frame, 1);
  assert.equal(obs.field, 'http.header.user-agent');
  assert.equal(obs.value, CS_UA);
  assert.equal(obs.src.role, 'client');
  assert.equal(obs.dst.role, 'server');
});

test('real engine: API result matches the CLI for identical options', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const jobId = await submit(httpPcap);
  await waitForJob(jobId);
  const api = (await completedResult(jobId)).result;
  const cli = cliAnalysis(httpPcap);

  const scrubRun = (findings: any[]) => findings.map((f) => ({
    finding_id: f.finding_id,
    rule: f.rule.id,
    subject: f.subject.value,
    score: f.score,
    observation_frames: f.observation_ids.length,
  }));
  assert.deepEqual(scrubRun(api.findings), scrubRun(cli.findings));

  assert.deepEqual(
    api.threats.map((x: any) => [x.target, x.overall_score, x.confidence]),
    cli.threats.map((x: any) => [x.target, x.overall_score, x.confidence]),
  );
  assert.equal(api.run.capture.sha256, httpPcapSha(cli));
  assert.deepEqual(api.selection.counts, cli.selection.counts);
  assert.equal(api.coverage.status, cli.coverage.status);
});

function httpPcapSha(cli: any): string {
  return cli.capture_sha256;
}

test('reanalysis creates a separate run and leaves the first result intact', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const jobId = await submit(httpPcap);
  await waitForJob(jobId);
  const before = (await completedResult(jobId)).result;

  const res = await app.inject({
    method: 'POST', url: `/api/jobs/${jobId}/reanalyze`,
    headers: { 'content-type': 'application/json' },
    payload: { minScore: 0.32 },
  });
  assert.equal(res.statusCode, 202, res.body);
  const { jobId: rerunId, parentJobId, capture_identity_verified } = res.json();
  assert.notEqual(rerunId, jobId);
  assert.equal(parentJobId, jobId);
  assert.equal(capture_identity_verified, true);

  const rerun = await waitForJob(rerunId);
  assert.equal(rerun.status, 'completed');
  const rerunResult = (await completedResult(rerunId)).result;

  // Same capture, same evidence, different selection threshold.
  assert.equal(rerunResult.capture_sha256, before.capture_sha256);
  assert.deepEqual(
    rerunResult.findings.map((f: any) => f.finding_id),
    before.findings.map((f: any) => f.finding_id),
  );
  assert.equal(rerunResult.selection.filter.min_score, 0.32);
  assert.equal(rerunResult.selection.counts.sessions_eligible, 0);
  assert.deepEqual(rerunResult.threats, []);

  // The original row is untouched.
  const original = await waitForJob(jobId);
  const originalResult = (await completedResult(jobId)).result;
  assert.equal(original.status, 'completed');
  assert.deepEqual(originalResult.threats, before.threats);
  assert.equal(originalResult.selection.filter.min_score, 0.25);
});

test('a stored legacy 0.2.x summary opens with recorded values and explicit gaps', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const legacy = {
    ghostwire_version: '0.2.0',
    file: dnsPcap,
    analysis_time: 0,
    packets_total: 1,
    sessions_total: 0,
    tls_fingerprints: 0,
    http_fingerprints: 0,
    ssh_fingerprints: 0,
    beacons_detected: 0,
    dns_threats: 1,
    c2_matches: 0,
    threats: [],
  };
  const jobs = getJobs();
  const id = jobs.createJob(dnsPcap);
  jobs.markCompleted(id, JSON.stringify(legacy));

  const res = await app.inject({ method: 'GET', url: `/api/jobs/${id}` });
  assert.equal(res.statusCode, 200);
  const row = res.json();
  assert.equal(row.compatibility.status, 'legacy');
  assert.match(row.compatibility.message, /Unversioned 0\.2\.x/);
  assert.equal(row.result.dns_threats, 1);
  assert.equal(row.result.packets_total, 1);
  assert.equal(row.result.findings, null);
  assert.ok(row.compatibility.detail_unavailable.includes('coverage'));

  // The raw payload is still there for an older client.
  assert.deepEqual(row.summary, legacy);

  const resultRes = await app.inject({ method: 'GET', url: `/api/jobs/${id}/result` });
  assert.equal(resultRes.statusCode, 200);
  const payload = resultRes.json();
  assert.equal(payload.compatibility.status, 'legacy');
  assert.equal(payload.result.dns_threats, 1);
});

test('an unknown future schema is reported as unsupported and preserved', async (t) => {
  if (!engineReady) return t.skip(skipReason);
  const future = { schema_version: '99.0', mystery: { value: 1 } };
  const jobs = getJobs();
  const id = jobs.createJob(dnsPcap);
  jobs.markCompleted(id, JSON.stringify(future));

  const res = await app.inject({ method: 'GET', url: `/api/jobs/${id}/result` });
  assert.equal(res.statusCode, 200);
  const payload = res.json();
  assert.equal(payload.compatibility.status, 'unsupported');
  assert.equal(payload.compatibility.original_preserved, true);
  assert.deepEqual(payload.result.original, future);
});

test('analysis defaults are advertised and enforced', async () => {
  const res = await app.inject({ method: 'GET', url: '/health' });
  const health = res.json();
  assert.equal(health.version, '0.3.0');
  assert.equal(health.result_schema_version, '1.0');
  assert.equal(health.analysis_defaults.minScore, 0.25);
  assert.equal(health.analysis_defaults.minPackets, 10);
});
