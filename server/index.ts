import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { JobStore } from './db.js';
import { AuditLog } from './audit.js';

// --- Server safety limits (env-configurable) -------------------------------
const BODY_LIMIT = Number(process.env.GHOSTWIRE_BODY_LIMIT_BYTES || (1 << 20));
const REQUEST_TIMEOUT_MS = Number(process.env.GHOSTWIRE_REQUEST_TIMEOUT_MS || 30_000);
const HANDLER_TIMEOUT_MS = Number(process.env.GHOSTWIRE_HANDLER_TIMEOUT_MS || 300_000);

function getMaxPcapBytes(): number {
  return Number(process.env.GHOSTWIRE_MAX_PCAP_BYTES || (500 * (1 << 20)));
}
function getAnalysisTimeoutMs(): number {
  return Number(process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS || 240_000);
}
const KILL_GRACE_MS = 5_000;
function getRateMax(): number {
  return Number(process.env.GHOSTWIRE_RATE_MAX || 20);
}
function getRateWindow(): string {
  return process.env.GHOSTWIRE_RATE_WINDOW || '1 minute';
}

const app = Fastify({
  logger: false,
  bodyLimit: BODY_LIMIT,
  requestTimeout: REQUEST_TIMEOUT_MS,
  handlerTimeout: HANDLER_TIMEOUT_MS,
});

app.register(cors, { origin: true });
app.register(rateLimit, {
  global: false,
  max: getRateMax(),
  timeWindow: getRateWindow(),
});

// --- Job store + audit log (Phase 3) - lazy singletons ----------------------
// Constructed on first use (not at import) so tests can point GHOSTWIRE_DATA_DIR
// at a tmp dir in before() and so importing the module has no filesystem side
// effects.
const PROJECT_ROOT = path.resolve(__dirname, '..');

function dataDir(): string {
  return process.env.GHOSTWIRE_DATA_DIR || path.join(PROJECT_ROOT, 'data');
}
function dbPath(): string {
  return process.env.GHOSTWIRE_DB_PATH || path.join(dataDir(), 'jobs.sqlite');
}
function auditPath(): string {
  return process.env.GHOSTWIRE_AUDIT_LOG || path.join(dataDir(), 'audit.jsonl');
}

let _jobs: JobStore | null = null;
let _audit: AuditLog | null = null;

export function getJobs(): JobStore {
  if (!_jobs) {
    fs.mkdirSync(dataDir(), { recursive: true });
    _jobs = new JobStore(dbPath());
  }
  return _jobs;
}
export function getAudit(): AuditLog {
  if (!_audit) {
    fs.mkdirSync(dataDir(), { recursive: true });
    _audit = new AuditLog(auditPath());
  }
  return _audit;
}

/** Test hook: drop cached singletons so a new env (tmp data dir) takes effect. */
export function _resetState(): void {
  try { _jobs?.close(); } catch { /* ignore */ }
  _jobs = null;
  _audit = null;
}

// --- Connected WebSocket clients (for job status broadcasts) ---------------
const wsClients = new Set<any>();
function broadcast(message: object): void {
  const data = JSON.stringify(message);
  for (const socket of wsClients) {
    try { socket.send(data); } catch { /* client gone */ }
  }
}

// Health check endpoint
app.get('/health', async () => ({ status: 'ok', version: '0.2.0' }));

// --- Auth middleware --------------------------------------------------------
const API_KEY = process.env.GHOSTWIRE_API_KEY || null;
const API_KEY_ID = API_KEY ? createHash('sha256').update(API_KEY).digest('hex').slice(0, 16) : null;

app.addHook('onRequest', async (request: any, reply: any) => {
  if (request.url === '/health') return;

  if (request.url === '/ws' || request.url.startsWith('/ws?')) {
    if (API_KEY) {
      const url = new URL(request.url, `http://${request.headers.host}`);
      const wsToken = url.searchParams.get('token');
      const auth = request.headers['authorization'];
      if (wsToken !== API_KEY && auth !== `Bearer ${API_KEY}`) {
        return reply.code(401).send({ error: 'Unauthorized. Provide ?token=<key> or Authorization header.' });
      }
    }
    return;
  }

  if (API_KEY) {
    const auth = request.headers['authorization'];
    if (!auth || auth !== `Bearer ${API_KEY}`) {
      return reply.code(401).send({ error: 'Unauthorized. Set Authorization: Bearer <key>' });
    }
  }
});

// --- Path validation --------------------------------------------------------
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];
const DEFAULT_ALLOWED_DIR = path.join(PROJECT_ROOT, 'samples');

function getAllowedDirs(): string[] {
  const dirs = (process.env.GHOSTWIRE_ALLOWED_DIRS || '')
    .split(':')
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => path.resolve(d));
  if (dirs.length === 0) {
    dirs.push(DEFAULT_ALLOWED_DIR);
  }
  return dirs;
}

function validateFilePath(filePath: string): string | null {
  const resolved = path.resolve(filePath);
  if (filePath.includes('..')) {
    return 'Path traversal rejected';
  }
  const allowed = getAllowedDirs().some(
    (dir) => resolved.startsWith(dir + path.sep) || resolved === dir,
  );
  if (!allowed) {
    return 'Access denied: file outside allowed directories. Configure GHOSTWIRE_ALLOWED_DIRS if needed.';
  }
  const ext = path.extname(resolved).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return `Unsupported file extension: ${ext}. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
  }
  try {
    fs.accessSync(resolved, fs.constants.R_OK);
  } catch {
    return `File not found or unreadable: ${resolved}`;
  }
  return null;
}

export function checkPcapSize(filePath: string, maxBytes?: number): { size: number } | { error: string } {
  const resolved = path.resolve(filePath);
  const cap = maxBytes ?? getMaxPcapBytes();
  try {
    const size = fs.statSync(resolved).size;
    if (size > cap) {
      return {
        error: `File too large: ${(size / (1 << 20)).toFixed(1)} MiB exceeds limit ${(cap / (1 << 20)).toFixed(0)} MiB. Configure GHOSTWIRE_MAX_PCAP_BYTES to raise it.`,
      };
    }
    return { size };
  } catch {
    return { error: `Cannot stat file: ${resolved}` };
  }
}

// --- Audit line builder (Phase 3.3) ----------------------------------------
function writeAuditLine(jobId: string, filePath: string, startedAt: number,
                        summaryJson: string | null, error: string | null): void {
  const duration_ms = Date.now() - startedAt;
  let counts = { packets_total: 0, beacons_detected: 0, c2_matches: 0, dns_threats: 0, top_threat_confidence: '' };
  if (summaryJson) {
    try {
      const s = JSON.parse(summaryJson);
      counts = {
        packets_total: s.packets_total ?? 0,
        beacons_detected: s.beacons_detected ?? 0,
        c2_matches: s.c2_matches ?? 0,
        dns_threats: s.dns_threats ?? 0,
        top_threat_confidence: s.threats?.length ? s.threats[0].confidence : '',
      };
    } catch { /* malformed summary -> zero counts, still audited */ }
  }
  getAudit().write({
    ts: new Date().toISOString(),
    api_key_id: API_KEY_ID,
    file_path: filePath,
    job_id: jobId,
    status: error ? 'failed' : 'completed',
    duration_ms,
    error,
    ...counts,
  });
}

// --- Async analysis runner (Phase 3.1) -------------------------------------
function runAnalysis(jobId: string, filePath: string, parser: string,
                     minScore: number, minPackets: number): void {
  getJobs().markStarted(jobId);
  broadcast({ type: 'job', id: jobId, status: 'running' });

  const venv = process.env.GHOSTWIRE_PYTHON_BIN || path.join(__dirname, '..', '.venv', 'bin', 'python3');
  const args = [
    '-m', 'engine.cli',
    'analyze', filePath,
    '--output', 'json',
    '--min-score', String(minScore),
    '--min-packets', String(minPackets),
    '--parser', parser,
  ];
  const startedAt = Date.now();
  const proc = spawn(venv, args, {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PYTHONPATH: path.join(__dirname, '..') },
  });

  let stdout = '';
  let stderr = '';
  let settled = false;
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const analysisTimeoutMs = getAnalysisTimeoutMs();

  const finish = (fn: () => void) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    if (killTimer) clearTimeout(killTimer);
    try { proc.kill(); } catch { /* dead */ }
    fn();
  };

  const timer = setTimeout(() => {
    if (settled) return;
    timedOut = true;
    console.error(`[GHOSTWIRE] Job ${jobId} timeout (${analysisTimeoutMs}ms); sending SIGTERM`);
    try { proc.kill('SIGTERM'); } catch { /* dead */ }
    killTimer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch { /* dead */ }
    }, KILL_GRACE_MS);
  }, analysisTimeoutMs);

  proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
  proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

  proc.on('error', (err: Error) => {
    console.error(`[GHOSTWIRE] Job ${jobId} spawn error: ${err.message}`);
    getJobs().markFailed(jobId, `spawn error: ${err.message}`);
    writeAuditLine(jobId, filePath, startedAt, null, err.message);
    broadcast({ type: 'job', id: jobId, status: 'failed', error: err.message });
    finish(() => {});
  });

  proc.on('close', (code: number) => {
    if (timedOut) {
      getJobs().markFailed(jobId, 'analysis timed out');
      writeAuditLine(jobId, filePath, startedAt, null, 'timeout');
      broadcast({ type: 'job', id: jobId, status: 'failed', error: 'timed out' });
      finish(() => {});
      return;
    }
    if (code !== 0) {
      console.error(`[GHOSTWIRE] Job ${jobId} failed (exit ${code}): ${stderr}`);
      getJobs().markFailed(jobId, 'analysis failed');
      writeAuditLine(jobId, filePath, startedAt, null, `exit ${code}`);
      broadcast({ type: 'job', id: jobId, status: 'failed', error: 'analysis failed' });
      finish(() => {});
      return;
    }
    try {
      JSON.parse(stdout);
    } catch {
      getJobs().markFailed(jobId, 'malformed analysis output');
      writeAuditLine(jobId, filePath, startedAt, null, 'malformed output');
      broadcast({ type: 'job', id: jobId, status: 'failed', error: 'malformed output' });
      finish(() => {});
      return;
    }
    getJobs().markCompleted(jobId, stdout);
    writeAuditLine(jobId, filePath, startedAt, stdout, null);
    broadcast({ type: 'job', id: jobId, status: 'completed' });
    finish(() => {});
  });
}

// --- Routes -----------------------------------------------------------------
app.post('/api/analyze', {
  config: { rateLimit: { max: getRateMax(), timeWindow: getRateWindow() } },
}, async (request: any, reply: any) => {
  const body = request.body || {};
  const { filePath, parser = 'auto' } = body;
  const minScore = typeof body.minScore === 'number' ? body.minScore : 0.1;
  const minPackets = Number.isInteger(body.minPackets) ? body.minPackets : 5;
  if (!['auto', 'dpkt', 'scapy'].includes(parser)) {
    return reply.code(400).send({ error: "parser must be 'auto', 'dpkt', or 'scapy'" });
  }
  if (typeof minScore !== 'number' || minScore < 0 || minScore > 1) {
    return reply.code(400).send({ error: 'minScore must be a number in [0, 1]' });
  }
  if (typeof minPackets !== 'number' || minPackets < 1) {
    return reply.code(400).send({ error: 'minPackets must be a positive integer' });
  }
  if (!filePath || typeof filePath !== 'string') {
    return reply.code(400).send({ error: 'filePath is required' });
  }

  const pathError = validateFilePath(filePath);
  if (pathError) {
    return reply.code(400).send({ error: pathError });
  }

  const sizeCheck = checkPcapSize(filePath);
  if ('error' in sizeCheck) {
    return reply.code(413).send({ error: sizeCheck.error });
  }

  // Create the job, kick off the analysis asynchronously, return the jobId.
  // Concurrent POSTs now get distinct jobIds and do not clobber each other. (3.1)
  const jobId = getJobs().createJob(filePath);
  runAnalysis(jobId, filePath, parser, minScore, minPackets);
  return reply.code(202).send({ jobId, status: 'queued', filePath });
});

function safeParse(s: string): any {
  try { return JSON.parse(s); } catch { return null; }
}

app.get('/api/jobs', async (_request: any, reply: any) => {
  const rows = getJobs().list();
  return reply.send({ jobs: rows.map((r) => ({ ...r, summary: r.summary_json ? safeParse(r.summary_json) : null })) });
});

app.get('/api/jobs/:id', async (request: any, reply: any) => {
  const row = getJobs().get(request.params.id);
  if (!row) {
    return reply.code(404).send({ error: 'Job not found' });
  }
  return reply.send({ ...row, summary: row.summary_json ? safeParse(row.summary_json) : null });
});

// Back-compat: the latest completed job's summary (replaces the old
// single-slot currentAnalysis). 404 if nothing has completed yet.
app.get('/api/analysis', async (_request: any, reply: any) => {
  const list = getJobs().list();
  const done = list.find((r) => r.status === 'completed' && r.summary_json);
  if (!done) {
    return reply.code(404).send({ error: 'No completed analysis available yet.' });
  }
  return reply.send(safeParse(done.summary_json!));
});

// --- WebSocket -------------------------------------------------------------
// Serve the built dashboard static assets at / (Phase 5 single-image deploy).
// Only registered when the build dir exists, so dev (Vite) and tests are unaffected.
const DASHBOARD_DIR = process.env.GHOSTWIRE_DASHBOARD_DIR || path.join(PROJECT_ROOT, 'dashboard', 'dist');
if (fs.existsSync(DASHBOARD_DIR)) {
  app.register(import('@fastify/static'), {
    root: DASHBOARD_DIR,
    prefix: '/',
    decorateReply: false,
  });
}

app.register(import('@fastify/websocket'));
app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection: any, _req: any) => {
    wsClients.add(connection.socket);
    const list = getJobs().list();
    if (list.length) {
      connection.socket.send(JSON.stringify({ type: 'job', id: list[0].id, status: list[0].status }));
    }
    connection.socket.on('message', (message: Buffer) => {
      try {
        const msg = JSON.parse(message.toString());
        if (msg.type === 'ping') {
          connection.socket.send(JSON.stringify({ type: 'pong' }));
        }
      } catch { /* ignore */ }
    });
    connection.socket.on('close', () => { wsClients.delete(connection.socket); });
  });
});

// --- Start -----------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.GHOSTWIRE_HOST || '127.0.0.1';
const isLoopback = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
if (!isLoopback && !API_KEY) {
  console.error(`REFUSING TO START: GHOSTWIRE_HOST is non-loopback (${HOST}) but GHOSTWIRE_API_KEY is unset.`);
  console.error('A network-exposed server with no auth is fail-open. Set GHOSTWIRE_API_KEY or bind 127.0.0.1.');
  process.exit(1);
}

async function start() {
  getJobs(); getAudit();  // ensure data dir + db exist
  await app.listen({ port: PORT, host: HOST });
  console.log(`GHOSTWIRE API server running on http://${HOST}:${PORT}`);
  console.log(`WebSocket available at ws://${HOST}:${PORT}/ws`);
  console.log(`PCAP allowlist: ${getAllowedDirs().join(':')}`);
  console.log(`Job store: ${dbPath()}`);
  console.log(`Audit log: ${auditPath()}`);
  console.log(`Limits: body=${(BODY_LIMIT / (1 << 20)).toFixed(1)}MiB, max-pcap=${(getMaxPcapBytes() / (1 << 20)).toFixed(0)}MiB, analysis-timeout=${(getAnalysisTimeoutMs() / 1000).toFixed(0)}s, rate=${getRateMax()}/${getRateWindow()}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  start();
}

export { app };