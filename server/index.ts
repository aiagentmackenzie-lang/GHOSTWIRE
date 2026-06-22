import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { pathToFileURL } from 'url';

// ─── Server safety limits (env-configurable) ──────────────────────────────
// bodyLimit caps request body size (JSON metadata, not the PCAP itself —
// PCAPs are referenced by path, not uploaded). requestTimeout/handlerTimeout
// bound how long we hold a connection / run a handler before tearing it down.
const BODY_LIMIT = Number(process.env.GHOSTWIRE_BODY_LIMIT_BYTES || (1 << 20)); // 1 MiB
const REQUEST_TIMEOUT_MS = Number(process.env.GHOSTWIRE_REQUEST_TIMEOUT_MS || 30_000);
const HANDLER_TIMEOUT_MS = Number(process.env.GHOSTWIRE_HANDLER_TIMEOUT_MS || 300_000);

// Max PCAP size we will analyze. Default 500 MiB — a SPAN capture bigger than
// this almost certainly means the operator should be slicing it up, and we
// refuse to OOM the server on it. (production-plan Phase 1.2)
function getMaxPcapBytes(): number {
  return Number(process.env.GHOSTWIRE_MAX_PCAP_BYTES || (500 * (1 << 20)));
}

// Subprocess analysis timeout. Default 240s. On expiry: SIGTERM, then SIGKILL
// after 5s if still alive, and we return 504. (production-plan Phase 1.3)
function getAnalysisTimeoutMs(): number {
  return Number(process.env.GHOSTWIRE_ANALYSIS_TIMEOUT_MS || 240_000);
}
const KILL_GRACE_MS = 5_000;

// Rate limit on /api/analyze (per-IP). (production-plan Phase 1.4)
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
  global: false, // opt-in per route; health + ws stay unthrottled
  max: getRateMax(),
  timeWindow: getRateWindow(),
});

// Health check endpoint
app.get('/health', async () => ({ status: 'ok', version: '0.1.0' }));

// ─── Auth middleware ──────────────────────────────────────────────────────
// If GHOSTWIRE_API_KEY is set, require Authorization: Bearer <key>.
// If unset, the API is open — but the server refuses to bind a non-loopback
// host without a key (see startup check at the bottom), so "open" is only
// reachable on localhost. (audit H-06)
const API_KEY = process.env.GHOSTWIRE_API_KEY || null;

app.addHook('onRequest', async (request: any, reply: any) => {
  // Skip auth for health checks
  if (request.url === '/health') return;

  // WebSocket auth: validate query param or Authorization header
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

// ─── Path validation ──────────────────────────────────────────────────────
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

// Allowed directories for PCAP files (configurable via env).
// Default: the project's own samples/ directory, so out-of-the-box the server
// can only read captures shipped with the project, not arbitrary files on the
// host. Operators who want to analyze captures elsewhere must explicitly set
// GHOSTWIRE_ALLOWED_DIRS=/path/a:/path/b. (audit H-06)
const PROJECT_ROOT = path.resolve(__dirname, '..');
const DEFAULT_ALLOWED_DIR = path.join(PROJECT_ROOT, 'samples');
// Resolved per-request so tests/operators can reconfigure without a restart
// (ESM imports hoist above test setup, so module-load resolution would miss
// fixture dirs set in before()).
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
  // Resolve to absolute path and reject traversal
  const resolved = path.resolve(filePath);

  // Block path traversal components
  if (filePath.includes('..')) {
    return 'Path traversal rejected';
  }

  // Restrict to the configured allowlist (fail-closed: default = samples/).
  const allowed = getAllowedDirs().some(
    (dir) => resolved.startsWith(dir + path.sep) || resolved === dir,
  );
  if (!allowed) {
    return 'Access denied: file outside allowed directories. Configure GHOSTWIRE_ALLOWED_DIRS if needed.';
  }

  // Restrict to allowed extensions
  const ext = path.extname(resolved).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return `Unsupported file extension: ${ext}. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
  }

  // File must exist and be readable
  try {
    fs.accessSync(resolved, fs.constants.R_OK);
  } catch {
    return `File not found or unreadable: ${resolved}`;
  }

  return null; // valid
}

// Max-PCAP-size pre-check. Returns the byte size, or an error string if the
// file exceeds GHOSTWIRE_MAX_PCAP_BYTES. Kept separate from validateFilePath
// because the failure mode (413) differs from a path error (400). (Phase 1.2)
// Exported for direct unit testing.
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

export { app };

app.post('/api/analyze', {
  // Rate-limit only the heavy endpoint; health + ws stay open. (Phase 1.4)
  config: { rateLimit: { max: getRateMax(), timeWindow: getRateWindow() } },
}, async (request: any, reply: any) => {
  const body = request.body || {};
  const { filePath, parser = 'auto' } = body;
  // Server-side type validation before spawning the Python subprocess (audit M-14).
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

  // Validate file path (no traversal, correct extension, exists, within allowlist)
  const pathError = validateFilePath(filePath);
  if (pathError) {
    return reply.code(400).send({ error: pathError });
  }

  // Max-size pre-check BEFORE spawning — refuse oversized captures with 413.
  const sizeCheck = checkPcapSize(filePath);
  if ('error' in sizeCheck) {
    return reply.code(413).send({ error: sizeCheck.error });
  }

  const analysisTimeoutMs = getAnalysisTimeoutMs();

  // Run ghostwire CLI and capture JSON output
  return new Promise((resolve) => {
    // GHOSTWIRE_PYTHON_BIN overrides the hardcoded venv path so operators
    // (and tests) can point at any interpreter. Defaults to the project venv.
    const venv = process.env.GHOSTWIRE_PYTHON_BIN || path.join(__dirname, '..', '.venv', 'bin', 'python3');
    const args = [
      '-m', 'engine.cli',
      'analyze', filePath,
      '--output', 'json',
      '--min-score', String(minScore),
      '--min-packets', String(minPackets),
      '--parser', parser,
    ];

    // PYTHONPATH is overridden so the Python subprocess can import the engine
    // package from the project root. Safe for local development; the server
    // binds loopback by default and refuses non-loopback binding without
    // GHOSTWIRE_API_KEY, so this is not remotely reachable without auth.
    const proc = spawn(venv, args, {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, PYTHONPATH: path.join(__dirname, '..') },
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;

    // Settle once: clear timers, reap the process, run the reply fn.
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      try { proc.kill(); } catch { /* already dead */ }
      fn();
    };

    // Subprocess timeout → SIGTERM, then SIGKILL after grace, then 504.
    // (production-plan Phase 1.3)
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      console.error(`[GHOSTWIRE] Analysis timeout (${analysisTimeoutMs}ms) for ${filePath}; sending SIGTERM`);
      try { proc.kill('SIGTERM'); } catch { /* dead */ }
      killTimer = setTimeout(() => {
        console.error(`[GHOSTWIRE] Process did not exit after SIGTERM; sending SIGKILL`);
        try { proc.kill('SIGKILL'); } catch { /* dead */ }
      }, KILL_GRACE_MS);
    }, analysisTimeoutMs);

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

    proc.on('error', (err: Error) => {
      console.error(`[GHOSTWIRE] Spawn error: ${err.message}`);
      finish(() => resolve(reply.code(500).send({ error: 'Failed to start analysis. Check server logs.' })));
    });

    proc.on('close', (code: number) => {
      // Timeout path wins over exit code: a SIGTERM-killed process exits
      // non-zero, but the operator wants 504, not a generic 500.
      if (timedOut) {
        finish(() => resolve(reply.code(504).send({ error: 'Analysis timed out. Increase GHOSTWIRE_ANALYSIS_TIMEOUT_MS or analyze a smaller capture.' })));
        return;
      }
      if (code !== 0) {
        // Sanitize: log full stderr server-side, send generic error to client
        console.error(`[GHOSTWIRE] Analysis failed (exit ${code}): ${stderr}`);
        finish(() => resolve(reply.code(500).send({ error: 'Analysis failed. Check server logs for details.' })));
        return;
      }
      try {
        finish(() => resolve(reply.send(JSON.parse(stdout))));
      } catch {
        finish(() => resolve(reply.code(500).send({ error: 'Failed to parse analysis output' })));
      }
    });
  });
});

// In-memory analysis result cache (legacy single-slot). Phase 3 replaces
// this with the SQLite job store; kept for now so /api/analysis still works.
let currentAnalysis: any = null;
app.get('/api/analysis', async (_request: any, reply: any) => {
  if (!currentAnalysis) {
    return reply.code(404).send({ error: 'No analysis available. POST to /api/analyze first.' });
  }
  return reply.send(currentAnalysis);
});

// WebSocket for real-time updates
app.register(import('@fastify/websocket'));

app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection: any, _req: any) => {
    // Send current analysis if available
    if (currentAnalysis) {
      connection.socket.send(JSON.stringify({ type: 'analysis', data: currentAnalysis }));
    }

    connection.socket.on('message', (message: Buffer) => {
      try {
        const msg = JSON.parse(message.toString());
        if (msg.type === 'ping') {
          connection.socket.send(JSON.stringify({ type: 'pong' }));
        }
      } catch { /* ignore */ }
    });
  });
});

const PORT = parseInt(process.env.PORT || '3001', 10);
// Fail-closed binding (audit H-06): default to loopback. Binding a non-loopback
// host requires GHOSTWIRE_API_KEY to be set, so the server is never
// network-exposed AND open at the same time.
const HOST = process.env.GHOSTWIRE_HOST || '127.0.0.1';
const isLoopback = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
if (!isLoopback && !API_KEY) {
  console.error(`REFUSING TO START: GHOSTWIRE_HOST is non-loopback (${HOST}) but GHOSTWIRE_API_KEY is unset.`);
  console.error('A network-exposed server with no auth is fail-open. Set GHOSTWIRE_API_KEY or bind 127.0.0.1.');
  process.exit(1);
}

async function start() {
  await app.listen({ port: PORT, host: HOST });
  console.log(`GHOSTWIRE API server running on http://${HOST}:${PORT}`);
  console.log(`WebSocket available at ws://${HOST}:${PORT}/ws`);
  console.log(`PCAP allowlist: ${getAllowedDirs().join(':')}`);
  console.log(`Limits: body=${(BODY_LIMIT / (1 << 20)).toFixed(1)}MiB, max-pcap=${(getMaxPcapBytes() / (1 << 20)).toFixed(0)}MiB, analysis-timeout=${(getAnalysisTimeoutMs() / 1000).toFixed(0)}s, rate=${getRateMax()}/${getRateWindow()}`);
}

// Run only when executed directly (not imported by a test).
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  start();
}