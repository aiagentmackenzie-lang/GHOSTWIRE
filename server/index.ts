import Fastify from 'fastify';
import cors from '@fastify/cors';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

const app = Fastify({ logger: false });

app.register(cors, { origin: true });

// Health check endpoint
app.get('/health', async () => ({ status: 'ok', version: '0.1.0' }));

// Store analysis results in memory (simple approach for now)
let currentAnalysis: any = null;

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
const ALLOWED_DIRS = (process.env.GHOSTWIRE_ALLOWED_DIRS || '')
    .split(':')
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => path.resolve(d));
if (ALLOWED_DIRS.length === 0) {
  ALLOWED_DIRS.push(DEFAULT_ALLOWED_DIR);
}

function validateFilePath(filePath: string): string | null {
  // Resolve to absolute path and reject traversal
  const resolved = path.resolve(filePath);

  // Block path traversal components
  if (filePath.includes('..')) {
    return 'Path traversal rejected';
  }

  // Restrict to the configured allowlist (fail-closed: default = samples/).
  const allowed = ALLOWED_DIRS.some(
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

app.post('/api/analyze', async (request: any, reply: any) => {
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

  // Run ghostwire CLI and capture JSON output
  return new Promise((resolve) => {
    const venv = path.join(__dirname, '..', '.venv', 'bin', 'python3');
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

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

    proc.on('close', (code: number) => {
      if (code !== 0) {
        // Sanitize: log full stderr server-side, send generic error to client
        console.error(`[GHOSTWIRE] Analysis failed (exit ${code}): ${stderr}`);
        resolve(reply.code(500).send({ error: 'Analysis failed. Check server logs for details.' }));
        return;
      }

      try {
        currentAnalysis = JSON.parse(stdout);
        resolve(reply.send(currentAnalysis));
      } catch {
        resolve(reply.code(500).send({ error: 'Failed to parse analysis output' }));
      }
    });
  });
});

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

app.listen({ port: PORT, host: HOST }).then(() => {
  console.log(`GHOSTWIRE API server running on http://${HOST}:${PORT}`);
  console.log(`WebSocket available at ws://${HOST}:${PORT}/ws`);
  console.log(`PCAP allowlist: ${ALLOWED_DIRS.join(':')}`);
});