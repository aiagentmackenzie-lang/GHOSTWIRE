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

// ─── Auth middleware ────────────────────────────────────────────
// If GHOSTWIRE_API_KEY is set, require Authorization: Bearer <key>
// If unset, the API is open (local-dev mode only).
const API_KEY = process.env.GHOSTWIRE_API_KEY || null;

app.addHook('onRequest', async (request: any, reply: any) => {
  // Skip auth for WebSocket upgrade and health checks
  if (request.url === '/ws' || request.url === '/health') return;

  if (API_KEY) {
    const auth = request.headers['authorization'];
    if (!auth || auth !== `Bearer ${API_KEY}`) {
      return reply.code(401).send({ error: 'Unauthorized. Set Authorization: Bearer <key>' });
    }
  }
});

// ─── Path validation ──────────────────────────────────────────
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

function validateFilePath(filePath: string): string | null {
  // Resolve to absolute path and reject traversal
  const resolved = path.resolve(filePath);

  // Block path traversal components
  if (filePath.includes('..')) {
    return 'Path traversal rejected';
  }

  // Must be an absolute path or relative without traversal
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
  const { filePath, parser = 'auto', minScore = 0.1, minPackets = 5 } = request.body;

  if (!filePath) {
    return reply.code(400).send({ error: 'filePath is required' });
  }

  // Validate file path (no traversal, correct extension, exists)
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

    // ⚠ Security note: PYTHONPATH is overridden so the Python subprocess
    // can import the engine package from the project root. This is safe for
    // local development but the server MUST NOT be exposed publicly without
    // auth (GHOSTWIRE_API_KEY) and proper network isolation.
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

app.get('/api/analysis', async (request: any, reply: any) => {
  if (!currentAnalysis) {
    return reply.code(404).send({ error: 'No analysis available. POST to /api/analyze first.' });
  }
  return reply.send(currentAnalysis);
});

// WebSocket for real-time updates
app.register(import('@fastify/websocket'));

app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection: any, req: any) => {
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

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => {
  console.log(`GHOSTWIRE API server running on http://localhost:${PORT}`);
  console.log(`WebSocket available at ws://localhost:${PORT}/ws`);
});