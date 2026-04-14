import Fastify from 'fastify';
import cors from '@fastify/cors';
import { spawn } from 'child_process';
import path from 'path';

const app = Fastify({ logger: false });

app.register(cors, { origin: true });

// Store analysis results in memory (simple approach for now)
let currentAnalysis: any = null;

app.post('/api/analyze', async (request: any, reply: any) => {
  const { filePath, parser = 'auto', minScore = 0.1, minPackets = 5 } = request.body;

  if (!filePath) {
    return reply.code(400).send({ error: 'filePath is required' });
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
        resolve(reply.code(500).send({ error: 'Analysis failed', details: stderr }));
        return;
      }

      try {
        currentAnalysis = JSON.parse(stdout);
        resolve(reply.send(currentAnalysis));
      } catch {
        resolve(reply.code(500).send({ error: 'Failed to parse analysis output', raw: stdout }));
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