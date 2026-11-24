// Job store — durable analysis job state (production-plan Phase 3.1).
//
// Replaces the in-memory single-slot `currentAnalysis` with a SQLite-backed
// job table so concurrent analyses no longer clobber each other and job
// history survives a server restart (within the DB file's lifetime).
//
// Wave 1 additions: the run that produced a stored result is recorded next to
// it (schema/engine version, capture digest, the request that started it, and
// an optional parent job for a reanalysis). A reanalysis always creates a new
// row — a stored result is never rewritten.

import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface JobRequest {
  parser: string;
  minScore: number;
  minPackets: number;
  [key: string]: unknown;
}

export interface JobRow {
  id: string;
  file_path: string;
  status: JobStatus;
  created_at: number;   // epoch ms
  started_at: number | null;
  finished_at: number | null;
  summary_json: string | null;  // the CLI JSON output, parsed by callers
  error: string | null;
  schema_version: string | null;
  engine_version: string | null;
  capture_sha256: string | null;
  request_json: string | null;
  parent_job_id: string | null;
}

const BASE_SCHEMA = `
CREATE TABLE IF NOT EXISTS jobs (
  id           TEXT PRIMARY KEY,
  file_path    TEXT NOT NULL,
  status       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  started_at   INTEGER,
  finished_at  INTEGER,
  summary_json TEXT,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS jobs_created_at_idx ON jobs(created_at);
`;

// Columns added in 0.3.0. Existing databases get them via ALTER TABLE so a
// saved 0.2.x job opens without losing its recorded summary.
const ADDED_COLUMNS: Array<[string, string]> = [
  ['schema_version', 'TEXT'],
  ['engine_version', 'TEXT'],
  ['capture_sha256', 'TEXT'],
  ['request_json', 'TEXT'],
  ['parent_job_id', 'TEXT'],
];

export class JobStore {
  private db: Database.Database;
  private stmts;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.exec(BASE_SCHEMA);
    this.migrate();
    this.stmts = {
      create: this.db.prepare(
        `INSERT INTO jobs (id, file_path, status, created_at, request_json, parent_job_id)
         VALUES (?, ?, ?, ?, ?, ?)`
      ),
      start: this.db.prepare(
        'UPDATE jobs SET status = ?, started_at = ? WHERE id = ?'
      ),
      complete: this.db.prepare(
        `UPDATE jobs SET status = ?, finished_at = ?, summary_json = ?,
          schema_version = ?, engine_version = ?, capture_sha256 = ? WHERE id = ?`
      ),
      fail: this.db.prepare(
        'UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?'
      ),
      get: this.db.prepare('SELECT * FROM jobs WHERE id = ?'),
      list: this.db.prepare('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200'),
    };
  }

  /** Add post-0.2.x columns to an existing jobs table. Idempotent. */
  private migrate(): void {
    const existing = new Set(
      (this.db.prepare('PRAGMA table_info(jobs)').all() as Array<{ name: string }>)
        .map((c) => c.name),
    );
    for (const [name, type] of ADDED_COLUMNS) {
      if (!existing.has(name)) {
        this.db.exec(`ALTER TABLE jobs ADD COLUMN ${name} ${type}`);
      }
    }
  }

  createJob(filePath: string, request?: JobRequest, parentJobId?: string): string {
    const id = randomUUID();
    this.stmts.create.run(
      id, filePath, 'queued' as JobStatus, Date.now(),
      request ? JSON.stringify(request) : null,
      parentJobId ?? null,
    );
    return id;
  }

  markStarted(id: string): void {
    this.stmts.start.run('running' as JobStatus, Date.now(), id);
  }

  markCompleted(id: string, summaryJson: string): void {
    let schemaVersion: string | null = null;
    let engineVersion: string | null = null;
    let captureSha: string | null = null;
    try {
      const parsed = JSON.parse(summaryJson);
      schemaVersion = typeof parsed.schema_version === 'string' ? parsed.schema_version : null;
      engineVersion = typeof parsed.ghostwire_version === 'string'
        ? parsed.ghostwire_version
        : (typeof parsed.engine_version === 'string' ? parsed.engine_version : null);
      captureSha = typeof parsed.capture_sha256 === 'string'
        ? parsed.capture_sha256
        : (parsed.run?.capture?.sha256 ?? null);
    } catch { /* store the payload; a malformed summary simply has no versions */ }
    this.stmts.complete.run(
      'completed' as JobStatus, Date.now(), summaryJson,
      schemaVersion, engineVersion, captureSha, id,
    );
  }

  markFailed(id: string, error: string): void {
    this.stmts.fail.run('failed' as JobStatus, Date.now(), error, id);
  }

  get(id: string): JobRow | undefined {
    return this.stmts.get.get(id) as JobRow | undefined;
  }

  list(): JobRow[] {
    return this.stmts.list.all() as JobRow[];
  }

  /** Request that started a job, or null when it predates request recording. */
  requestFor(id: string): JobRequest | null {
    const row = this.get(id);
    if (!row?.request_json) return null;
    try { return JSON.parse(row.request_json) as JobRequest; } catch { return null; }
  }

  close(): void {
    this.db.close();
  }
}
