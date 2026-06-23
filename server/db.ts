// Job store — durable analysis job state (production-plan Phase 3.1).
//
// Replaces the in-memory single-slot `currentAnalysis` with a SQLite-backed
// job table so concurrent analyses no longer clobber each other and job
// history survives a server restart (within the DB file's lifetime).

import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface JobRow {
  id: string;
  file_path: string;
  status: JobStatus;
  created_at: number;   // epoch ms
  started_at: number | null;
  finished_at: number | null;
  summary_json: string | null;  // the CLI JSON output, parsed by callers
  error: string | null;
}

const SCHEMA = `
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

export class JobStore {
  private db: Database.Database;
  private stmts;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.exec(SCHEMA);
    this.stmts = {
      create: this.db.prepare(
        'INSERT INTO jobs (id, file_path, status, created_at) VALUES (?, ?, ?, ?)'
      ),
      start: this.db.prepare(
        'UPDATE jobs SET status = ?, started_at = ? WHERE id = ?'
      ),
      complete: this.db.prepare(
        'UPDATE jobs SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?'
      ),
      fail: this.db.prepare(
        'UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?'
      ),
      get: this.db.prepare('SELECT * FROM jobs WHERE id = ?'),
      list: this.db.prepare('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200'),
    };
  }

  createJob(filePath: string): string {
    const id = randomUUID();
    this.stmts.create.run(id, filePath, 'queued' as JobStatus, Date.now());
    return id;
  }

  markStarted(id: string): void {
    this.stmts.start.run('running' as JobStatus, Date.now(), id);
  }

  markCompleted(id: string, summaryJson: string): void {
    this.stmts.complete.run('completed' as JobStatus, Date.now(), summaryJson, id);
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

  close(): void {
    this.db.close();
  }
}