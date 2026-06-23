// Audit log — append-only, rotating JSON-lines (production-plan Phase 3.3).
//
// One line per analysis, written OUTSIDE the engine's write path (the server
// owns this; the Python engine never touches it). This is the operational
// baseline / chain-of-custody signal a forensics tool owes its users.
//
// Rotation: when the active log file exceeds `maxBytes` after a write, it is
// renamed to `<base>.1` (shifting existing `.N` up by one and deleting the
// oldest beyond `keepRotations`). Decision Q2: rotate at 100 MB, keep last 10.

import fs from 'node:fs';
import path from 'node:path';

export class AuditLog {
  private readonly logPath: string;
  private readonly maxBytes: number;
  private readonly keepRotations: number;

  constructor(logPath: string, maxBytes = 100 * (1 << 20), keepRotations = 10) {
    this.logPath = logPath;
    this.maxBytes = maxBytes;
    this.keepRotations = keepRotations;
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
  }

  /** Append one JSON line. Returns the bytes written. */
  write(line: Record<string, unknown>): number {
    const data = Buffer.from(JSON.stringify(line) + '\n', 'utf8');
    fs.appendFileSync(this.logPath, data);
    try {
      if (fs.statSync(this.logPath).size > this.maxBytes) {
        this.rotate();
      }
    } catch {
      // stat failure must never break the analysis path; the line was written.
    }
    return data.length;
  }

  /** Shift audit.jsonl -> audit.jsonl.1, .1 -> .2, ..., drop the oldest. */
  private rotate(): void {
    for (let i = this.keepRotations; i >= 1; i--) {
      const src = i === 1 ? this.logPath : `${this.logPath}.${i - 1}`;
      const dst = `${this.logPath}.${i}`;
      try {
        if (fs.existsSync(src)) {
          if (i === this.keepRotations && fs.existsSync(dst)) {
            fs.unlinkSync(dst);  // drop the oldest rotation
          }
          fs.renameSync(src, dst);
        }
      } catch {
        // best-effort rotation; a failed rename is logged by the caller if needed
      }
    }
  }
}