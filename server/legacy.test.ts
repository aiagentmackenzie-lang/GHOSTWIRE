// Compatibility adapter tests (Wave 1, slice 5).
//
// The adapter's job is to keep a saved 0.2.x summary readable without
// inventing detail, and to refuse to reinterpret an unknown future schema.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LEGACY_MISSING_DETAIL,
  RESULT_SCHEMA_VERSION,
  SUPPORTED_SCHEMA_VERSIONS,
  legacySummaryFields,
  normalizeStoredResult,
} from './legacy.js';

const LEGACY_DNS_SUMMARY = {
  ghostwire_version: '0.2.0',
  file: '/captures/dns.pcap',
  analysis_time: 0.02,
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

const LEGACY_HTTP_SUMMARY = {
  ghostwire_version: '0.2.0',
  file: '/captures/http.pcap',
  analysis_time: 0.01,
  packets_total: 1,
  sessions_total: 1,
  tls_fingerprints: 0,
  http_fingerprints: 1,
  ssh_fingerprints: 0,
  beacons_detected: 0,
  dns_threats: 0,
  c2_matches: 1,
  threats: [
    {
      target: '185.220.101.34:80-192.168.1.50:49152',
      target_type: 'session',
      overall_score: 0.315,
      confidence: 'LOW',
      beacon_score: null,
      c2_matches: [],
      dns_threats: [],
      iocs: ['C2:cobalt_strike (Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0))'],
      mitre_techniques: ['T1071.001'],
      summary: 'Known C2: cobalt_strike',
    },
  ],
};

test('a current-schema result passes through unchanged', () => {
  const raw = {
    schema_version: RESULT_SCHEMA_VERSION,
    ghostwire_version: '0.2.1',
    findings: [{ finding_id: 'fnd-1' }],
  };
  const normalized = normalizeStoredResult(raw);
  assert.equal(normalized.compatibility.status, 'current');
  assert.equal(normalized.compatibility.schema_version, RESULT_SCHEMA_VERSION);
  assert.deepEqual(normalized.result, raw);
  assert.deepEqual(normalized.compatibility.detail_unavailable, []);
});

test('legacy DNS summary keeps its recorded count and marks missing structure', () => {
  const { compatibility, result } = normalizeStoredResult(LEGACY_DNS_SUMMARY);
  assert.equal(compatibility.status, 'legacy');
  assert.equal(compatibility.schema_version, null);
  assert.equal(compatibility.original_preserved, true);

  // Recorded values survive.
  assert.equal(result.packets_total, 1);
  assert.equal(result.dns_threats, 1);
  assert.equal(result.engine_version, '0.2.0');
  assert.equal(result.threats.length, 0);

  // Structure that was never stored is explicitly unavailable, not empty.
  assert.equal(result.findings, null);
  assert.equal(result.observations, null);
  assert.equal(result.coverage, null);
  assert.ok(compatibility.detail_unavailable.includes('findings'));
  assert.ok(result.notes.some((n: string) => n.includes('does not prove there were no findings')));
});

test('legacy HTTP summary keeps score, label and IOC text, and refuses to infer direction', () => {
  const { result } = normalizeStoredResult(LEGACY_HTTP_SUMMARY);
  const row = result.threats[0];

  assert.equal(row.target, '185.220.101.34:80-192.168.1.50:49152');
  assert.equal(row.overall_score, 0.315);
  assert.equal(row.confidence, 'LOW');
  assert.deepEqual(row.iocs, LEGACY_HTTP_SUMMARY.threats[0].iocs);
  assert.equal(row.summary, 'Known C2: cobalt_strike');

  // The historical endpoint string is a label, not evidence of direction.
  assert.equal(row.endpoints, null);
  assert.equal(row.endpoint_direction, 'unknown');
  assert.equal(row.frames, null);
  assert.deepEqual(row.finding_ids, []);
  assert.equal(row.score_components, null);
  assert.ok(row.detail_unavailable.includes('observations'));
  assert.ok(row.detail_unavailable.includes('endpoints'));
});

test('an empty legacy array is not evidence that nothing was found', () => {
  const { result, compatibility } = normalizeStoredResult(LEGACY_DNS_SUMMARY);
  assert.deepEqual(result.threats, []);
  assert.ok(result.notes.some((n: string) => n.includes('does not prove there were no findings')));
  assert.equal(compatibility.status, 'legacy');
});

test('an unknown future schema is unsupported and preserved verbatim', () => {
  const future = {
    schema_version: '9.4',
    something_new: { nested: true },
    findings: [{ finding_id: 'fnd-future' }],
  };
  const { compatibility, result } = normalizeStoredResult(future);
  assert.equal(compatibility.status, 'unsupported');
  assert.equal(compatibility.schema_version, '9.4');
  assert.match(compatibility.message, /does not support/);
  assert.equal(compatibility.original_preserved, true);
  // The payload is preserved, not reinterpreted into plausible-looking counts.
  assert.deepEqual(result.original, future);
  assert.equal(result.counts, undefined);
  assert.ok(!SUPPORTED_SCHEMA_VERSIONS.includes('9.4'));
});

test('absent and non-object payloads are handled without throwing', () => {
  const absent = normalizeStoredResult(null);
  assert.equal(absent.compatibility.status, 'absent');
  assert.equal(absent.result, null);

  const scalar = normalizeStoredResult(42);
  assert.equal(scalar.compatibility.status, 'unsupported');
  assert.deepEqual(scalar.result.original, 42);
});

test('legacySummaryFields projects the fields older clients read', () => {
  const fields = legacySummaryFields(LEGACY_HTTP_SUMMARY);
  assert.equal(fields.ghostwire_version, '0.2.0');
  assert.equal(fields.packets_total, 1);
  assert.equal(fields.sessions_total, 1);
  assert.equal(fields.c2_matches, 1);
  assert.equal(fields.threats.length, 1);

  const empty = legacySummaryFields(null);
  assert.equal(empty.packets_total, 0);
  assert.deepEqual(empty.threats, []);
  assert.equal(LEGACY_MISSING_DETAIL.includes('unavailable'), true);
});

// The migration path matters as much as the adapter: a database written by
// 0.2.x has no schema_version/engine_version/capture_sha256 columns, and its
// rows must still open after the upgrade.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { JobStore } from './db.js';

test('a 0.2.x database is migrated in place and its rows still open', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-legacy-db-'));
  const dbPath = path.join(dir, 'jobs.sqlite');
  try {
    const old = new Database(dbPath);
    old.exec(`
      CREATE TABLE jobs (
        id TEXT PRIMARY KEY, file_path TEXT NOT NULL, status TEXT NOT NULL,
        created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
        summary_json TEXT, error TEXT
      );
    `);
    old.prepare(
      'INSERT INTO jobs (id, file_path, status, created_at, finished_at, summary_json) VALUES (?,?,?,?,?,?)',
    ).run('legacy-dns', '/captures/dns.pcap', 'completed', 1, 2, JSON.stringify(LEGACY_DNS_SUMMARY));
    old.prepare(
      'INSERT INTO jobs (id, file_path, status, created_at, finished_at, summary_json) VALUES (?,?,?,?,?,?)',
    ).run('legacy-http', '/captures/http.pcap', 'completed', 1, 2, JSON.stringify(LEGACY_HTTP_SUMMARY));
    old.close();

    const store = new JobStore(dbPath);
    const dns = store.get('legacy-dns');
    const http = store.get('legacy-http');
    assert.ok(dns && http);
    // New columns exist and are null for historical rows.
    assert.equal(dns.schema_version, null);
    assert.equal(dns.engine_version, null);
    // Recorded values survive.
    assert.equal(JSON.parse(dns.summary_json!).dns_threats, 1);
    assert.equal(JSON.parse(http.summary_json!).threats[0].overall_score, 0.315);
    // Normalization still classifies them as legacy.
    assert.equal(normalizeStoredResult(JSON.parse(dns.summary_json!)).compatibility.status, 'legacy');
    store.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
