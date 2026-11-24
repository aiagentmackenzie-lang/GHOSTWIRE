// Result-schema compatibility adapter (Wave 1, slice 5).
//
// A stored job can hold one of three things:
//
//   1. A versioned result this build understands (schema_version in
//      SUPPORTED_SCHEMA_VERSIONS).
//   2. An unversioned 0.2.x summary. Those recorded counts, scores, severity
//      labels and IOC text — and nothing else. The adapter shows what was
//      recorded and marks every detail the old summary never stored as
//      unavailable. It must never infer a frame, an endpoint direction, or the
//      absence of findings from an empty legacy array: `c2_matches: []` in a
//      0.2.x summary means "the old exporter wrote an empty list", not "there
//      were no matches".
//   3. A schema version from a future build. Reinterpreting it would invent
//      meaning, so the adapter reports it as unsupported and hands back the
//      original payload untouched.

export const RESULT_SCHEMA_VERSION = '1.0';
export const SUPPORTED_SCHEMA_VERSIONS = ['1.0'];
export const LEGACY_SCHEMA_LABEL = '0.2.x-legacy';
export const LEGACY_MISSING_DETAIL = 'detail unavailable in this saved analysis';

export type CompatibilityStatus = 'current' | 'legacy' | 'unsupported' | 'absent';

export interface Compatibility {
  status: CompatibilityStatus;
  schema_version: string | null;
  supported_schema_versions: string[];
  message: string;
  original_preserved: boolean;
  detail_unavailable: string[];
}

export interface NormalizedResult {
  compatibility: Compatibility;
  result: any;
}

/** Fields a 0.2.x summary never recorded. */
const LEGACY_UNAVAILABLE_THREAT_FIELDS = [
  'observations',
  'finding_ids',
  'conversation_id',
  'score_components',
  'endpoints',
  'client_side',
  'role_basis',
  'frames',
];

function isObject(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Legacy threat rows: keep what was recorded, label what was not. */
function normalizeLegacyThreat(threat: any, index: number): any {
  const recorded = isObject(threat) ? threat : {};
  const summary = typeof recorded.summary === 'string' ? recorded.summary : '';
  return {
    ...recorded,
    // The historical endpoint string is kept verbatim as a label. Its order was
    // canonical (smaller address first), so it does not establish direction.
    target: typeof recorded.target === 'string' ? recorded.target : `row-${index + 1}`,
    endpoints: null,
    endpoint_direction: 'unknown',
    frames: null,
    conversation_id: null,
    finding_ids: [],
    score_components: null,
    observations: null,
    // Recorded values survive: counts, score, severity, IOC text, summary.
    iocs: Array.isArray(recorded.iocs) ? recorded.iocs : [],
    summary,
    detail_unavailable: [...LEGACY_UNAVAILABLE_THREAT_FIELDS],
  };
}

function legacyView(summary: Record<string, any>): any {
  const threats = Array.isArray(summary.threats) ? summary.threats : [];
  const notes = [
    'This job was stored by an older GHOSTWIRE build and carries no result schema version.',
    'Recorded counts, conversation scores, severity labels and IOC text are shown as recorded.',
    `Missing structured evidence is marked "${LEGACY_MISSING_DETAIL}".`,
    'An empty array in this summary records what the old exporter wrote; it does not prove there were no findings.',
    'Re-run the capture to obtain frames, endpoints, rule provenance and coverage.',
    'Fingerprints recorded by 0.2.x used the comma-delimiter JA3 algorithm '
      + '(ja3 revision ghostwire-ja3-comma-v0.2); do not compare them with current JA3 values.',
  ];
  return {
    schema_version: null,
    legacy: true,
    engine_version: summary.ghostwire_version ?? null,
    file: summary.file ?? null,
    analysis_time: typeof summary.analysis_time === 'number' ? summary.analysis_time : null,
    packets_total: summary.packets_total ?? null,
    sessions_total: summary.sessions_total ?? null,
    tls_fingerprints: summary.tls_fingerprints ?? null,
    http_fingerprints: summary.http_fingerprints ?? null,
    ssh_fingerprints: summary.ssh_fingerprints ?? null,
    beacons_detected: summary.beacons_detected ?? null,
    dns_threats: summary.dns_threats ?? null,
    c2_matches: summary.c2_matches ?? null,
    threats: threats.map(normalizeLegacyThreat),
    findings: null,
    observations: null,
    coverage: null,
    selection: null,
    run: null,
    detail_unavailable: [
      'findings',
      'observations',
      'coverage',
      'selection',
      'run.capture.sha256',
      'run.capture.parser_used',
      'run.settings',
    ],
    notes,
  };
}

/**
 * Normalize a stored summary payload for an API client.
 *
 * `raw` is the parsed `summary_json` (or null). The returned `result` never
 * discards the recorded values; unknown future schemas are returned under
 * `result.original` with `compatibility.status === 'unsupported'`.
 */
export function normalizeStoredResult(raw: any): NormalizedResult {
  if (raw === null || raw === undefined) {
    return {
      compatibility: {
        status: 'absent',
        schema_version: null,
        supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
        message: 'This job has no stored result yet.',
        original_preserved: true,
        detail_unavailable: [],
      },
      result: null,
    };
  }

  if (!isObject(raw)) {
    return {
      compatibility: {
        status: 'unsupported',
        schema_version: null,
        supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
        message: 'Stored payload is not a JSON object; the original value is preserved unchanged.',
        original_preserved: true,
        detail_unavailable: [],
      },
      result: { original: raw },
    };
  }

  const schema = raw.schema_version;
  if (typeof schema === 'string' && SUPPORTED_SCHEMA_VERSIONS.includes(schema)) {
    return {
      compatibility: {
        status: 'current',
        schema_version: schema,
        supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
        message: `Stored result uses supported schema ${schema}.`,
        original_preserved: true,
        detail_unavailable: [],
      },
      result: raw,
    };
  }

  if (typeof schema === 'string' && schema.length > 0) {
    return {
      compatibility: {
        status: 'unsupported',
        schema_version: schema,
        supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
        message:
          `This result uses schema ${schema}, which this GHOSTWIRE build does not support. ` +
          'The original payload is preserved unchanged; upgrade the server to open it.',
        original_preserved: true,
        detail_unavailable: [],
      },
      // Preserve the payload verbatim. Do not derive counts from an unknown
      // shape — a plausible-looking number would be a guess.
      result: { original: raw },
    };
  }

  return {
    compatibility: {
      status: 'legacy',
      schema_version: null,
      supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
      message:
        'Unversioned 0.2.x summary: recorded values are shown; structured evidence is unavailable.',
      original_preserved: true,
      detail_unavailable: [
        'findings',
        'observations',
        'coverage',
        'selection',
        'run',
      ],
    },
    result: legacyView(raw),
  };
}

/** Summary fields an older client relies on, projected from any result shape. */
export function legacySummaryFields(result: any): Record<string, any> {
  if (!isObject(result)) {
    return {
      ghostwire_version: null,
      packets_total: 0,
      sessions_total: 0,
      beacons_detected: 0,
      tls_fingerprints: 0,
      http_fingerprints: 0,
      ssh_fingerprints: 0,
      c2_matches: 0,
      dns_threats: 0,
      threats: [],
    };
  }
  return {
    ghostwire_version: result.ghostwire_version ?? result.engine_version ?? null,
    file: result.file ?? null,
    analysis_time: result.analysis_time ?? null,
    packets_total: result.packets_total ?? 0,
    sessions_total: result.sessions_total ?? 0,
    tls_fingerprints: result.tls_fingerprints ?? 0,
    http_fingerprints: result.http_fingerprints ?? 0,
    ssh_fingerprints: result.ssh_fingerprints ?? 0,
    beacons_detected: result.beacons_detected ?? 0,
    dns_threats: result.dns_threats ?? 0,
    c2_matches: result.c2_matches ?? 0,
    threats: Array.isArray(result.threats) ? result.threats : [],
  };
}
