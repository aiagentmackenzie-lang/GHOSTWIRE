// Result-contract types for the dashboard (Wave 1).
//
// Every field the UI renders comes from the versioned result written by
// `engine.analysis`. Optional fields exist for two honest reasons: a legacy
// 0.2.x summary genuinely does not have them, and a partial decode genuinely
// could not produce them. The UI must show "unavailable" rather than invent a
// value, a position or an all-clear.

export interface Endpoint {
  ip: string
  port: number
  role: 'client' | 'server' | 'unknown'
  address_family?: string
}

export interface SequenceRange {
  start: number
  end: number
  length: number
  frames: number[]
}

export interface StreamGap {
  start: number
  end: number
  missing_bytes: number
}

export interface StreamEvidence {
  session_id: string
  direction: string
  seq_ranges: SequenceRange[]
  gaps: StreamGap[]
  missing_bytes: number
  captured_payload_bytes: number
  distinct_stream_bytes: number
  stored_bytes: number
  capped: boolean
  role_basis: string
}

export interface Observation {
  observation_id: string
  kind: string
  frame: number
  frames: number[]
  timestamp: number | null
  transport: string
  src: Endpoint
  dst: Endpoint
  direction: string
  field: string
  value: string
  normalized_value: string | null
  occurrence: number
  note?: string
  stream?: StreamEvidence
}

export interface Reason {
  code: string
  detail: string
  contribution: number | null
  scale: string
  observation_id: string | null
}

export interface RuleRef {
  id: string
  revision: string
  source: string
}

export interface ToolInference {
  tool: string
  confidence: number
  basis: string
  caveat: string
}

export interface Finding {
  finding_id: string
  kind: string
  rule: RuleRef
  subject: { type: string; value: string }
  scope: string
  match_method: string
  score: number
  score_scale: string
  reasons: Reason[]
  observation_ids: string[]
  conversation_id: string | null
  conversation_basis: string | null
  mitre_techniques: string[]
  provenance: Record<string, unknown>
  summary: string
  tool_inference?: ToolInference
}

export interface Coverage {
  status: 'complete' | 'partial' | 'unsupported_decode' | 'empty'
  label: string
  reasons: string[]
  limits: string[]
  frames_read: number
  frames_decoded: number
  frames_undecoded: number
  sessions_total: number
  sessions_dropped: number
  stream_gaps: number
  stream_missing_bytes: number
  payloads_capped: number
  parser_used: string | null
  link_type_declared: number | null
  link_type_name: string | null
}

export interface Selection {
  counts: Record<string, number>
  filter: {
    min_score?: number
    sessions_below_threshold?: number
    sessions_without_findings?: number
    counting_unit?: string
    note?: string
  }
  truncation: {
    sessions_limit?: number
    sessions_truncated?: boolean
    findings_limit?: number
    findings_truncated?: boolean
    ordering?: string
  }
  explanation: string
}

export interface RunCapture {
  path: string
  sha256: string
  size_bytes: number
  format: string | null
  link_type_declared: number | null
  link_type_name: string | null
  parser_declared: string
  parser_used: string | null
  parser_fallback: boolean
  frames_read: number
  frames_decoded: number
  frames_undecoded: number
  decode_rate: number | null
  first_timestamp: number | null
  last_timestamp: number | null
  duration_seconds: number | null
  ordering_anomalies: number
}

export interface Run {
  schema_version: string
  run_id: string
  engine_version: string
  generated_at: string
  capture: RunCapture
  settings: Record<string, unknown>
  versions: Record<string, unknown>
}

export interface ScoreComponent {
  source: string
  value: number
  weight: number
  contribution: number
  value_scale: string
  finding_id: string | null
  detail: string
}

export interface Endpoints {
  src: Endpoint
  dst: Endpoint
}

export interface ThreatEntry {
  target: string
  target_type: string
  overall_score: number
  score_scale?: string
  confidence: string
  beacon_score: number | null
  c2_matches: unknown[]
  dns_threats: unknown[]
  iocs: string[]
  mitre_techniques: string[]
  summary: string
  finding_ids?: string[]
  components?: ScoreComponent[]
  endpoints?: Endpoints | null
  client_side?: string
  role_basis?: string
  beacon_detail?: BeaconDetail | null
  // Legacy rows: what the old summary never recorded.
  detail_unavailable?: string[]
  endpoint_direction?: string
}

export interface BeaconDetail {
  overall_score: number
  confidence: string
  iat_mean: number
  iat_std: number
  iat_jitter: number
  packet_count: number
  duration: number
  byte_ratio: number
  components: Record<string, number>
  units: Record<string, string>
}

export interface Compatibility {
  status: 'current' | 'legacy' | 'unsupported' | 'absent'
  schema_version: string | null
  supported_schema_versions: string[]
  message: string
  original_preserved: boolean
  detail_unavailable: string[]
}

export interface AnalysisData {
  schema_version?: string
  ghostwire_version: string
  file: string
  analysis_time: number | null
  packets_total: number
  packets_decoded?: number
  sessions_total: number
  tls_fingerprints: number
  http_fingerprints: number
  ssh_fingerprints: number
  beacons_detected: number
  dns_threats: number
  c2_matches: number
  threats: ThreatEntry[]
  capture_sha256?: string
  protocol_counts?: Record<string, number>
  run?: Run
  coverage?: Coverage
  findings?: Finding[]
  observations?: Observation[]
  conversations?: unknown[]
  selection?: Selection
  summary?: string
  warnings?: string[]
  // UI-only markers (never sent by the engine)
  demo?: boolean
  compatibility?: Compatibility
}
