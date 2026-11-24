import { useState, useCallback, useEffect } from 'react'
import ThreatPanel from './components/ThreatPanel'
import Timeline from './components/Timeline'
import BeaconChart from './components/BeaconChart'
import NetworkGraph from './components/NetworkGraph'
import SessionView from './components/SessionView'
import ProtoBreakdown from './components/ProtoBreakdown'
import FingerprintTable from './components/FingerprintTable'
import type { AnalysisData, Compatibility } from './types'

const MISSING = 'unavailable'

function Stat({ label, value, unit, color }: {
  label: string; value: string | number; unit?: string; color?: string
}) {
  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      padding: '12px 16px', border: '1px solid var(--border)',
    }}>
      <div style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {label}
      </div>
      <div style={{ fontSize: '22px', fontWeight: 700, color: color || 'var(--text)', fontFamily: 'var(--font-mono)' }}>
        {value}
      </div>
      {unit && <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>{unit}</div>}
    </div>
  )
}

function App() {
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null)
  const [compatibility, setCompatibility] = useState<Compatibility | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filePath, setFilePath] = useState('')
  const [jobs, setJobs] = useState<Array<{
    id: string; status: string; file_path: string; compatibility?: Compatibility
    schema_version?: string | null; engine_version?: string | null
  }>>([])
  const [jobIdInput, setJobIdInput] = useState('')

  // API key: operator-entered, stored in browser localStorage (v0.2.1). The
  // key is NEVER baked into the JS bundle — that would ship the secret to
  // anyone who loads /, defeating API auth. VITE_API_TOKEN is kept ONLY as a
  // local-dev convenience so a developer can skip the prompt.
  const STORAGE_KEY = 'ghostwire_api_key'
  const [apiKey, setApiKey] = useState<string>(
    () => localStorage.getItem(STORAGE_KEY) || ''
  )
  const [keyInput, setKeyInput] = useState('')
  const hasKey =
    Boolean(apiKey) || Boolean(import.meta.env.VITE_API_TOKEN as string | undefined)

  // API base. Defaults to same-origin so the dashboard served by the server
  // (Phase 5) just works; in dev, set VITE_API_BASE=http://localhost:3001.
  const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
  const authHeaders = (): Record<string, string> => {
    const t = apiKey || (import.meta.env.VITE_API_TOKEN as string | undefined)
    return t ? { Authorization: `Bearer ${t}` } : {}
  }
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

  const connectKey = () => {
    const k = keyInput.trim()
    if (!k) return
    localStorage.setItem(STORAGE_KEY, k)
    setApiKey(k)
    setKeyInput('')
    setError(null)
  }

  const clearKey = () => {
    localStorage.removeItem(STORAGE_KEY)
    setApiKey('')
    setError(null)
  }

  const loadJobs = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/jobs`, { headers: authHeaders() })
      if (!res.ok) return
      const data = await res.json()
      setJobs((data.jobs || []).slice(0, 8))
    } catch { /* list is a convenience; analysis does not depend on it */ }
  }, [API_BASE, apiKey])

  // Only query the job list once a key is available; otherwise the first
  // paint fires an avoidable 401.
  useEffect(() => { if (hasKey) void loadJobs() }, [loadJobs, hasKey])

  // Reopen a saved job. The API returns the normalized view plus a
  // compatibility verdict, so a 0.2.x summary renders with its recorded values
  // and explicit "unavailable" markers instead of a guessed shape.
  const openJob = useCallback(async (id: string) => {
    if (!id) return
    setError(null)
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/api/jobs/${id}`, { headers: authHeaders() })
      if (res.status === 401) { handle401('Invalid or expired API key. Re-enter the key.'); return }
      if (!res.ok) { setError(`Job ${id} not found`); setLoading(false); return }
      const job = await res.json()
      if (job.status !== 'completed') {
        setError(`Job ${id} is ${job.status}; no result to display.`)
        setLoading(false)
        return
      }
      setCompatibility((job.compatibility as Compatibility) ?? null)
      setAnalysis((job.result ?? job.summary) as AnalysisData)
      setLoading(false)
    } catch {
      setError('Failed to load the saved job.')
      setLoading(false)
    }
  }, [API_BASE, apiKey])

  const handle401 = (msg: string) => {
    localStorage.removeItem(STORAGE_KEY)
    setApiKey('')
    setError(msg)
    setLoading(false)
  }

  const runAnalysis = useCallback(async (path: string) => {
    setLoading(true)
    setError(null)
    setCompatibility(null)
    setAnalysis(null)
    try {
      // Async job model (Phase 3): POST returns { jobId } immediately, then
      // we poll /api/jobs/:id until completed/failed.
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ filePath: path }),
      })
      if (res.status === 401) {
        handle401('Invalid or expired API key. Re-enter the key.')
        return
      }
      const data = await res.json()
      if (!res.ok || data.error) {
        setError(data.error || `Analysis rejected (${res.status})`)
        setLoading(false)
        return
      }
      const jobId: string = data.jobId
      const deadline = Date.now() + 5 * 60 * 1000
      while (Date.now() < deadline) {
        await sleep(1000)
        const jr = await fetch(`${API_BASE}/api/jobs/${jobId}`, { headers: authHeaders() })
        if (jr.status === 401) {
          handle401('Invalid or expired API key. Re-enter the key.')
          return
        }
        const job = await jr.json()
        if (job.status === 'completed') {
          // `result` is the normalized view (current schema, legacy adapter, or
          // unsupported). `summary` is the raw stored payload, kept for old
          // clients. Prefer the normalized result when present.
          const result = (job.result ?? job.summary) as AnalysisData
          setCompatibility((job.compatibility as Compatibility) ?? null)
          setAnalysis(result)
          setLoading(false)
          void loadJobs()
          return
        }
        if (job.status === 'failed') {
          setError(job.error || 'Analysis failed')
          setLoading(false)
          return
        }
      }
      setError('Analysis timed out (no result within 5 minutes)')
      setLoading(false)
    } catch {
      setError('Failed to connect to GHOSTWIRE API. Is the server running?')
      setLoading(false)
    }
  }, [API_BASE, apiKey])

  // Demo data. It is synthetic and is marked as such for as long as it is on
  // screen — the 0.2.x button presented invented charts as if they described
  // a capture.
  const loadDemo = useCallback(() => {
    setCompatibility(null)
    setAnalysis({
      demo: true,
      schema_version: '1.0',
      ghostwire_version: '0.3.0',
      file: 'demo/synthetic-sample (not a capture)',
      analysis_time: 0.021,
      packets_total: 110,
      packets_decoded: 110,
      sessions_total: 51,
      tls_fingerprints: 2,
      http_fingerprints: 50,
      ssh_fingerprints: 0,
      beacons_detected: 1,
      dns_threats: 0,
      c2_matches: 1,
      protocol_counts: { TCP: 108, DNS: 2 },
      run: {
        schema_version: '1.0',
        run_id: 'run-demo',
        engine_version: '0.3.0',
        generated_at: new Date().toISOString(),
        capture: {
          path: 'demo/synthetic-sample', sha256: 'demo-not-a-capture', size_bytes: 0,
          format: 'synthetic', link_type_declared: 1, link_type_name: 'EN10MB (Ethernet)',
          parser_declared: 'auto', parser_used: 'demo', parser_fallback: false,
          frames_read: 110, frames_decoded: 110, frames_undecoded: 0, decode_rate: 1,
          first_timestamp: 0, last_timestamp: 1440.5, duration_seconds: 1440.5,
          ordering_anomalies: 0,
        },
        settings: { min_score: 0.25, min_packets: 10 },
        versions: { engine: '0.2.1', result_schema: '1.0', ja3_algorithm: 'ja3-rfc-v1' },
      },
      coverage: {
        status: 'complete', label: 'Synthetic demo data',
        reasons: ['demo content: this is not a capture'], limits: [],
        frames_read: 110, frames_decoded: 110, frames_undecoded: 0, sessions_total: 51,
        sessions_dropped: 0, stream_gaps: 0, stream_missing_bytes: 0, payloads_capped: 0,
        parser_used: 'demo', link_type_declared: 1, link_type_name: 'EN10MB (Ethernet)',
      },
      selection: {
        counts: { sessions_total: 51, sessions_scored: 3, sessions_eligible: 3, sessions_returned: 3, findings_total: 3, findings_returned: 3 },
        filter: { min_score: 0.25, sessions_below_threshold: 0, counting_unit: 'session score' },
        truncation: { sessions_limit: 50, sessions_truncated: false },
        explanation: 'Synthetic demo rows; not produced by an analysis of a capture.',
      },
      summary: 'Synthetic demo: 3 conversation rows from invented evidence.',
      findings: [
        {
          finding_id: 'fnd-demo-1', kind: 'tls_fingerprint',
          rule: { id: 'c2.ja4_prefix', revision: '1', source: 'engine/fingerprint/c2_database.py::match_ja4' },
          subject: { type: 'tls_ja4', value: 't13d1516h2_demo' },
          scope: 'conversation', match_method: 'prefix', score: 0.7, score_scale: 'rule_weight_0_1',
          reasons: [{ code: 'c2.ja4_match', detail: 'TLS JA4 matched a cobalt_strike research prefix (demo)', contribution: 0.7, scale: 'rule_weight_0_1', observation_id: 'obs-demo-1' }],
          observation_ids: ['obs-demo-1'], conversation_id: 'cnv-demo-1',
          conversation_basis: 'demo', mitre_techniques: ['T1071.001'], provenance: { demo: true },
          summary: 'TLS JA4 matched a cobalt_strike research prefix (demo)',
          tool_inference: { tool: 'cobalt_strike', confidence: 0.7, basis: 'demo', caveat: 'Demo data — not a real observation.' },
        },
        {
          finding_id: 'fnd-demo-2', kind: 'http_header',
          rule: { id: 'c2.http_user_agent_exact', revision: '1', source: 'engine/fingerprint/c2_database.py::match_http' },
          subject: { type: 'http_header', value: 'Go-http-client/1.1' },
          scope: 'conversation', match_method: 'exact_normalized', score: 0.95, score_scale: 'rule_weight_0_1',
          reasons: [{ code: 'c2.http_pattern_match', detail: 'HTTP User-Agent matched a sliver rule (demo)', contribution: 0.95, scale: 'rule_weight_0_1', observation_id: 'obs-demo-2' }],
          observation_ids: ['obs-demo-2'], conversation_id: 'cnv-demo-2',
          conversation_basis: 'demo', mitre_techniques: ['T1071.001'], provenance: { demo: true },
          summary: 'HTTP User-Agent matched a sliver rule (demo)',
          tool_inference: { tool: 'sliver', confidence: 0.95, basis: 'demo', caveat: 'Demo data — not a real observation.' },
        },
        {
          finding_id: 'fnd-demo-3', kind: 'dns',
          rule: { id: 'dns.tunneling_heuristic', revision: '1', source: 'engine/detection/dns_threats.py::detect_dns_tunneling' },
          subject: { type: 'domain', value: 'aGVsbG8.dgahost.example' },
          scope: 'packet', match_method: 'heuristic', score: 0.8, score_scale: 'rule_score_0_1',
          reasons: [
            { code: 'dns.unusual_qtype', detail: 'Unusual DNS query type: TXT (demo)', contribution: 0.5, scale: 'rule_score_0_1', observation_id: 'obs-demo-3' },
            { code: 'dns.long_label', detail: 'Long subdomain (28 chars) (demo)', contribution: 0.3, scale: 'rule_score_0_1', observation_id: 'obs-demo-3' },
          ],
          observation_ids: ['obs-demo-3'], conversation_id: null, conversation_basis: null,
          mitre_techniques: ['T1071.004'], provenance: { demo: true },
          summary: 'DNS query matched a tunneling heuristic (demo)',
        },
      ],
      observations: [
        {
          observation_id: 'obs-demo-1', kind: 'stream', frame: 3, frames: [3, 4], timestamp: 2.5,
          transport: 'TCP', src: { ip: '192.168.1.50', port: 49152, role: 'client', address_family: 'ipv4' },
          dst: { ip: '185.220.101.34', port: 443, role: 'server', address_family: 'ipv4' },
          direction: 'src_to_dst', field: 'tls.client_hello.ja4', value: 't13d1516h2_demo',
          normalized_value: 'c2.example', occurrence: 1,
          stream: { session_id: 'demo', direction: 'src_to_dst', seq_ranges: [{ start: 1, end: 78, length: 77, frames: [3, 4] }], gaps: [], missing_bytes: 0, captured_payload_bytes: 77, distinct_stream_bytes: 77, stored_bytes: 77, capped: false, role_basis: 'tls_client_hello' },
        },
        {
          observation_id: 'obs-demo-2', kind: 'packet', frame: 41, frames: [41], timestamp: 300.5,
          transport: 'TCP', src: { ip: '192.168.1.50', port: 50001, role: 'client', address_family: 'ipv4' },
          dst: { ip: '45.33.32.156', port: 80, role: 'server', address_family: 'ipv4' },
          direction: 'src_to_dst', field: 'http.header.user-agent', value: 'Go-http-client/1.1',
          normalized_value: 'go-http-client/1.1', occurrence: 1,
        },
        {
          observation_id: 'obs-demo-3', kind: 'packet', frame: 99, frames: [99], timestamp: 900,
          transport: 'UDP', src: { ip: '192.168.1.50', port: 33333, role: 'client', address_family: 'ipv4' },
          dst: { ip: '8.8.8.8', port: 53, role: 'server', address_family: 'ipv4' },
          direction: 'src_to_dst', field: 'dns.query_name', value: 'aGVsbG8.dgahost.example',
          normalized_value: null, occurrence: 1,
        },
      ],
      threats: [
        {
          target: '185.220.101.34:443-192.168.1.50:49152', target_type: 'session',
          overall_score: 0.82, score_scale: 'weighted_composite_0_1', confidence: 'HIGH',
          beacon_score: 0.95, c2_matches: [], dns_threats: [],
          iocs: ['C2:cobalt_strike (t13d1516h2_demo)'], mitre_techniques: ['T1071.001'],
          summary: 'Beacon timing heuristic fired; rule match: cobalt_strike (demo)',
          finding_ids: ['fnd-demo-1'], endpoints: {
            src: { ip: '192.168.1.50', port: 49152, role: 'client', address_family: 'ipv4' },
            dst: { ip: '185.220.101.34', port: 443, role: 'server', address_family: 'ipv4' },
          },
          client_side: 'src', role_basis: 'tcp_syn',
          components: [
            { source: 'beacon', value: 0.95, weight: 0.4, contribution: 0.38, value_scale: 'beacon_score_0_1', finding_id: null, detail: 'beacon detector score' },
            { source: 'c2', value: 0.7, weight: 0.35, contribution: 0.245, value_scale: 'rule_weight_0_1', finding_id: 'fnd-demo-1', detail: 'highest-confidence C2 rule match' },
          ],
          beacon_detail: {
            overall_score: 0.95, confidence: 'HIGH', iat_mean: 60, iat_std: 0.24, iat_jitter: 0.004,
            packet_count: 50, duration: 1440.5, byte_ratio: 0.07,
            components: { jitter: 0.95, volume: 0.6, regularity: 0.7, entropy: 0.5 },
            units: { iat_mean: 'seconds', iat_jitter: 'std/mean', duration: 'seconds', byte_ratio: 'ratio' },
          },
        },
        {
          target: '45.33.32.156:80-192.168.1.50:50001', target_type: 'session',
          overall_score: 0.33, score_scale: 'weighted_composite_0_1', confidence: 'LOW',
          beacon_score: null, c2_matches: [], dns_threats: [],
          iocs: [], mitre_techniques: ['T1071.001'],
          summary: 'HTTP User-Agent matched a sliver rule (demo)',
          finding_ids: ['fnd-demo-2'], endpoints: {
            src: { ip: '192.168.1.50', port: 50001, role: 'client', address_family: 'ipv4' },
            dst: { ip: '45.33.32.156', port: 80, role: 'server', address_family: 'ipv4' },
          },
          client_side: 'src', role_basis: 'http_request',
        },
      ],
    })
  }, [])

  const counts = analysis?.selection?.counts
  const coverage = analysis?.coverage
  const compatibilityNotes = compatibility?.status === 'legacy'
    ? [
      compatibility.message,
      ...(compatibility.detail_unavailable?.length
        ? [`Unavailable detail: ${compatibility.detail_unavailable.join(', ')}`]
        : []),
    ]
    : compatibility?.status === 'unsupported'
      ? [compatibility.message]
      : []

  return (
    <div style={{ minHeight: '100vh', padding: '20px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        borderBottom: '1px solid var(--border)', paddingBottom: '16px', marginBottom: '20px',
        gap: '12px', flexWrap: 'wrap',
      }}>
        <div>
          <h1 style={{
            fontSize: '24px', fontWeight: 700, letterSpacing: '-0.5px',
            color: 'var(--primary)', textShadow: '0 0 20px rgba(0,255,159,0.3)',
          }}>
            GHOSTWIRE
          </h1>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            Network Forensics Engine
            {analysis?.ghostwire_version ? ` v${analysis.ghostwire_version}` : ''}
            {analysis?.schema_version ? ` · result schema ${analysis.schema_version}` : ''}
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="PCAP file path..."
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runAnalysis(filePath)}
            style={{
              background: 'var(--surface)', border: '1px solid var(--border)',
              color: 'var(--text)', padding: '8px 12px', borderRadius: '6px',
              fontSize: '13px', fontFamily: 'var(--font-mono)', width: '300px',
            }}
          />
          <button
            onClick={() => runAnalysis(filePath)}
            disabled={loading || !filePath}
            style={{
              background: 'var(--primary)', color: 'var(--bg)',
              padding: '8px 16px', borderRadius: '6px', border: 'none',
              fontWeight: 600, fontSize: '13px', cursor: 'pointer',
              opacity: loading ? 0.5 : 1,
            }}
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
          <button
            onClick={loadDemo}
            title="Load synthetic demo data (marked as demo while displayed)"
            style={{
              background: 'transparent', color: 'var(--primary)',
              padding: '8px 12px', borderRadius: '6px', border: '1px dashed var(--border)',
              fontSize: '12px', cursor: 'pointer',
            }}
          >
            Demo data
          </button>
          {hasKey && (
            <button
              onClick={clearKey}
              title="Clear the stored API key and sign out"
              style={{
                background: 'transparent', color: 'var(--text-dim)',
                padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)',
                fontSize: '12px', cursor: 'pointer',
              }}
            >
              Clear key
            </button>
          )}
        </div>
      </header>

      {/* Persistent demo marker — stays visible while demo content is shown. */}
      {analysis?.demo && (
        <div style={{
          background: 'rgba(255,170,0,0.12)', border: '2px dashed var(--warning)',
          borderRadius: '8px', padding: '10px 14px', marginBottom: '16px',
          color: 'var(--warning)', fontSize: '13px', fontWeight: 600,
        }}>
          DEMO DATA — synthetic sample, not an analysis of a capture. Every value below is
          invented for layout demonstration.
        </div>
      )}

      {/* Compatibility banner (legacy or unsupported stored result). */}
      {compatibilityNotes.length > 0 && (
        <div style={{
          background: 'rgba(255,170,0,0.08)', border: '1px solid var(--warning)',
          borderRadius: '8px', padding: '10px 14px', marginBottom: '16px',
          color: 'var(--warning)', fontSize: '12px', lineHeight: 1.6,
        }}>
          {compatibilityNotes.map((note, i) => <div key={i}>{note}</div>)}
        </div>
      )}

      {/* API key prompt (v0.2.1) — shown when no key is set. */}
      {!hasKey && (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: '8px', padding: '20px', marginBottom: '20px',
          maxWidth: '480px', margin: '0 auto 20px',
        }}>
          <h2 style={{ fontSize: '16px', color: 'var(--text)', marginBottom: '8px' }}>
            API key required
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginBottom: '16px' }}>
            Enter the GHOSTWIRE API key to analyze PCAPs. The key is stored in your
            browser only; it is never baked into the dashboard bundle.
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input
              type="password"
              placeholder="API key..."
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && connectKey()}
              style={{
                flex: 1, background: 'var(--bg)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: '8px 12px', borderRadius: '6px',
                fontSize: '13px', fontFamily: 'var(--font-mono)',
              }}
            />
            <button
              onClick={connectKey}
              disabled={!keyInput.trim()}
              style={{
                background: 'var(--primary)', color: 'var(--bg)',
                padding: '8px 16px', borderRadius: '6px', border: 'none',
                fontWeight: 600, fontSize: '13px', cursor: 'pointer',
                opacity: keyInput.trim() ? 1 : 0.5,
              }}
            >
              Connect
            </button>
          </div>
        </div>
      )}

      {/* Saved jobs: reopen a stored result (including a legacy summary). */}
      <div style={{
        display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap',
        marginBottom: '16px', fontSize: '11px', color: 'var(--text-dim)',
      }}>
        <span>Saved jobs:</span>
        <input
          type="text"
          placeholder="job id..."
          value={jobIdInput}
          onChange={(e) => setJobIdInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && openJob(jobIdInput.trim())}
          style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            color: 'var(--text)', padding: '4px 8px', borderRadius: '4px',
            fontSize: '11px', fontFamily: 'var(--font-mono)', width: '280px',
          }}
        />
        <button
          onClick={() => openJob(jobIdInput.trim())}
          disabled={!jobIdInput.trim()}
          style={{
            background: 'transparent', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: '4px',
            padding: '4px 10px', fontSize: '11px', cursor: 'pointer',
          }}
        >
          Open
        </button>
        {jobs.length === 0 && <span>(none stored)</span>}
        {jobs.map((job) => (
          <button
            key={job.id}
            onClick={() => openJob(job.id)}
            title={job.file_path}
            style={{
              background: 'var(--surface)', color: 'var(--text-dim)',
              border: `1px solid ${job.compatibility?.status === 'legacy' ? 'var(--warning)'
                : job.compatibility?.status === 'unsupported' ? 'var(--danger)' : 'var(--border)'}`,
              borderRadius: '4px', padding: '3px 8px', fontSize: '10px',
              fontFamily: 'var(--font-mono)', cursor: 'pointer',
            }}
          >
            {job.id.slice(0, 8)} · {job.status}
            {job.compatibility?.status === 'legacy' ? ' · legacy' : ''}
            {job.compatibility?.status === 'unsupported' ? ' · unsupported' : ''}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div style={{
          background: 'rgba(255,51,102,0.1)', border: '1px solid var(--danger)',
          borderRadius: '8px', padding: '12px', marginBottom: '20px',
          color: 'var(--danger)', fontSize: '13px',
        }}>
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-dim)' }}>
          <div style={{
            width: '40px', height: '40px', margin: '0 auto 16px',
            border: '3px solid var(--border)', borderTop: '3px solid var(--primary)',
            borderRadius: '50%', animation: 'spin 1s linear infinite',
          }} />
          <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
          Analyzing network traffic...
        </div>
      )}

      {/* Dashboard */}
      {analysis && !loading && (
        <div>
          {/* Coverage / summary banner */}
          {coverage && (
            <div style={{
              background: coverage.status === 'complete'
                ? 'rgba(0,255,159,0.06)' : 'rgba(255,170,0,0.08)',
              border: `1px solid ${coverage.status === 'complete' ? 'var(--border)' : 'var(--warning)'}`,
              borderRadius: '8px', padding: '10px 14px', marginBottom: '16px',
              fontSize: '12px', color: coverage.status === 'complete' ? 'var(--text-dim)' : 'var(--warning)',
              lineHeight: 1.6,
            }}>
              <strong>{coverage.status.toUpperCase()}</strong> — {coverage.label}
              {coverage.reasons.slice(0, 3).map((r, i) => <div key={i}>• {r}</div>)}
              {analysis.summary && <div style={{ marginTop: '4px' }}>{analysis.summary}</div>}
            </div>
          )}

          {/* Stats Row — each tile names its unit. */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '12px', marginBottom: '20px',
          }}>
            <Stat label="Frames" value={analysis.packets_total ?? MISSING} unit="read from capture" />
            <Stat
              label="Decoded"
              value={analysis.packets_decoded ?? coverage?.frames_decoded ?? MISSING}
              unit="frames with IP + L4"
            />
            <Stat label="Sessions" value={analysis.sessions_total ?? MISSING} unit="TCP 5-tuples" />
            <Stat
              label="Findings"
              value={counts?.findings_total ?? analysis.findings?.length ?? MISSING}
              unit={counts?.findings_returned != null ? `${counts.findings_returned} returned` : 'rule interpretations'}
              color={(counts?.findings_total ?? 0) > 0 ? 'var(--warning)' : 'var(--primary)'}
            />
            <Stat
              label="Session rows"
              value={counts?.sessions_returned ?? analysis.threats.length}
              unit={`min-score ${analysis.selection?.filter?.min_score ?? MISSING}`}
            />
            <Stat
              label="Beacons"
              value={analysis.beacons_detected ?? MISSING}
              unit="above beacon threshold"
              color={(analysis.beacons_detected ?? 0) > 0 ? 'var(--danger)' : 'var(--text)'}
            />
            <Stat
              label="Rule matches"
              value={analysis.c2_matches ?? MISSING}
              unit="distinct (tool, subject)"
              color={(analysis.c2_matches ?? 0) > 0 ? 'var(--warning)' : 'var(--text-dim)'}
            />
            <Stat label="DNS findings" value={analysis.dns_threats ?? MISSING} unit="standalone (no session)" />
            <Stat label="TLS FP" value={analysis.tls_fingerprints ?? MISSING} unit="handshakes" />
            <Stat label="HTTP FP" value={analysis.http_fingerprints ?? MISSING} unit="requests" />
            <Stat
              label="Elapsed"
              value={analysis.analysis_time == null ? MISSING : `${analysis.analysis_time.toFixed(3)}s`}
              unit="measured wall clock"
              color="var(--text-dim)"
            />
          </div>

          <ThreatPanel threats={analysis.threats} analysis={analysis} />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <Timeline threats={analysis.threats} analysis={analysis} />
            <BeaconChart threats={analysis.threats} analysis={analysis} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <NetworkGraph threats={analysis.threats} />
            <ProtoBreakdown analysis={analysis} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <SessionView analysis={analysis} threats={analysis.threats} />
            <FingerprintTable analysis={analysis} />
          </div>

          {analysis.selection?.explanation && (
            <div style={{
              fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)',
              borderTop: '1px solid var(--border)', paddingTop: '10px',
            }}>
              {analysis.selection.explanation}
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!analysis && !loading && !error && (
        <div style={{ textAlign: 'center', padding: '80px 20px', color: 'var(--text-dim)' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔌</div>
          <h2 style={{ fontSize: '20px', color: 'var(--text)', marginBottom: '8px' }}>
            Feed the wire
          </h2>
          <p style={{ fontSize: '14px', maxWidth: '420px', margin: '0 auto' }}>
            Enter a PCAP file path and click Analyze. Every finding will show the frame,
            rule and observed value behind it. Demo data is synthetic and stays labelled.
          </p>
        </div>
      )}
    </div>
  )
}

export default App
