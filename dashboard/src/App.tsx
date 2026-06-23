import { useState, useCallback } from 'react'
import ThreatPanel from './components/ThreatPanel'
import Timeline from './components/Timeline'
import BeaconChart from './components/BeaconChart'
import NetworkGraph from './components/NetworkGraph'
import SessionView from './components/SessionView'
import ProtoBreakdown from './components/ProtoBreakdown'
import FingerprintTable from './components/FingerprintTable'

interface AnalysisData {
  ghostwire_version: string
  file: string
  analysis_time: number
  packets_total: number
  sessions_total: number
  tls_fingerprints: number
  http_fingerprints: number
  ssh_fingerprints: number
  beacons_detected: number
  dns_threats: number
  c2_matches: number
  threats: ThreatEntry[]
}

export interface ThreatEntry {
  target: string
  target_type: string
  overall_score: number
  confidence: string
  beacon_score: number | null
  c2_matches: any[]
  dns_threats: any[]
  iocs: string[]
  mitre_techniques: string[]
  summary: string
}

function App() {
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filePath, setFilePath] = useState('')

  // API key: operator-entered, stored in browser localStorage (v0.2.1). The
  // key is NEVER baked into the JS bundle — that would ship the secret to
  // anyone who loads /, defeating API auth. VITE_API_TOKEN is kept ONLY as a
  // local-dev convenience so a developer can skip the prompt.
  //
  // XSS note: storing the key in localStorage exposes it to XSS. Acceptable
  // here because the dashboard ships no third-party JS and never sets
  // innerHTML from user/network input. An httpOnly-cookie session is the
  // harder bar (roadmap, not v0.2.1).
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

  // A 401 means the stored/entered key is wrong or expired: drop it, stop
  // loading, and surface the prompt again with a clear message.
  const handle401 = (msg: string) => {
    localStorage.removeItem(STORAGE_KEY)
    setApiKey('')
    setError(msg)
    setLoading(false)
  }

  const runAnalysis = useCallback(async (path: string) => {
    setLoading(true)
    setError(null)
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
          setAnalysis(job.summary)
          setLoading(false)
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
    } catch (e: any) {
      setError('Failed to connect to GHOSTWIRE API. Is the server running?')
      setLoading(false)
    }
  }, [API_BASE, apiKey])

  // Load demo data
  const loadDemo = useCallback(() => {
    setAnalysis({
      ghostwire_version: '0.2.1',
      file: 'samples/c2_beacon_test.pcap',
      analysis_time: 0.02,
      packets_total: 110,
      sessions_total: 51,
      tls_fingerprints: 2,
      http_fingerprints: 50,
      ssh_fingerprints: 0,
      beacons_detected: 1,
      dns_threats: 0,
      c2_matches: 1,
      threats: [
        {
          target: '185.220.101.34:443-192.168.1.50:49152',
          target_type: 'session',
          overall_score: 0.82,
          confidence: 'HIGH',
          beacon_score: 0.95,
          c2_matches: [{ tool_name: 'cobalt_strike', confidence: 0.85, match_type: 'ja4' }],
          dns_threats: [],
          iocs: ['C2:cobalt_strike (t13d1516h2_...)'],
          mitre_techniques: ['T1071.001', 'T1573.001'],
          summary: 'C2 beacon detected (jitter: 0.004); Known C2: cobalt_strike',
        },
        {
          target: '10.0.0.5:49999-45.33.32.156:443',
          target_type: 'session',
          overall_score: 0.45,
          confidence: 'MEDIUM',
          beacon_score: 0.52,
          c2_matches: [],
          dns_threats: [{ domain: 'x7f3a9b2.malware-domain.net', threat_type: 'dga', score: 0.7 }],
          iocs: ['DNS:x7f3a9b2.malware-domain.net (dga)'],
          mitre_techniques: ['T1071.004'],
          summary: 'Possible beacon (jitter: 0.28); DNS threats: dga',
        },
        {
          target: '192.168.1.10:54321-8.8.8.8:53',
          target_type: 'session',
          overall_score: 0.31,
          confidence: 'LOW',
          beacon_score: null,
          c2_matches: [],
          dns_threats: [{ domain: 'aGVsbG8.dgahost.com', threat_type: 'tunneling', score: 0.5 }],
          iocs: ['DNS:aGVsbG8.dgahost.com (tunneling)'],
          mitre_techniques: [],
          summary: 'DNS threats: tunneling',
        },
      ],
    })
  }, [])

  return (
    <div style={{ minHeight: '100vh', padding: '20px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        borderBottom: '1px solid var(--border)', paddingBottom: '16px', marginBottom: '24px',
      }}>
        <div>
          <h1 style={{
            fontSize: '24px', fontWeight: 700, letterSpacing: '-0.5px',
            color: 'var(--primary)', textShadow: '0 0 20px rgba(0,255,159,0.3)',
          }}>
            GHOSTWIRE
          </h1>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            Network Forensics Engine v0.2.1
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
            style={{
              background: 'transparent', color: 'var(--primary)',
              padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border)',
              fontSize: '12px', cursor: 'pointer',
            }}
          >
            Demo
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
          {/* Stats Row */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: '12px', marginBottom: '24px',
          }}>
            {[
              { label: 'Packets', value: analysis.packets_total, color: 'var(--text)' },
              { label: 'Sessions', value: analysis.sessions_total, color: 'var(--text)' },
              { label: 'Beacons', value: analysis.beacons_detected, color: analysis.beacons_detected > 0 ? 'var(--danger)' : 'var(--primary)' },
              { label: 'C2 Matches', value: analysis.c2_matches, color: analysis.c2_matches > 0 ? 'var(--warning)' : 'var(--text-dim)' },
              { label: 'DNS Threats', value: analysis.dns_threats, color: analysis.dns_threats > 0 ? 'var(--warning)' : 'var(--text-dim)' },
              { label: 'TLS FP', value: analysis.tls_fingerprints, color: 'var(--info)' },
              { label: 'HTTP FP', value: analysis.http_fingerprints, color: 'var(--info)' },
              { label: 'Time', value: `${analysis.analysis_time}s`, color: 'var(--text-dim)' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{
                background: 'var(--surface)', borderRadius: '8px',
                padding: '12px 16px', border: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {label}
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: color as string, fontFamily: 'var(--font-mono)' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Threat Panel */}
          <ThreatPanel threats={analysis.threats} />

          {/* Charts Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <Timeline threats={analysis.threats} />
            <BeaconChart threats={analysis.threats} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <NetworkGraph threats={analysis.threats} />
            <ProtoBreakdown analysis={analysis} />
          </div>

          {/* Session View & Fingerprints */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <SessionView threats={analysis.threats} />
            <FingerprintTable analysis={analysis} />
          </div>
        </div>
      )}

      {/* Empty State */}
      {!analysis && !loading && !error && (
        <div style={{ textAlign: 'center', padding: '80px 20px', color: 'var(--text-dim)' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔌</div>
          <h2 style={{ fontSize: '20px', color: 'var(--text)', marginBottom: '8px' }}>
            Feed the wire
          </h2>
          <p style={{ fontSize: '14px', maxWidth: '400px', margin: '0 auto' }}>
            Enter a PCAP file path and click Analyze, or click Demo to see GHOSTWIRE in action.
          </p>
        </div>
      )}
    </div>
  )
}

export default App