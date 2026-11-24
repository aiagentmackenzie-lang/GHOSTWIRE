import type { AnalysisData } from '../types'

interface Props {
  analysis: AnalysisData
}

const COLORS = ['#00aaff', '#00ff9f', '#ffaa00', '#ff3366', '#b06cff', '#888']

/**
 * Protocol breakdown by decoded packet count.
 *
 * 0.2.x mixed units: HTTP fingerprint count, TLS fingerprint count, SSH
 * fingerprint count, DNS *finding* count and `packets_total − those counts` all
 * in one denominator. A one-packet DNS capture rendered as "DNS 50%, Other
 * 50%" because the finding count equalled the packet count. This version uses
 * `protocol_counts` (packets, one unit) and the frame total as denominator,
 * and says so.
 */
export default function ProtoBreakdown({ analysis }: Props) {
  const counts = analysis.protocol_counts
  const total = analysis.packets_total || 0

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        📊 Protocol Breakdown
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '12px' }}>
        Unit: frames, classified by decoded L7 protocol (fallback L4). Denominator:
        {' '}{total} frame(s) read.
      </p>

      {!counts || Object.keys(counts).length === 0 ? (
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
          Per-protocol frame counts are unavailable in this result.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6)
            .map(([proto, count], i) => {
              const pct = total > 0 ? (count / total) * 100 : 0
              return (
                <div key={proto}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text)' }}>{proto}</span>
                    <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                      {count} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div style={{ height: '8px', background: 'var(--surface2)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${Math.max(pct, 1)}%`,
                      background: COLORS[i % COLORS.length], borderRadius: '4px',
                    }} />
                  </div>
                </div>
              )
            })}
        </div>
      )}
    </div>
  )
}
