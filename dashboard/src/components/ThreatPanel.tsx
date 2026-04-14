import type { ThreatEntry } from '../App'

interface Props {
  threats: ThreatEntry[]
}

const confidenceColor: Record<string, string> = {
  CRITICAL: '#ff3366',
  HIGH: '#ff6633',
  MEDIUM: '#ffaa00',
  LOW: '#00aaff',
  NEGLIGIBLE: '#888',
}

export default function ThreatPanel({ threats }: Props) {
  if (!threats.length) {
    return (
      <div style={{
        background: 'var(--surface)', borderRadius: '8px', padding: '24px',
        border: '1px solid var(--border)', marginBottom: '20px', textAlign: 'center',
      }}>
        <span style={{ color: 'var(--primary)', fontSize: '14px' }}>✓ No significant threats detected</span>
      </div>
    )
  }

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', marginBottom: '20px', overflow: 'hidden',
    }}>
      <div style={{
        padding: '12px 16px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: '8px',
      }}>
        <span style={{ color: 'var(--danger)', fontSize: '16px' }}>⚠</span>
        <span style={{ fontWeight: 600, fontSize: '14px' }}>
          Threats Detected ({threats.length})
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Target', 'Score', 'Confidence', 'Beacon', 'IOCs', 'Summary'].map(h => (
                <th key={h} style={{
                  padding: '8px 12px', textAlign: 'left', color: 'var(--text-dim)',
                  fontWeight: 500, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {threats.map((t, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{
                  padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: '11px',
                  maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {t.target}
                </td>
                <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)' }}>
                  <span style={{
                    display: 'inline-block', width: '40px', height: '6px',
                    background: 'var(--surface2)', borderRadius: '3px', position: 'relative',
                  }}>
                    <span style={{
                      position: 'absolute', left: 0, top: 0, height: '100%',
                      width: `${t.overall_score * 100}%`,
                      background: t.overall_score > 0.6 ? 'var(--danger)' : t.overall_score > 0.3 ? 'var(--warning)' : 'var(--info)',
                      borderRadius: '3px',
                    }} />
                  </span>
                  <span style={{ marginLeft: '6px' }}>{t.overall_score.toFixed(2)}</span>
                </td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    color: confidenceColor[t.confidence] || 'var(--text-dim)',
                    fontWeight: 600, fontSize: '11px',
                    padding: '2px 8px', borderRadius: '4px',
                    background: `${confidenceColor[t.confidence]}15`,
                    border: `1px solid ${confidenceColor[t.confidence]}30`,
                  }}>
                    {t.confidence}
                  </span>
                </td>
                <td style={{
                  padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: '12px',
                  color: (t.beacon_score || 0) > 0.5 ? 'var(--danger)' : 'var(--text-dim)',
                }}>
                  {t.beacon_score ? (t.beacon_score * 100).toFixed(0) + '%' : '—'}
                </td>
                <td style={{ padding: '8px 12px', fontSize: '11px', maxWidth: '150px' }}>
                  {t.iocs.slice(0, 2).map((ioc, j) => (
                    <div key={j} style={{
                      background: 'var(--surface2)', borderRadius: '4px', padding: '1px 6px',
                      marginBottom: '2px', fontFamily: 'var(--font-mono)', fontSize: '10px',
                    }}>
                      {ioc}
                    </div>
                  ))}
                </td>
                <td style={{ padding: '8px 12px', fontSize: '12px', color: 'var(--text-dim)', maxWidth: '250px' }}>
                  {t.summary}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}