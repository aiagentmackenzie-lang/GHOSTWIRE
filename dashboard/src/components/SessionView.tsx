import type { ThreatEntry } from '../App'

interface Props {
  threats: ThreatEntry[]
}

export default function SessionView({ threats }: Props) {
  if (!threats.length) {
    return (
      <div style={{
        background: 'var(--surface)', borderRadius: '8px',
        border: '1px solid var(--border)', padding: '16px',
      }}>
        <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
          🔍 Session Inspector
        </h3>
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
          No sessions to inspect
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
        🔍 Session Inspector
      </h3>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {threats.slice(0, 5).map((t, i) => {
          const color = t.overall_score > 0.6 ? 'var(--danger)' : t.overall_score > 0.3 ? 'var(--warning)' : 'var(--info)'
          return (
            <div key={i} style={{
              background: 'var(--surface2)', borderRadius: '6px',
              padding: '10px 12px', border: `1px solid ${color}30`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <code style={{ fontSize: '11px', color: 'var(--text)' }}>{t.target}</code>
                <span style={{ fontSize: '11px', color, fontWeight: 600 }}>
                  {t.confidence}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', lineHeight: '1.6' }}>
                {t.summary}
              </div>
              {t.mitre_techniques.length > 0 && (
                <div style={{ display: 'flex', gap: '4px', marginTop: '6px', flexWrap: 'wrap' }}>
                  {t.mitre_techniques.map((m, j) => (
                    <span key={j} style={{
                      background: 'var(--surface)', borderRadius: '3px',
                      padding: '1px 6px', fontSize: '9px', fontFamily: 'var(--font-mono)',
                      color: 'var(--info)', border: '1px solid var(--border)',
                    }}>
                      {m}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}