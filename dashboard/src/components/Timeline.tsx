import type { ThreatEntry } from '../App'

interface Props {
  threats: ThreatEntry[]
}

export default function Timeline({ threats }: Props) {
  // Visual timeline showing threat sessions over time
  const maxScore = Math.max(...threats.map(t => t.overall_score), 0.01)

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
        📅 Session Timeline
      </h3>

      <div style={{ position: 'relative', height: '120px' }}>
        {/* Time axis */}
        <div style={{
          position: 'absolute', bottom: 0, left: 0, right: 0,
          height: '1px', background: 'var(--border)',
        }} />

        {/* Threat markers */}
        {threats.map((t, i) => {
          const x = (i / Math.max(threats.length - 1, 1)) * 100
          const h = (t.overall_score / maxScore) * 80
          const color = t.overall_score > 0.6 ? 'var(--danger)' : t.overall_score > 0.3 ? 'var(--warning)' : 'var(--info)'

          return (
            <div key={i} style={{
              position: 'absolute',
              left: `${x}%`,
              bottom: '20px',
              transform: 'translateX(-50%)',
              display: 'flex', flexDirection: 'column', alignItems: 'center',
            }}>
              <div style={{
                width: '6px', height: `${h}px`,
                background: color,
                borderRadius: '3px 3px 0 0',
                boxShadow: `0 0 8px ${color}40`,
                transition: 'height 0.5s ease',
              }} />
              <div style={{
                marginTop: '4px', fontSize: '9px', fontFamily: 'var(--font-mono)',
                color: 'var(--text-dim)', maxWidth: '80px', textAlign: 'center',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {t.target.split('-')[1]?.split(':')[0] || t.target.slice(0, 12)}
              </div>
            </div>
          )
        })}
      </div>

      {threats.length === 0 && (
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
          No threat sessions to display
        </div>
      )}
    </div>
  )
}