import type { ThreatEntry } from '../App'

interface Props {
  threats: ThreatEntry[]
}

export default function NetworkGraph({ threats }: Props) {
  // Force-directed network graph showing IP connections
  // Extract unique IPs from threat targets
  const nodes: { id: string; type: string; score: number }[] = []
  const edges: { from: string; to: string; score: number }[] = []

  threats.forEach(t => {
    const parts = t.target.split('-')
    if (parts.length >= 2) {
      const src = parts[0]
      const dst = parts[1]

      if (!nodes.find(n => n.id === src)) nodes.push({ id: src, type: 'source', score: t.overall_score })
      if (!nodes.find(n => n.id === dst)) nodes.push({ id: dst, type: 'dest', score: t.overall_score })
      edges.push({ from: src, to: dst, score: t.overall_score })
    }
  })

  // Simple circular layout
  const cx = 200, cy = 80, r = 60
  const positioned = nodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2
    return { ...n, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) }
  })

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
        🕸️ Network Graph
      </h3>

      <svg width="100%" height="160" viewBox="0 0 400 160">
        {/* Edges */}
        {edges.map((e, i) => {
          const from = positioned.find(n => n.id === e.from)
          const to = positioned.find(n => n.id === e.to)
          if (!from || !to) return null
          return (
            <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={e.score > 0.6 ? 'var(--danger)' : e.score > 0.3 ? 'var(--warning)' : 'var(--border)'}
              strokeWidth={1 + e.score * 2} opacity={0.6} />
          )
        })}

        {/* Nodes */}
        {positioned.map((n, i) => (
          <g key={i}>
            <circle cx={n.x} cy={n.y} r={6}
              fill={n.type === 'source' ? 'var(--primary)' : 'var(--danger)'}
              opacity={0.8} />
            <text x={n.x} y={n.y + 18} textAnchor="middle"
              fill="var(--text-dim)" fontSize="8" fontFamily="var(--font-mono)">
              {n.id.split(':').slice(0, 1)[0]}
            </text>
          </g>
        ))}
      </svg>

      {nodes.length === 0 && (
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
          No network connections to display
        </div>
      )}

      <div style={{ display: 'flex', gap: '16px', justifyContent: 'center', marginTop: '4px' }}>
        <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--primary)' }}>●</span> Internal
        </span>
        <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--danger)' }}>●</span> External / Threat
        </span>
      </div>
    </div>
  )
}