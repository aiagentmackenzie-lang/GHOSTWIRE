import type { ThreatEntry } from '../types'

interface Props {
  threats: ThreatEntry[]
}

const ROLE_COLOR: Record<string, string> = {
  client: 'var(--primary)',
  server: 'var(--info)',
  unknown: 'var(--text-dim)',
}

/**
 * Conversation graph.
 *
 * The 0.2.x graph read the *canonical* session key ("smaller address first") as
 * the direction, so the request in the HTTP fixture was drawn backwards. Here
 * the arrow follows the observed wire direction recorded on the conversation,
 * and the node colour follows the role resolved from protocol evidence. When a
 * legacy row has no structured endpoints the graph says so rather than guessing
 * a direction from string order.
 */
export default function NetworkGraph({ threats }: Props) {
  const edges = threats
    .map((t) => {
      const endpoints = t.endpoints
      if (!endpoints) return null
      return { src: endpoints.src, dst: endpoints.dst, score: t.overall_score, target: t.target }
    })
    .filter((e): e is NonNullable<typeof e> => e !== null)

  const nodes: Array<{ id: string; role: string; label: string }> = []
  for (const edge of edges) {
    for (const side of [edge.src, edge.dst]) {
      const id = `${side.ip}:${side.port}`
      if (!nodes.find((n) => n.id === id)) {
        nodes.push({ id, role: side.role, label: `${side.ip}:${side.port}` })
      }
    }
  }

  const cx = 200, cy = 82, r = 58
  const positioned = nodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI / 2
    return { ...n, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) }
  })

  const missing = threats.length - edges.length

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        🕸️ Conversation Graph
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '8px' }}>
        Arrow: observed wire direction (src → dst). Node colour: role inferred from
        SYN / TLS / HTTP evidence; grey means the role could not be established.
      </p>

      <svg width="100%" height="165" viewBox="0 0 400 165">
        <defs>
          <marker id="gw-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 z" fill="var(--text-dim)" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          const from = positioned.find((n) => n.id === `${e.src.ip}:${e.src.port}`)
          const to = positioned.find((n) => n.id === `${e.dst.ip}:${e.dst.port}`)
          if (!from || !to) return null
          return (
            <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={e.score > 0.6 ? 'var(--danger)' : e.score > 0.3 ? 'var(--warning)' : 'var(--border)'}
              strokeWidth={1 + e.score * 2} opacity={0.7}
              markerEnd="url(#gw-arrow)" />
          )
        })}

        {positioned.map((n) => (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={6}
              fill={ROLE_COLOR[n.role] || 'var(--text-dim)'} opacity={0.85} />
            <text x={n.x} y={n.y + 18} textAnchor="middle"
              fill="var(--text-dim)" fontSize="8" fontFamily="var(--font-mono)">
              {n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label}
            </text>
          </g>
        ))}
      </svg>

      {edges.length === 0 && (
        <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-dim)', fontSize: '13px' }}>
          {threats.length === 0
            ? 'No conversation rows to display.'
            : 'Structured endpoints are unavailable in this result; direction cannot be shown.'}
        </div>
      )}
      {missing > 0 && edges.length > 0 && (
        <div style={{ fontSize: '10px', color: 'var(--warning)', marginTop: '4px' }}>
          {missing} row(s) lack structured endpoints and are not drawn.
        </div>
      )}

      <div style={{ display: 'flex', gap: '14px', justifyContent: 'center', marginTop: '4px', fontSize: '10px' }}>
        <span style={{ color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--primary)' }}>●</span> client
        </span>
        <span style={{ color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--info)' }}>●</span> server
        </span>
        <span style={{ color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--text-dim)' }}>●</span> role unknown
        </span>
      </div>
    </div>
  )
}
