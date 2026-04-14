interface Props {
  analysis: any
}

export default function ProtoBreakdown({ analysis }: Props) {
  // Simulated protocol breakdown (real data comes from API)
  const protocols = [
    { name: 'HTTP', count: analysis.http_fingerprints, color: '#00aaff' },
    { name: 'TLS', count: analysis.tls_fingerprints, color: '#00ff9f' },
    { name: 'SSH', count: analysis.ssh_fingerprints, color: '#ffaa00' },
    { name: 'DNS', count: analysis.dns_threats || 0, color: '#ff3366' },
    { name: 'Other', count: analysis.packets_total - analysis.http_fingerprints - analysis.tls_fingerprints - analysis.ssh_fingerprints, color: '#888' },
  ].filter(p => p.count > 0)

  const total = protocols.reduce((s, p) => s + p.count, 0) || 1

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
        📊 Protocol Breakdown
      </h3>

      {/* Horizontal bar chart */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {protocols.map(p => (
          <div key={p.name}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text)' }}>{p.name}</span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                {p.count} ({((p.count / total) * 100).toFixed(1)}%)
              </span>
            </div>
            <div style={{
              height: '8px', background: 'var(--surface2)', borderRadius: '4px',
              overflow: 'hidden',
            }}>
              <div style={{
                height: '100%', width: `${(p.count / total) * 100}%`,
                background: p.color, borderRadius: '4px',
                transition: 'width 0.5s ease',
                boxShadow: `0 0 8px ${p.color}40`,
              }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}