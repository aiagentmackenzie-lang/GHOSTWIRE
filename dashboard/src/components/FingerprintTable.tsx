interface Props {
  analysis: any
}

export default function FingerprintTable({ analysis }: Props) {
  const hasFingerprints = analysis.tls_fingerprints > 0 || analysis.http_fingerprints > 0 || analysis.ssh_fingerprints > 0

  if (!hasFingerprints) {
    return (
      <div style={{
        background: 'var(--surface)', borderRadius: '8px',
        border: '1px solid var(--border)', padding: '16px',
      }}>
        <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
          🔐 Fingerprints
        </h3>
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
          No fingerprints extracted
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
        🔐 Fingerprints
      </h3>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {[
          { type: 'TLS (JA4+)', count: analysis.tls_fingerprints, color: 'var(--primary)' },
          { type: 'HTTP (JA4H)', count: analysis.http_fingerprints, color: 'var(--info)' },
          { type: 'SSH (JA4SSH)', count: analysis.ssh_fingerprints, color: 'var(--warning)' },
        ].filter(f => f.count > 0).map(f => (
          <div key={f.type} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '8px 12px', background: 'var(--surface2)', borderRadius: '6px',
          }}>
            <span style={{ fontSize: '12px', color: 'var(--text)' }}>{f.type}</span>
            <span style={{
              fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 600,
              color: f.color as string,
            }}>
              {f.count}
            </span>
          </div>
        ))}

        {analysis.c2_matches > 0 && (
          <div style={{
            padding: '8px 12px', background: 'rgba(255,51,102,0.08)',
            borderRadius: '6px', border: '1px solid var(--danger)30',
          }}>
            <span style={{ fontSize: '12px', color: 'var(--danger)', fontWeight: 600 }}>
              ⚠ {analysis.c2_matches} C2 fingerprint match{analysis.c2_matches > 1 ? 'es' : ''}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}