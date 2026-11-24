import type { AnalysisData } from '../types'

interface Props {
  analysis: AnalysisData
}

/**
 * Fingerprint inventory.
 *
 * 0.2.x called any C2 rule match a "C2 fingerprint match" and labelled the
 * summary "Known C2". A fingerprint count is a count of extracted
 * fingerprints; a match is one rule interpretation of one of them. They are
 * different units and are shown separately here, with the rule that matched.
 */
export default function FingerprintTable({ analysis }: Props) {
  const rows = [
    { type: 'TLS handshakes', count: analysis.tls_fingerprints, unit: 'records fingerprinted', color: 'var(--primary)' },
    { type: 'HTTP requests', count: analysis.http_fingerprints, unit: 'requests fingerprinted', color: 'var(--info)' },
    { type: 'SSH banners', count: analysis.ssh_fingerprints, unit: 'banners fingerprinted', color: 'var(--warning)' },
  ].filter(f => f.count > 0)

  const findings = analysis.findings || []
  const ruleMatches = findings.filter(f => f.tool_inference)

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        🔐 Fingerprints &amp; Rule Matches
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '10px' }}>
        Fingerprint counts and rule matches use different units and are listed separately.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {rows.length === 0 && (
          <div style={{ textAlign: 'center', padding: '18px', color: 'var(--text-dim)', fontSize: '12px' }}>
            No fingerprints were extracted from the decoded traffic.
          </div>
        )}
        {rows.map(f => (
          <div key={f.type} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '8px 12px', background: 'var(--surface2)', borderRadius: '6px',
          }}>
            <span style={{ fontSize: '12px', color: 'var(--text)' }}>
              {f.type}
              <span style={{ fontSize: '9px', color: 'var(--text-dim)', marginLeft: '6px' }}>{f.unit}</span>
            </span>
            <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: f.color }}>
              {f.count}
            </span>
          </div>
        ))}

        {ruleMatches.length > 0 && (
          <div style={{
            padding: '8px 12px', background: 'rgba(255,51,102,0.08)',
            borderRadius: '6px', border: '1px solid var(--border)',
          }}>
            <div style={{ fontSize: '11px', color: 'var(--danger)', fontWeight: 600, marginBottom: '4px' }}>
              {ruleMatches.length} rule match(es) — observed-value matches, not verdicts
            </div>
            {ruleMatches.slice(0, 4).map(f => (
              <div key={f.finding_id} style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                {f.rule.id}@{f.rule.revision} → {f.tool_inference?.tool} (weight {f.score.toFixed(2)})
              </div>
            ))}
            {ruleMatches.length > 4 && (
              <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                … {ruleMatches.length - 4} further match(es)
              </div>
            )}
          </div>
        )}

        {analysis.findings === undefined && (
          <div style={{ fontSize: '10px', color: 'var(--warning)' }}>
            Structured rule matches are unavailable in this saved analysis; only the
            recorded counts are shown.
          </div>
        )}
      </div>
    </div>
  )
}
