import type { AnalysisData, Finding, ThreatEntry } from '../types'

interface Props {
  threats: ThreatEntry[]
  analysis?: AnalysisData
}

const confidenceColor: Record<string, string> = {
  CRITICAL: '#ff3366',
  HIGH: '#ff6633',
  MEDIUM: '#ffaa00',
  LOW: '#00aaff',
  NEGLIGIBLE: '#888',
}

function frameLabel(finding: Finding | undefined, analysis?: AnalysisData): string {
  if (!finding) return '—'
  const byId = new Map((analysis?.observations || []).map(o => [o.observation_id, o]))
  const frames: number[] = []
  for (const oid of finding.observation_ids) {
    const obs = byId.get(oid)
    if (obs && obs.frame && !frames.includes(obs.frame)) frames.push(obs.frame)
  }
  if (frames.length) return frames.sort((a, b) => a - b).join(', ')
  return finding.scope === 'conversation' ? 'stream' : '—'
}

/**
 * Conversation table.
 *
 * A row is a conversation assessment (a score), not a "threat". The columns
 * name their unit: score on the weighted composite, findings contributing to
 * it, and the frame(s) of the observed subject. When the session threshold
 * removed every row but findings exist, that is stated — it is not an
 * all-clear.
 */
export default function ThreatPanel({ threats, analysis }: Props) {
  const findings = analysis?.findings || []
  const findingsById = new Map(findings.map(f => [f.finding_id, f]))
  const selection = analysis?.selection
  const coverage = analysis?.coverage
  const legacy = Boolean(analysis && !analysis.schema_version)
  const minScore = selection?.filter?.min_score

  if (!threats.length) {
    const hasFindings = findings.length > 0
    const unsupported = coverage?.status === 'unsupported_decode'
    const partial = coverage?.status === 'partial'
    return (
      <div style={{
        background: 'var(--surface)', borderRadius: '8px', padding: '18px',
        border: '1px solid var(--border)', marginBottom: '20px',
      }}>
        <div style={{ color: unsupported || partial ? 'var(--warning)' : 'var(--primary)', fontSize: '14px', marginBottom: '6px' }}>
          {unsupported
            ? '⚠ Coverage unsupported — this is not an all-clear'
            : partial
              ? '⚠ Partial coverage — results are incomplete'
              : hasFindings
                ? '◐ Findings exist below the session threshold'
                : '✓ No findings recorded'}
        </div>
        <div style={{ fontSize: '12px', color: 'var(--text-dim)', lineHeight: 1.6 }}>
          {legacy
            ? 'This saved analysis has no structured findings. Its recorded counts are shown above; per-finding evidence is unavailable.'
            : hasFindings && (selection?.counts?.sessions_total ?? 0) === 0
              ? `${findings.length} finding(s) were recorded. No TCP conversation was reconstructed, so there is no session score to filter — the findings stand on their own.`
              : hasFindings
                ? `${findings.length} finding(s) were recorded. No conversation scored at or above ${minScore ?? 'the'} threshold, so the session table is empty.`
                : coverage
                  ? coverage.label
                  : 'No conversation rows were returned.'}
        </div>
        {selection?.explanation && (
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
            {selection.explanation}
          </div>
        )}
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
        display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: 'var(--warning)', fontSize: '16px' }}>◐</span>
          <span style={{ fontWeight: 600, fontSize: '14px' }}>
            Conversation Assessments ({threats.length}
            {selection?.filter?.sessions_below_threshold
              ? ` of ${(threats.length + selection.filter.sessions_below_threshold)} scored`
              : ''})
          </span>
        </div>
        <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          score = weighted composite 0–1 · threshold {minScore ?? 'n/a'}
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Conversation', 'Score', 'Severity', 'Findings', 'Observed subject (frame)', 'Why the rule fired'].map(h => (
                <th key={h} style={{
                  padding: '8px 12px', textAlign: 'left', color: 'var(--text-dim)',
                  fontWeight: 500, fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {threats.map((t, i) => {
              const rowFindings = (t.finding_ids || [])
                .map(id => findingsById.get(id))
                .filter((f): f is Finding => Boolean(f))
              const first = rowFindings[0]
              const endpoints = t.endpoints
              return (
                <tr key={`${t.target}-${i}`} style={{ borderBottom: '1px solid var(--border)', verticalAlign: 'top' }}>
                  <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: '10px', maxWidth: '220px' }}>
                    {endpoints
                      ? <>{endpoints.src.ip}:{endpoints.src.port} → {endpoints.dst.ip}:{endpoints.dst.port}
                        <div style={{ color: 'var(--text-dim)' }}>
                          client: {t.client_side ?? 'unknown'} · {t.role_basis ?? 'role basis unavailable'}
                        </div>
                      </>
                      : <>{t.target}
                        <div style={{ color: 'var(--warning)' }}>direction unknown (legacy label)</div>
                      </>}
                  </td>
                  <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)' }}>
                    {t.overall_score.toFixed(3)}
                    {t.score_scale && (
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>{t.score_scale}</div>
                    )}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{
                      color: confidenceColor[t.confidence] || 'var(--text-dim)',
                      fontWeight: 600, fontSize: '10px', padding: '2px 7px', borderRadius: '4px',
                      background: `${confidenceColor[t.confidence] ?? '#888'}15`,
                      border: `1px solid ${confidenceColor[t.confidence] ?? '#888'}30`,
                    }}>
                      {t.confidence}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', fontSize: '11px' }}>
                    {t.finding_ids?.length ?? 'n/a'}
                    <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>contributing</div>
                  </td>
                  <td style={{ padding: '8px 12px', fontSize: '10px', maxWidth: '260px' }}>
                    {rowFindings.length ? (
                      rowFindings.slice(0, 2).map(f => (
                        <div key={f.finding_id} style={{ marginBottom: '3px' }}>
                          <code style={{ color: 'var(--text)' }}>{f.subject.value}</code>
                          <div style={{ color: 'var(--text-dim)' }}>
                            frame {frameLabel(f, analysis)} · {f.rule.id}@{f.rule.revision}
                          </div>
                        </div>
                      ))
                    ) : (
                      <span style={{ color: 'var(--text-dim)' }}>
                        {t.detail_unavailable?.length ? 'detail unavailable in this saved analysis' : 'no structured findings'}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '8px 12px', fontSize: '11px', color: 'var(--text-dim)', maxWidth: '300px' }}>
                    {first?.reasons?.length
                      ? first.reasons.slice(0, 3).map(r => <div key={r.code}>• {r.detail}</div>)
                      : t.summary}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {selection?.truncation?.sessions_truncated && (
        <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--warning)', borderTop: '1px solid var(--border)' }}>
          Ranked list truncated to {selection.truncation.sessions_limit} conversation rows
          (ordered by score, then session id). Not a filter.
        </div>
      )}
    </div>
  )
}
