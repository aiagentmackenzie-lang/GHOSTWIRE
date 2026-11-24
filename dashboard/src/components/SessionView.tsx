import type { AnalysisData, Finding, Observation } from '../types'

interface Props {
  analysis?: AnalysisData
  threats?: unknown[]
}

function observedRows(finding: Finding, byId: Map<string, Observation>): Observation[] {
  return finding.observation_ids
    .map(id => byId.get(id))
    .filter((o): o is Observation => Boolean(o))
}

/**
 * Finding inspector.
 *
 * This is the panel an analyst opens to answer "where is this from?". Each
 * finding shows its rule, frame reference, observed value, and the score
 * contribution of each reason. A stream-derived finding additionally shows the
 * sequence ranges it came from and any capture gap in that range — a finding
 * cannot be supported by bytes the capture does not contain.
 */
export default function SessionView({ analysis }: Props) {
  const findings = analysis?.findings || []
  const threats = analysis?.threats || []
  const legacy = Boolean(analysis && !analysis.schema_version)
  const observations = analysis?.observations || []
  const byId = new Map(observations.map(o => [o.observation_id, o]))

  if (!analysis) {
    return null
  }

  if (!findings.length) {
    return (
      <div style={{
        background: 'var(--surface)', borderRadius: '8px',
        border: '1px solid var(--border)', padding: '16px',
      }}>
        <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-dim)' }}>
          🔍 Finding Inspector
        </h3>
        <div style={{ textAlign: 'center', padding: '26px', color: 'var(--text-dim)', fontSize: '13px' }}>
          {legacy
            ? 'Structured findings are unavailable in this saved analysis. Recorded rows: '
              + `${threats.length}.`
            : analysis.coverage?.status === 'unsupported_decode'
              ? 'The capture could not be decoded, so there are no observations to inspect.'
              : 'No finding was recorded for this capture.'}
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        🔍 Finding Inspector
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '10px' }}>
        {findings.length} finding(s), each with its frame and rule. Findings are not
        filtered by the conversation score threshold.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '420px', overflowY: 'auto' }}>
        {findings.slice(0, 8).map((f) => {
          const obs = observedRows(f, byId)
          const first = obs[0]
          return (
            <div key={f.finding_id} style={{
              background: 'var(--surface2)', borderRadius: '6px',
              padding: '10px 12px', border: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px', marginBottom: '4px' }}>
                <code style={{ fontSize: '10px', color: 'var(--text)', wordBreak: 'break-all' }}>
                  {f.subject.value}
                </code>
                <span style={{ fontSize: '10px', color: 'var(--info)', whiteSpace: 'nowrap' }}>
                  {f.kind}
                </span>
              </div>

              <div style={{ fontSize: '10px', color: 'var(--text-dim)', lineHeight: 1.6 }}>
                <div>
                  frame {first ? first.frame : 'n/a'}
                  {first?.timestamp != null && ` · t=${first.timestamp}`}
                  {first && ` · ${first.transport} ${first.direction}`}
                  {first && ` · ${first.src.ip}:${first.src.port} (${first.src.role}) → ${first.dst.ip}:${first.dst.port} (${first.dst.role})`}
                </div>
                <div>
                  field <code>{first?.field ?? 'n/a'}</code>
                  {first?.normalized_value ? ` · normalized “${first.normalized_value}”` : ''}
                </div>
                <div>
                  rule <code>{f.rule.id}</code>@{f.rule.revision} · {f.match_method} ·
                  score {f.score.toFixed(3)} ({f.score_scale})
                </div>
                {first?.stream && (
                  <div>
                    stream: {first.stream.seq_ranges.length} range(s)
                    {first.stream.gaps.length > 0 && (
                      <span style={{ color: 'var(--warning)' }}>
                        {' '}· {first.stream.gaps.length} gap(s), {first.stream.missing_bytes} missing bytes
                      </span>
                    )}
                    {' '}· {first.stream.captured_payload_bytes} captured / {first.stream.distinct_stream_bytes} distinct bytes
                  </div>
                )}
              </div>

              <div style={{ marginTop: '6px', fontSize: '10px', color: 'var(--text-dim)' }}>
                {f.reasons.slice(0, 3).map(r => (
                  <div key={r.code}>
                    • {r.detail}
                    {r.contribution != null && (
                      <span style={{ color: 'var(--info)' }}> (+{r.contribution} {r.scale})</span>
                    )}
                  </div>
                ))}
              </div>

              {f.tool_inference && (
                <div style={{ marginTop: '6px', fontSize: '9px', color: 'var(--warning)' }}>
                  Tool attribution is an inference: {f.tool_inference.tool}.
                  {' '}{f.tool_inference.caveat}
                </div>
              )}
            </div>
          )
        })}
        {findings.length > 8 && (
          <div style={{ fontSize: '10px', color: 'var(--text-dim)', textAlign: 'center' }}>
            … {findings.length - 8} further finding(s) in the JSON result
          </div>
        )}
      </div>
    </div>
  )
}
