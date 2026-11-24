import type { AnalysisData, ThreatEntry } from '../types'

interface Props {
  threats: ThreatEntry[]
  analysis?: AnalysisData
}

function fmtClock(ts: number): string {
  // Capture timestamps are epoch seconds; keep sub-second precision because a
  // short capture spans milliseconds.
  const d = new Date(ts * 1000)
  return `${d.toISOString().slice(11, 23)}Z`
}

/**
 * Conversation timeline.
 *
 * 0.2.x positioned bars by their index in the score-sorted list, so the x axis
 * was "rank", not time. This version positions by the earliest observed
 * timestamp of the conversation's findings, on the capture's real time axis.
 * When a result carries no timestamps (legacy summaries, or a decode with no
 * observations) it reports the axis as unavailable instead of inventing one.
 */
export default function Timeline({ threats, analysis }: Props) {
  const observations = analysis?.observations || []
  const findings = analysis?.findings || []
  const observationsById = new Map(observations.map(o => [o.observation_id, o]))

  const points = threats.map((t, index) => {
    const ids = t.finding_ids || []
    const times: number[] = []
    for (const id of ids) {
      const finding = findings.find(f => f.finding_id === id)
      for (const oid of finding?.observation_ids || []) {
        const obs = observationsById.get(oid)
        if (obs && typeof obs.timestamp === 'number') times.push(obs.timestamp)
      }
    }
    return {
      index,
      threat: t,
      time: times.length ? Math.min(...times) : null,
      score: t.overall_score,
    }
  })

  const timed = points.filter(p => p.time !== null) as Array<{ index: number; threat: ThreatEntry; time: number; score: number }>
  const first = analysis?.run?.capture?.first_timestamp
  const last = analysis?.run?.capture?.last_timestamp
  const axisStart = timed.length ? Math.min(...timed.map(p => p.time), first ?? Infinity) : first
  const axisEnd = timed.length ? Math.max(...timed.map(p => p.time), last ?? -Infinity) : last
  const hasAxis = timed.length > 0 && axisStart !== null && axisStart !== undefined
    && axisEnd !== null && axisEnd !== undefined
  const span = hasAxis ? Math.max((axisEnd as number) - (axisStart as number), 0.001) : 1

  const maxScore = Math.max(...points.map(p => p.score), 0.01)

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        📅 Conversation Timeline
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '10px' }}>
        x: first observed timestamp of the conversation's findings · y: conversation score.
        {hasAxis && <> Axis: {fmtClock(axisStart as number)} → {fmtClock(axisEnd as number)} ({span.toFixed(3)} s).</>}
      </p>

      {!hasAxis ? (
        <div style={{ textAlign: 'center', padding: '46px 12px', color: 'var(--text-dim)', fontSize: '13px' }}>
          {points.length === 0
            ? 'No conversation rows in this result.'
            : 'Observed timestamps are unavailable in this result, so a time axis cannot be drawn.'}
        </div>
      ) : (
        <div style={{ position: 'relative', height: '130px' }}>
          <div style={{ position: 'absolute', bottom: '24px', left: 0, right: 0, height: '1px', background: 'var(--border)' }} />
          {timed.map(({ threat, time, score }) => {
            const x = ((time - (axisStart as number)) / span) * 100
            const h = (score / maxScore) * 70
            const color = score > 0.6 ? 'var(--danger)' : score > 0.3 ? 'var(--warning)' : 'var(--info)'
            return (
              <div key={threat.target} style={{
                position: 'absolute', left: `${x}%`, bottom: '24px',
                transform: 'translateX(-50%)',
                display: 'flex', flexDirection: 'column', alignItems: 'center',
              }} title={`${threat.target} — score ${score.toFixed(3)} at ${fmtClock(time)}`}>
                <div style={{
                  width: '6px', height: `${Math.max(3, h)}px`, background: color,
                  borderRadius: '3px 3px 0 0',
                }} />
                <div style={{
                  marginTop: '3px', fontSize: '9px', fontFamily: 'var(--font-mono)',
                  color: 'var(--text-dim)', maxWidth: '90px', textAlign: 'center',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {score.toFixed(2)}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {hasAxis && points.length > timed.length && (
        <div style={{ marginTop: '6px', fontSize: '10px', color: 'var(--warning)' }}>
          {points.length - timed.length} conversation row(s) have no observed timestamp and are not plotted.
        </div>
      )}
    </div>
  )
}
