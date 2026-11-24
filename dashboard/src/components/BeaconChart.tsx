import type { AnalysisData, ThreatEntry } from '../types'

interface Props {
  threats: ThreatEntry[]
  analysis?: AnalysisData
}

/**
 * C2 beacon assessment.
 *
 * The 0.2.x version drew 20 bars from `Math.random()` — the picture changed
 * between two renders of the same capture. This version plots only measured
 * inputs: the conversation's beacon score and its jitter (std/mean of the
 * inter-arrival times). If a result does not carry the measured detail (a
 * legacy summary), it says so instead of drawing something plausible.
 */
export default function BeaconChart({ threats, analysis }: Props) {
  const beaconThreats = threats.filter(t => (t.beacon_score || 0) > 0)
  const legacy = !analysis?.schema_version

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-dim)' }}>
        📡 Beacon Timing (measured)
      </h3>
      <p style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '10px' }}>
        Score: beacon detector output (0–1). Jitter: standard deviation ÷ mean of
        inter-arrival intervals &gt; 1 s.
      </p>

      <div style={{ minHeight: '120px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {beaconThreats.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '26px', color: 'var(--text-dim)', fontSize: '13px' }}>
            {legacy
              ? 'Beacon timing detail is unavailable in this saved analysis.'
              : 'No conversation reached the beacon threshold in this capture.'}
          </div>
        ) : (
          beaconThreats.map((t, i) => {
            const score = t.beacon_score || 0
            const detail = t.beacon_detail
            const isBeacon = score > 0.5
            const color = isBeacon ? 'var(--danger)' : 'var(--info)'
            return (
              <div key={`${t.target}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '130px', fontSize: '10px', fontFamily: 'var(--font-mono)',
                  color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis',
                }} title={t.target}>
                  {t.target}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ height: '14px', background: 'var(--surface2)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${Math.max(2, score * 100)}%`,
                      background: color, borderRadius: '3px',
                    }} />
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '3px' }}>
                    {detail
                      ? <>jitter {detail.iat_jitter.toFixed(3)} · mean IAT {detail.iat_mean.toFixed(1)} s · {detail.packet_count} packets · span {detail.duration.toFixed(1)} s</>
                      : 'measured timing detail unavailable in this result'}
                  </div>
                </div>
                <div style={{
                  fontSize: '11px', fontFamily: 'var(--font-mono)',
                  color, width: '44px', textAlign: 'right',
                }}>
                  {score.toFixed(2)}
                </div>
              </div>
            )
          })
        )}
      </div>

      <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text-dim)', textAlign: 'center' }}>
        No simulated values are drawn. An inter-arrival histogram needs per-packet
        timings, which the analysis does not retain.
      </div>
    </div>
  )
}
