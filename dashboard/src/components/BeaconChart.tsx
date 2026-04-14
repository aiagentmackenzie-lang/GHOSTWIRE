import type { ThreatEntry } from '../App'

interface Props {
  threats: ThreatEntry[]
}

export default function BeaconChart({ threats }: Props) {
  // Beacon jitter visualization — shows how regular the timing is
  const beaconThreats = threats.filter(t => t.beacon_score && t.beacon_score > 0)

  return (
    <div style={{
      background: 'var(--surface)', borderRadius: '8px',
      border: '1px solid var(--border)', padding: '16px',
    }}>
      <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'var(--text-dim)' }}>
        📡 C2 Beacon Analysis
      </h3>

      <div style={{ height: '120px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {beaconThreats.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)', fontSize: '13px' }}>
            No beacon patterns detected
          </div>
        ) : (
          beaconThreats.map((t, i) => {
            const score = t.beacon_score || 0
            const isBeacon = score > 0.5
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '120px', fontSize: '10px', fontFamily: 'var(--font-mono)',
                  color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {t.target.split('-').pop()?.slice(0, 15)}
                </div>
                <div style={{ flex: 1, display: 'flex', gap: '2px', alignItems: 'flex-end', height: '30px' }}>
                  {/* Simulated IAT histogram bars */}
                  {Array.from({ length: 20 }, (_, j) => {
                    const jitter = 1 - score // Higher beacon = lower jitter = more uniform bars
                    const base = 0.7
                    const variation = jitter * Math.random()
                    const barH = (base - variation) * 100
                    return (
                      <div key={j} style={{
                        flex: 1, height: `${barH}%`,
                        background: isBeacon
                          ? `rgba(255,51,102,${0.3 + (barH / 100) * 0.7})`
                          : `rgba(0,170,255,${0.2 + (barH / 100) * 0.5})`,
                        borderRadius: '2px 2px 0 0',
                        transition: 'height 0.3s ease',
                      }} />
                    )
                  })}
                </div>
                <div style={{
                  fontSize: '11px', fontFamily: 'var(--font-mono)',
                  color: isBeacon ? 'var(--danger)' : 'var(--text-dim)',
                  width: '40px', textAlign: 'right',
                }}>
                  {(score * 100).toFixed(0)}%
                </div>
              </div>
            )
          })
        )}
      </div>

      <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text-dim)', textAlign: 'center' }}>
        IAT Distribution — uniform bars = C2 beacon | scattered = benign
      </div>
    </div>
  )
}