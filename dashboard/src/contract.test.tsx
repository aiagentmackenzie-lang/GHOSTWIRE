// Dashboard contract tests (Wave 1, slice 4).
//
// The 0.2.x UI drew random bars, placed sessions by list rank, mixed packet and
// fingerprint counts in one denominator, and presented demo content without a
// marker. These tests pin the distinctions that replaced those behaviours:
// measured-only values, one unit per number, an explainable empty table, and a
// persistent demo / compatibility banner.

import { describe, it, expect } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import App from './App'
import BeaconChart from './components/BeaconChart'
import NetworkGraph from './components/NetworkGraph'
import ProtoBreakdown from './components/ProtoBreakdown'
import ThreatPanel from './components/ThreatPanel'
import Timeline from './components/Timeline'
import type { AnalysisData, Finding, Observation, ThreatEntry } from './types'

const CS_UA = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)'
const DNS_DOMAIN = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil.com'

function observation(over: Partial<Observation>): Observation {
  return {
    observation_id: 'obs-1',
    kind: 'packet',
    frame: 1,
    frames: [1],
    timestamp: 1.0,
    transport: 'TCP',
    src: { ip: '192.168.1.50', port: 49152, role: 'client', address_family: 'ipv4' },
    dst: { ip: '185.220.101.34', port: 80, role: 'server', address_family: 'ipv4' },
    direction: 'src_to_dst',
    field: 'http.header.user-agent',
    value: CS_UA,
    normalized_value: CS_UA.toLowerCase(),
    occurrence: 1,
    ...over,
  }
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    finding_id: 'fnd-1',
    kind: 'http_header',
    rule: { id: 'c2.http_user_agent_exact', revision: '1', source: 'engine/fingerprint/c2_database.py::match_http' },
    subject: { type: 'http_header', value: CS_UA },
    scope: 'conversation',
    match_method: 'exact_normalized',
    score: 0.9,
    score_scale: 'rule_weight_0_1',
    reasons: [{
      code: 'c2.http_pattern_match',
      detail: 'HTTP User-Agent matched a cobalt_strike rule (weight 0.90)',
      contribution: 0.9,
      scale: 'rule_weight_0_1',
      observation_id: 'obs-1',
    }],
    observation_ids: ['obs-1'],
    conversation_id: 'cnv-1',
    conversation_basis: 'same 5-tuple supplied the header',
    mitre_techniques: ['T1071.001'],
    provenance: {},
    summary: 'HTTP User-Agent matched a cobalt_strike rule',
    tool_inference: {
      tool: 'cobalt_strike',
      confidence: 0.9,
      basis: 'documented default UA',
      caveat: 'This is a rule match on an observed field.',
    },
    ...over,
  }
}

function threat(over: Partial<ThreatEntry> = {}): ThreatEntry {
  return {
    target: '185.220.101.34:80-192.168.1.50:49152',
    target_type: 'session',
    overall_score: 0.315,
    score_scale: 'weighted_composite_0_1',
    confidence: 'LOW',
    beacon_score: null,
    c2_matches: [],
    dns_threats: [],
    iocs: [],
    mitre_techniques: [],
    summary: 'HTTP User-Agent matched a cobalt_strike rule',
    finding_ids: ['fnd-1'],
    endpoints: {
      src: { ip: '192.168.1.50', port: 49152, role: 'client', address_family: 'ipv4' },
      dst: { ip: '185.220.101.34', port: 80, role: 'server', address_family: 'ipv4' },
    },
    client_side: 'src',
    role_basis: 'http_request',
    ...over,
  }
}

function baseAnalysis(over: Partial<AnalysisData> = {}): AnalysisData {
  return {
    schema_version: '1.0',
    ghostwire_version: '0.2.1',
    file: '/captures/http.pcap',
    analysis_time: 0.021,
    packets_total: 1,
    packets_decoded: 1,
    sessions_total: 1,
    tls_fingerprints: 0,
    http_fingerprints: 1,
    ssh_fingerprints: 0,
    beacons_detected: 0,
    dns_threats: 0,
    c2_matches: 1,
    threats: [threat()],
    findings: [finding()],
    observations: [observation({})],
    protocol_counts: { HTTP: 1 },
    coverage: {
      status: 'complete', label: 'Complete analysis of the decoded capture',
      reasons: ['all 1 frames decoded; no stream gaps were observed'], limits: [],
      frames_read: 1, frames_decoded: 1, frames_undecoded: 0, sessions_total: 1,
      sessions_dropped: 0, stream_gaps: 0, stream_missing_bytes: 0, payloads_capped: 0,
      parser_used: 'dpkt', link_type_declared: 1, link_type_name: 'EN10MB (Ethernet)',
    },
    selection: {
      counts: {
        packets_total: 1, sessions_total: 1, sessions_scored: 1, sessions_eligible: 1,
        sessions_returned: 1, findings_total: 1, findings_returned: 1,
      },
      filter: { min_score: 0.25, sessions_below_threshold: 0 },
      truncation: { sessions_limit: 50, sessions_truncated: false },
      explanation: '1 finding(s) recorded. 1 of 1 conversation(s) had contributing findings.',
    },
    summary: 'Complete analysis of 1 frame(s): 1 finding(s) recorded.',
    ...over,
  }
}

describe('one packet, one denominator', () => {
  it('reports a single-packet DNS capture as 100% DNS, not 50/50', () => {
    const analysis = baseAnalysis({
      packets_total: 1,
      protocol_counts: { DNS: 1 },
      http_fingerprints: 0,
      c2_matches: 0,
      dns_threats: 1,
      threats: [],
      findings: [finding({
        kind: 'dns',
        rule: { id: 'dns.tunneling_heuristic', revision: '1', source: 'engine/detection/dns_threats.py' },
        subject: { type: 'domain', value: DNS_DOMAIN },
        conversation_id: null,
        conversation_basis: null,
        tool_inference: undefined,
        score: 1.0,
        score_scale: 'rule_score_0_1',
      })],
      observations: [observation({
        transport: 'UDP',
        field: 'dns.query_name',
        value: DNS_DOMAIN,
        src: { ip: '192.168.1.50', port: 33333, role: 'client' },
        dst: { ip: '8.8.8.8', port: 53, role: 'server' },
      })],
    })

    render(<ProtoBreakdown analysis={analysis} />)
    expect(screen.getByText('DNS')).toBeInTheDocument()
    expect(screen.getByText('1 (100.0%)')).toBeInTheDocument()
    expect(screen.queryByText(/Other/)).not.toBeInTheDocument()
    expect(screen.getByText(/Denominator:/)).toHaveTextContent('1 frame(s) read')
  })

  it('says so when per-protocol counts are unavailable', () => {
    const analysis = baseAnalysis({ protocol_counts: undefined })
    render(<ProtoBreakdown analysis={analysis} />)
    expect(screen.getByText(/Per-protocol frame counts are unavailable/)).toBeInTheDocument()
  })
})

describe('selection and empty states', () => {
  it('explains a filtered result instead of showing an all-clear', () => {
    const analysis = baseAnalysis({
      threats: [],
      selection: {
        counts: {
          sessions_total: 1, sessions_scored: 1, sessions_eligible: 0,
          sessions_returned: 0, findings_total: 1, findings_returned: 1,
        },
        filter: { min_score: 0.32, sessions_below_threshold: 1 },
        truncation: { sessions_limit: 50, sessions_truncated: false },
        explanation: '1 finding(s) recorded. 0 scored at or above the 0.32 session threshold. '
          + 'An empty session table is a threshold result, not an empty capture.',
      },
    })
    render(<ThreatPanel threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/Findings exist below the session threshold/)).toBeInTheDocument()
    expect(screen.getByText(/threshold result, not an empty capture/)).toBeInTheDocument()
    expect(screen.queryByText(/No significant threats/)).not.toBeInTheDocument()
  })

  it('does not call an unsupported decode an all-clear', () => {
    const analysis = baseAnalysis({
      threats: [],
      findings: [],
      observations: [],
      coverage: {
        status: 'unsupported_decode',
        label: 'Unsupported decode',
        reasons: ['frames were read but none decoded'],
        limits: [],
        frames_read: 2, frames_decoded: 0, frames_undecoded: 2, sessions_total: 0,
        sessions_dropped: 0, stream_gaps: 0, stream_missing_bytes: 0, payloads_capped: 0,
        parser_used: 'dpkt', link_type_declared: 9, link_type_name: 'linktype 9',
      },
    })
    render(<ThreatPanel threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/Coverage unsupported/)).toBeInTheDocument()
    expect(screen.queryByText(/✓ No findings/)).not.toBeInTheDocument()
  })

  it('marks a legacy summary as detail-unavailable', () => {
    const analysis: AnalysisData = {
      ...baseAnalysis(),
      schema_version: undefined,
      findings: undefined,
      observations: undefined,
      coverage: undefined,
      selection: undefined,
      threats: [threat({ endpoints: null, detail_unavailable: ['observations', 'finding_ids'] })],
    }
    render(<ThreatPanel threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/detail unavailable in this saved analysis/)).toBeInTheDocument()
    expect(screen.getByText(/direction unknown \(legacy label\)/)).toBeInTheDocument()
  })
})

describe('measured charts only', () => {
  it('plots a real time axis when timestamps exist', () => {
    const analysis = baseAnalysis({
      run: {
        schema_version: '1.0', run_id: 'run-1', engine_version: '0.2.1',
        generated_at: '2026-01-01T00:00:00Z',
        capture: {
          path: 'x', sha256: 'abc', size_bytes: 1, format: 'pcap',
          link_type_declared: 1, link_type_name: 'EN10MB (Ethernet)',
          parser_declared: 'auto', parser_used: 'dpkt', parser_fallback: false,
          frames_read: 1, frames_decoded: 1, frames_undecoded: 0, decode_rate: 1,
          first_timestamp: 1, last_timestamp: 1, duration_seconds: 0,
          ordering_anomalies: 0,
        },
        settings: {}, versions: {},
      },
    })
    render(<Timeline threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/Axis:/)).toHaveTextContent('00:00:01.000Z')
  })

  it('refuses to invent a timeline when timestamps are missing', () => {
    const analysis = baseAnalysis({ observations: [] })
    render(<Timeline threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/Observed timestamps are unavailable/)).toBeInTheDocument()
  })

  it('beacon chart shows measured jitter, not random bars', () => {
    const analysis = baseAnalysis({
      threats: [threat({
        beacon_score: 0.95,
        beacon_detail: {
          overall_score: 0.95, confidence: 'HIGH', iat_mean: 60, iat_std: 0.24,
          iat_jitter: 0.004, packet_count: 50, duration: 1440.5, byte_ratio: 0.07,
          components: { jitter: 0.95, volume: 0.6, regularity: 0.7, entropy: 0.5 },
          units: { iat_mean: 'seconds' },
        },
      })],
    })
    render(<BeaconChart threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/jitter 0.004/)).toBeInTheDocument()
    expect(screen.getByText(/No simulated values are drawn/)).toBeInTheDocument()
  })

  it('beacon chart reports missing measured detail', () => {
    const analysis = baseAnalysis({
      threats: [threat({ beacon_score: 0.8, beacon_detail: undefined })],
    })
    render(<BeaconChart threats={analysis.threats} analysis={analysis} />)
    expect(screen.getByText(/measured timing detail unavailable/)).toBeInTheDocument()
  })
})

describe('network graph uses observed direction', () => {
  it('draws the observed src→dst edge and labels roles', () => {
    const { container } = render(<NetworkGraph threats={[threat()]} />)
    expect(screen.getByText('192.168.1.50:49152')).toBeInTheDocument()
    expect(screen.getByText('185.220.101.34:80')).toBeInTheDocument()
    expect(container.querySelector('line')).not.toBeNull()
    expect(screen.getByText(/Arrow: observed wire direction/)).toBeInTheDocument()
  })

  it('refuses to guess direction from a legacy label', () => {
    render(<NetworkGraph threats={[threat({ endpoints: null })]} />)
    expect(screen.getByText(/Structured endpoints are unavailable/)).toBeInTheDocument()
    expect(screen.queryByText('192.168.1.50:49152')).not.toBeInTheDocument()
  })
})

describe('demo content stays labelled', () => {
  it('shows a persistent demo banner while demo data is displayed', () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /Demo data/i }))
    const banner = screen.getByText(/DEMO DATA/)
    expect(banner).toHaveTextContent('not an analysis of a capture')
    // And the banner stays for as long as the demo result is on screen.
    expect(screen.getAllByText(/Synthetic demo/i).length).toBeGreaterThan(0)
  })
})
