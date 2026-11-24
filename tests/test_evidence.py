"""Wave 1 acceptance controls: the evidence and coverage contract.

Each test corresponds to a control named in the upgrade plan's Wave 1 slices
and the Sweep 2/3 refinements. They are written against the *normal analysis
entry point* (``engine.analysis.run_analysis``) and, where the contract is
user-facing, against the CLI as well.
"""

from __future__ import annotations

import json

import pytest

from engine.analysis import run_analysis
from engine.evidence import (
    COVERAGE_COMPLETE,
    COVERAGE_UNSUPPORTED_DECODE,
    RESULT_SCHEMA_VERSION,
)
from engine.parser.pcap_loader import ParserReport, load_pcap

DNS_DOMAIN = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil.com"
CS_UA = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)"


def _finding_by_kind(result, kind):
    return [f for f in result.findings if f.kind == kind]


def _observation(result, obs_id):
    return next(o for o in result.observations if o.observation_id == obs_id)


# ─── Slice 1: capture, run and coverage contract ────────────────────────────

class TestRunContract:
    def test_run_records_capture_digest_decoder_and_versions(self, dns_pcap):
        result = run_analysis(dns_pcap)
        capture = result.run.capture

        # The audit's digest for this exact fixture.
        assert capture["sha256"] == (
            "a2f6299ae1ab35675896658119ce0bf6f4265adcf8076a875463730de5ad9ff8"
        )
        assert capture["size_bytes"] > 24
        assert capture["format"] == "pcap"
        assert capture["link_type_declared"] == 1
        assert capture["link_type_name"] == "EN10MB (Ethernet)"
        assert capture["parser_declared"] == "auto"
        assert capture["parser_used"] == "dpkt"
        assert capture["frames_read"] == 1
        assert capture["frames_decoded"] == 1
        assert capture["frames_undecoded"] == 0
        assert capture["decode_rate"] == 1.0

        assert result.run.schema_version == RESULT_SCHEMA_VERSION
        assert result.run.engine_version == "0.3.0"
        assert result.run.settings["min_score"] == 0.25
        assert result.run.settings["min_packets"] == 10
        assert result.run.settings["max_payload_bytes"] == 16 * 1024
        assert result.run.settings["max_sessions"] == 20_000
        assert result.run.versions["result_schema"] == RESULT_SCHEMA_VERSION
        assert result.run.versions["ja3_algorithm"] == "ja3-rfc-v1"
        assert result.run.versions["ja4_engine"].startswith("ja4plus-")

    def test_coverage_states_are_distinct(self, dns_pcap, tmp_path):
        complete = run_analysis(dns_pcap)
        assert complete.coverage.status == COVERAGE_COMPLETE
        assert complete.coverage.frames_read == 1
        assert complete.coverage.reasons  # an explanation, not just a label

        # A capture with frames the decoder cannot read is NOT "clean".
        # Link type 9 is PPP: no Ethernet, and the payload is not IP either.
        import struct

        broken = tmp_path / "unsupported.pcap"
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 9)
        packet = struct.pack("<IIII", 1, 0, 40, 40) + b"\x00" * 40
        broken.write_bytes(header + packet)
        unsupported = run_analysis(str(broken))
        assert unsupported.coverage.status == COVERAGE_UNSUPPORTED_DECODE
        assert unsupported.coverage.frames_read >= 1
        assert unsupported.coverage.frames_decoded == 0
        assert "decode" in unsupported.coverage.reasons[0]
        assert "does not mean the capture was clean" in unsupported.summary

    def test_complete_zero_findings_is_not_partial(self, benign_pcap):
        result = run_analysis(benign_pcap)
        assert result.findings == []
        assert result.coverage.status == COVERAGE_COMPLETE
        assert "no configured rule matched" in result.summary
        assert result.selection.counts["findings_total"] == 0

    def test_raw_ip_and_ethernet_yield_the_same_handshake(self, split_tls_pcap, tmp_path):
        """Equivalent Ethernet and raw-IP captures must agree, not differ silently."""
        from scapy.all import IP, wrpcap

        packets = load_pcap(split_tls_pcap)
        raw_ip = []
        for pkt in load_pcap(split_tls_pcap):
            from scapy.all import TCP, Ether, Raw

            frame = (
                Ether() / IP(src=pkt.src_ip, dst=pkt.dst_ip)
                / TCP(sport=pkt.src_port, dport=pkt.dst_port,
                      flags=pkt.metadata["tcp_flags"], seq=pkt.metadata["tcp_seq"])
                / Raw(load=pkt.raw_payload)
            )
            frame.time = pkt.timestamp
            raw_ip.append(frame["IP"])
        raw_path = tmp_path / "raw_ip.pcap"
        wrpcap(str(raw_path), raw_ip)

        eth = run_analysis(split_tls_pcap)
        raw = run_analysis(str(raw_path))

        assert eth.run.capture["link_type_declared"] == 1
        assert raw.run.capture["link_type_declared"] in (101, 228)
        assert len(eth.tls_fps) == 1 and len(raw.tls_fps) == 1
        for field in ("sni", "ja3_hash", "ja4"):
            assert getattr(eth.tls_fps[0], field) == getattr(raw.tls_fps[0], field)
        assert eth.coverage.status == raw.coverage.status == COVERAGE_COMPLETE
        assert packets  # eager loader still returns the same records

    def test_pcapng_fallback_reports_the_parser_that_produced_the_result(self, tmp_path):
        from scapy.all import wrpcapng

        from tests.conftest import _build_split_tls_packets

        p = tmp_path / "split.pcapng"
        wrpcapng(str(p), _build_split_tls_packets())
        report = ParserReport()
        load_pcap(str(p), parser="dpkt", report=report)
        assert report.parser_used == "scapy", report.to_dict()
        assert report.fallback_used is True
        assert report.to_dict()["parser_used"] == "scapy"

        result = run_analysis(str(p))
        assert result.run.capture["parser_used"] == "scapy"
        assert result.run.capture["parser_fallback"] is True
        assert len(result.tls_fps) == 1

    def test_observation_identity_is_stable_across_repeat_analyses(self, http_pcap):
        first = run_analysis(http_pcap)
        second = run_analysis(http_pcap)
        assert first.run.run_id != second.run.run_id  # a run is an event
        assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
        assert [o.observation_id for o in first.observations] == [
            o.observation_id for o in second.observations
        ]


# ─── Slice 2: DNS independence and HTTP attribution ─────────────────────────

class TestDnsEvidence:
    def test_dns_only_produces_one_standalone_finding_with_two_reasons(self, dns_pcap):
        result = run_analysis(dns_pcap)

        assert len(result.sessions) == 0
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.kind == "dns"
        assert finding.subject_value == DNS_DOMAIN
        assert finding.rule_id == "dns.tunneling_heuristic"
        assert finding.rule_revision == "1"
        assert finding.conversation_id is None
        assert len(finding.reasons) == 2
        assert {r.code for r in finding.reasons} == {"dns.unusual_qtype", "dns.long_label"}
        assert [r.contribution for r in finding.reasons] == [0.5, 0.5]

        name_obs = _observation(result, finding.observation_ids[0])
        assert name_obs.frame == 1
        assert name_obs.timestamp == pytest.approx(1.0)
        assert name_obs.transport == "UDP"
        assert name_obs.field_name == "dns.query_name"
        assert name_obs.value == DNS_DOMAIN
        assert (name_obs.src.ip, name_obs.src.port) == ("192.168.1.50", 33333)
        assert (name_obs.dst.ip, name_obs.dst.port) == ("8.8.8.8", 53)
        assert name_obs.src.role == "client" and name_obs.dst.role == "server"
        assert name_obs.direction == "src_to_dst"

        # Frame 1 also carries the query type that the second reason names.
        type_obs = _observation(result, finding.observation_ids[1])
        assert type_obs.frame == 1
        assert type_obs.field_name == "dns.query_type"
        assert type_obs.value == "TXT"

    def test_dns_is_absent_from_session_rows_and_explained(self, dns_pcap):
        out = run_analysis(dns_pcap).to_output()
        assert out["threats"] == []
        assert out["selection"]["counts"]["sessions_total"] == 0
        assert "No TCP conversations were reconstructed" in out["selection"]["explanation"]
        assert out["dns_findings"][0]["subject"]["value"] == DNS_DOMAIN

    def test_unrelated_dns_query_does_not_change_a_tcp_conversation(self, http_pcap,
                                                                   dns_plus_http_pcap):
        http_only = run_analysis(http_pcap)
        combined = run_analysis(dns_plus_http_pcap)

        assert len(http_only.threat_scores) == 1
        assert len(combined.threat_scores) == 1
        solo = http_only.threat_scores[0]
        with_dns = combined.threat_scores[0]

        # The historical result was 0.565 because capture-wide DNS was added to
        # every session. It must stay 0.315.
        assert solo.overall_score == pytest.approx(0.315)
        assert with_dns.overall_score == pytest.approx(0.315)
        assert with_dns.confidence == "LOW"
        assert with_dns.overall_score != pytest.approx(0.565)

        # ... and the DNS finding is still present, on its own.
        assert len(_finding_by_kind(combined, "dns")) == 1
        assert with_dns.dns_threats == []
        assert not any("evil.com" in ioc for ioc in with_dns.iocs)
        assert with_dns.components == [
            c for c in with_dns.components if c.source != "dns"
        ]


class TestHttpAttribution:
    def test_http_only_preserves_the_observed_user_agent(self, http_pcap):
        result = run_analysis(http_pcap)
        findings = _finding_by_kind(result, "http_header")
        assert len(findings) == 1
        finding = findings[0]

        assert finding.subject_value == CS_UA
        assert finding.rule_id == "c2.http_user_agent_exact"
        assert finding.match_method == "exact_normalized"
        assert finding.score == pytest.approx(0.90)
        assert finding.score_scale == "rule_weight_0_1"
        assert finding.conversation_id is not None

        obs = _observation(result, finding.observation_ids[0])
        assert obs.frame == 1
        assert obs.field_name == "http.header.user-agent"
        assert obs.value == CS_UA
        assert obs.normalized_value == CS_UA.lower()
        assert (obs.src.ip, obs.src.port) == ("192.168.1.50", 49152)
        assert (obs.dst.ip, obs.dst.port) == ("185.220.101.34", 80)
        assert obs.src.role == "client" and obs.dst.role == "server"

        assert finding.tool_inference["tool"] == "cobalt_strike"
        assert "does not by itself confirm" in finding.tool_inference["caveat"]
        assert "inference" in finding.summary

    def test_http_session_score_and_components_come_from_the_finding(self, http_pcap):
        result = run_analysis(http_pcap)
        score = result.threat_scores[0]
        finding = _finding_by_kind(result, "http_header")[0]

        assert score.overall_score == pytest.approx(0.315)
        assert score.confidence == "LOW"
        assert score.finding_ids == [finding.finding_id]
        c2_component = next(c for c in score.components if c.source == "c2")
        assert c2_component.value == pytest.approx(0.90)
        assert c2_component.weight == pytest.approx(0.35)
        assert c2_component.contribution == pytest.approx(0.315)
        assert c2_component.finding_id == finding.finding_id
        assert "Known C2" not in score.summary

        # Structured matches and the IOC text now agree with the finding.
        assert len(score.c2_matches) == 1
        assert score.c2_matches[0].matched_value == CS_UA
        assert score.iocs == [f"C2:cobalt_strike ({CS_UA})"]

    def test_second_conversation_on_the_same_client_gets_no_match(
            self, http_with_shared_client_pcap):
        result = run_analysis(http_with_shared_client_pcap)
        assert len(result.sessions) == 2

        http_findings = _finding_by_kind(result, "http_header")
        assert len(http_findings) == 1

        matched_session = http_findings[0].conversation_id
        conversations = {c.conversation_id: c for c in result.conversations}
        assert matched_session in conversations

        benign_target = "203.0.113.10:80-192.168.1.50:50000"
        benign_scores = [s for s in result.threat_scores if s.target == benign_target]
        assert benign_scores == [], "the benign conversation must not become a threat row"
        assert all(matched_session == c.conversation_id for c in result.conversations)

        # Neither the benign session's score nor its findings mention the UA.
        benign = next(s for s in result.sessions if s.dst_ip == "203.0.113.10")
        assert not any(s.target == benign.session_id for s in result.threat_scores)

    def test_sharing_a_client_ip_is_not_attribution(self, http_pcap):
        """A finding must never be attached by address alone."""
        result = run_analysis(http_pcap)
        finding = _finding_by_kind(result, "http_header")[0]
        obs = _observation(result, finding.observation_ids[0])
        assert finding.conversation_id is not None
        assert "same 5-tuple" in (finding.conversation_basis or "")
        assert f"{obs.src.ip}:{obs.src.port}" in (finding.conversation_basis or "")


class TestSelectionControl:
    def test_threshold_keeps_findings_and_explains_the_empty_table(self, http_pcap):
        result = run_analysis(http_pcap, min_score=0.32)
        out = result.to_output()

        assert out["findings"], "findings must survive filtering"
        assert len(out["findings"]) == 1
        assert out["findings"][0]["rule"]["id"] == "c2.http_user_agent_exact"

        assert out["threats"] == []
        counts = out["selection"]["counts"]
        assert counts["sessions_scored"] == 1
        assert counts["sessions_eligible"] == 0
        assert counts["sessions_returned"] == 0
        assert counts["findings_total"] == 1
        assert counts["findings_returned"] == 1
        assert out["selection"]["filter"]["sessions_below_threshold"] == 1
        assert "threshold result, not an empty capture" in out["selection"]["explanation"]

    def test_default_threshold_is_recorded_not_implied(self, dns_pcap):
        out = run_analysis(dns_pcap).to_output()
        assert out["selection"]["filter"]["min_score"] == 0.25
        assert out["run"]["settings"]["min_score"] == 0.25
        assert out["selection"]["filter"]["counting_unit"]

    def test_json_cap_is_reported_as_truncation(self, benign_pcap):
        out = run_analysis(benign_pcap).to_output()
        trunc = out["selection"]["truncation"]
        assert trunc["sessions_limit"] == 50
        assert trunc["ordering"]


# ─── Structured result is what the CLI writes ───────────────────────────────

class TestCliContract:
    def test_cli_json_carries_the_same_evidence(self, dns_pcap):
        import subprocess
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, "-m", "engine.cli", "analyze", dns_pcap, "--output", "json"],
            capture_output=True, text=True, cwd=str(root), timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)

        # 0.2.x fields still exist for older clients.
        for key in ("ghostwire_version", "file", "packets_total", "sessions_total",
                    "tls_fingerprints", "http_fingerprints", "ssh_fingerprints",
                    "beacons_detected", "dns_threats", "c2_matches", "threats"):
            assert key in data
        # ... plus the contract.
        for key in ("schema_version", "run", "coverage", "findings", "observations",
                    "selection", "capture_sha256"):
            assert key in data

        assert data["ghostwire_version"] == "0.3.0"
        assert data["schema_version"] == RESULT_SCHEMA_VERSION
        assert data["findings"][0]["subject"]["value"] == DNS_DOMAIN
        assert data["findings"][0]["observation_ids"]
        assert data["coverage"]["status"] == COVERAGE_COMPLETE
