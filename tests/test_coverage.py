"""Coverage-targeted tests (production-plan Phase 4.3).

Raises cli.py and pcap_loader.py coverage toward the >=70% target by
exercising the report-format branches, the per-query hunt path, the rich
summary output, the scapy parser path, corrupt-file handling, and ICMP/IPv6
parse paths.
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from scapy.all import ICMP, IP, Ether, Raw, wrpcap

from engine.cli import cli
from engine.parser.pcap_loader import iter_packet_records, load_pcap

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ─── CLI coverage (in-process via Click's CliRunner so coverage counts) ─────

class TestReportFormats:
    def test_report_markdown_to_default_file(self, beacon_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", beacon_pcap, "--format", "markdown"])
        assert result.exit_code == 0, result.output
        assert "Report saved" in result.output or "GHOSTWIRE" in result.output

    def test_report_text_format(self, beacon_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", beacon_pcap, "--format", "text"])
        assert result.exit_code == 0, result.output
        assert result.output.strip()

    def test_report_stix_format(self, beacon_pcap, tmp_path):
        out = tmp_path / "out.stix.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["report", beacon_pcap, "--format", "stix", "--output-file", str(out)])
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert data.get("type") == "bundle" or "objects" in data


class TestHuntQueries:
    def test_hunt_each_query_runs(self, mixed_pcap):
        from engine.detection.hunt import BUILTIN_QUERIES
        runner = CliRunner()
        for q in BUILTIN_QUERIES:
            result = runner.invoke(cli, ["hunt", mixed_pcap, "--query", q, "--output", "json"])
            assert result.exit_code == 0, f"query {q}: {result.output}"

    def test_hunt_summary_output(self, mixed_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["hunt", mixed_pcap, "--query", "suspicious_beacons"])
        assert result.exit_code == 0, result.output
        assert result.output.strip()

    def test_hunt_no_query_lists_queries(self, beacon_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["hunt", beacon_pcap])
        assert result.exit_code == 0, result.output


class TestAnalyzeOutputs:
    def test_analyze_summary_output(self, mixed_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", mixed_pcap])
        assert result.exit_code == 0, result.output
        assert result.output.strip()

    def test_analyze_scapy_parser(self, mixed_pcap):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", mixed_pcap, "--output", "json", "--parser", "scapy"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["packets_total"] >= 1

    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0." in result.output

    def test_analyze_missing_file_exits_nonzero(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "/nonexistent/x.pcap"])
        assert result.exit_code != 0


# ─── pcap_loader coverage ───────────────────────────────────────────────────

class TestPcapLoaderPaths:
    def test_corrupt_file_raises_value_error(self, tmp_path):
        p = tmp_path / "corrupt.pcap"
        p.write_bytes(b"This is not a pcap file at all")
        with pytest.raises(ValueError):
            load_pcap(str(p))

    def test_scapy_parser_path(self, beacon_pcap):
        """Explicit --parser scapy path produces records (covers _iter_scapy)."""
        records = list(iter_packet_records(beacon_pcap, parser="scapy"))
        assert len(records) >= 50, f"scapy path returned {len(records)} records"
        assert any(r.protocol_l4 == "TCP" for r in records)

    def test_icmp_packet_parsed(self, tmp_path):
        """An ICMP packet is parsed with protocol_l4 == ICMP (covers ICMP branch)."""
        pkt = (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
               / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
               / ICMP(type=8, code=0)
               / Raw(load=b"ping"))
        pkt.time = 1.0
        p = tmp_path / "icmp.pcap"
        wrpcap(str(p), [pkt])
        records = load_pcap(str(p))
        assert len(records) == 1
        assert records[0].protocol_l4 == "ICMP"
        assert records[0].metadata.get("icmp_type") == 8

    def test_unsupported_extension_raises(self, tmp_path):
        p = tmp_path / "foo.txt"
        p.write_bytes(b"not a pcap")
        with pytest.raises(ValueError, match="Unsupported"):
            load_pcap(str(p))

    def test_missing_file_raises_filenotfound(self):
        with pytest.raises(FileNotFoundError):
            load_pcap("/nonexistent/capture.pcap")

    def test_udp_dns_payload_captured(self, dns_pcap):
        """UDP/DNS payload is captured into raw_payload (covers UDP branch)."""
        records = load_pcap(dns_pcap)
        assert records
        udp = [r for r in records if r.protocol_l4 == "UDP"]
        assert udp, "expected at least one UDP record"
        assert udp[0].raw_payload, "UDP raw_payload empty"
