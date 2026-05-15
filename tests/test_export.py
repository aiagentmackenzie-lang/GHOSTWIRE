"""Tests for export modules (stix, report, mitre_map)."""

from engine.export.stix import build_stix_bundle, iocs_from_analysis, _looks_like_ip, _looks_like_domain
from engine.export.report import generate_markdown_report, generate_text_report
from engine.export.mitre_map import map_analysis_to_attack, map_techniques, AttackMapping


class TestSTIXExport:
    """Tests for STIX 2.1 bundle generation."""

    def test_build_stix_bundle_empty(self):
        """Empty IOC list should produce bundle with just author identity."""
        bundle = build_stix_bundle([])
        assert bundle["type"] == "bundle"
        # Should have at least the author identity object
        assert len(bundle["objects"]) >= 1
        assert bundle["objects"][0]["type"] == "identity"

    def test_build_stix_bundle_with_ip(self):
        """IP IOC should create an indicator with ipv4-addr pattern."""
        iocs = [{"type": "ipv4-addr", "value": "10.0.0.1", "confidence": 0.8,
                 "threat_type": "c2", "mitre_techniques": ["T1071.001"]}]
        bundle = build_stix_bundle(iocs)
        # Should have: identity + indicator + attack_pattern + relationship
        assert len(bundle["objects"]) == 4
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert "ipv4-addr:value = '10.0.0.1'" in indicators[0]["pattern"]

    def test_build_stix_bundle_with_domain(self):
        """Domain IOC should create domain-name pattern."""
        iocs = [{"type": "domain-name", "value": "evil.example.com", "confidence": 0.9,
                 "threat_type": "dga", "mitre_techniques": []}]
        bundle = build_stix_bundle(iocs)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert "domain-name:value = 'evil.example.com'" in indicators[0]["pattern"]

    def test_stix_confidence_range(self):
        """Confidence should be 0-100 integer."""
        iocs = [{"type": "ipv4-addr", "value": "1.2.3.4", "confidence": 0.75,
                 "threat_type": "c2", "mitre_techniques": []}]
        bundle = build_stix_bundle(iocs)
        indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert indicator["confidence"] == 75

    def test_iocs_from_analysis_with_ips(self):
        """Should extract IPs from threat targets."""
        analysis = {
            "threats": [{
                "target": "10.0.0.1:443-192.168.1.1:50000",
                "overall_score": 0.8,
                "mitre_techniques": ["T1071.001"],
                "summary": "C2 beacon",
                "c2_matches": [{"tool_name": "cobalt_strike", "matched_value": "test", "confidence": 0.9, "mitre_techniques": ["T1071.001"]}],
                "dns_threats": [],
            }]
        }
        iocs = iocs_from_analysis(analysis)
        ips = [i for i in iocs if i["type"] == "ipv4-addr"]
        assert len(ips) >= 2  # Both IPs extracted from target

    def test_iocs_from_analysis_with_dns(self):
        """Should extract domain IOCs from DNS threats."""
        analysis = {
            "threats": [{
                "target": "10.0.0.1:443",
                "overall_score": 0.6,
                "mitre_techniques": [],
                "summary": "DNS threat",
                "dns_threats": [{"domain": "xkrqzmwjtpbd.vvcc", "threat_type": "dga", "score": 0.7}],
                "c2_matches": [],
            }]
        }
        iocs = iocs_from_analysis(analysis)
        domains = [i for i in iocs if i["type"] == "domain-name"]
        assert len(domains) >= 1

    def test_looks_like_ip(self):
        assert _looks_like_ip("10.0.0.1") is True
        assert _looks_like_ip("256.0.0.1") is True  # String-level check only
        assert _looks_like_ip("not.an.ip") is False

    def test_looks_like_domain(self):
        assert _looks_like_domain("evil.com") is True
        assert _looks_like_domain("10.0.0.1") is False
        assert _looks_like_domain("http://evil.com/path") is False


class TestReportGeneration:
    """Tests for markdown and text report generation."""

    def _sample_analysis(self):
        return {
            "ghostwire_version": "0.1.0",
            "file": "/tmp/test.pcap",
            "analysis_time": 1.5,
            "packets_total": 1000,
            "sessions_total": 50,
            "tls_fingerprints": 5,
            "http_fingerprints": 3,
            "ssh_fingerprints": 1,
            "c2_matches": 2,
            "beacons_detected": 1,
            "dns_threats": 0,
            "threats": [
                {
                    "target": "10.0.0.1:443",
                    "target_type": "session",
                    "overall_score": 0.75,
                    "confidence": "HIGH",
                    "summary": "C2 beacon detected",
                    "beacon_score": 0.8,
                    "iocs": ["C2:cobalt_strike"],
                    "c2_matches": [{"tool_name": "cobalt_strike", "confidence": 0.9, "match_type": "ja3"}],
                    "dns_threats": [],
                    "mitre_techniques": ["T1071.001"],
                }
            ],
        }

    def test_markdown_report_structure(self):
        """Markdown report should have expected sections."""
        analysis = self._sample_analysis()
        report = generate_markdown_report(analysis)
        assert "# GHOSTWIRE" in report
        assert "Executive Summary" in report
        assert "Capture Overview" in report
        assert "Threat Details" in report
        assert "CRITICAL" in report or "HIGH" in report
        assert "Recommendations" in report

    def test_text_report_structure(self):
        """Text report should have key fields."""
        analysis = self._sample_analysis()
        report = generate_text_report(analysis)
        assert "GHOSTWIRE" in report
        assert "Packets:" in report
        assert "Threats:" in report

    def test_markdown_no_threats(self):
        """Report with no threats should show clean result."""
        analysis = {
            "ghostwire_version": "0.1.0",
            "file": "/tmp/clean.pcap",
            "analysis_time": 0.5,
            "packets_total": 100,
            "sessions_total": 5,
            "tls_fingerprints": 0,
            "http_fingerprints": 0,
            "ssh_fingerprints": 0,
            "c2_matches": 0,
            "beacons_detected": 0,
            "dns_threats": 0,
            "threats": [],
        }
        report = generate_markdown_report(analysis)
        assert "No significant threats" in report

    def test_markdown_mitre_mapping(self):
        """Report should include MITRE ATT&CK mapping."""
        analysis = self._sample_analysis()
        report = generate_markdown_report(analysis)
        assert "MITRE ATT&CK" in report


class TestMitreMap:
    """Tests for MITRE ATT&CK mapping."""

    def test_map_techniques_known(self):
        """Known technique IDs should map correctly."""
        mappings = map_techniques(["T1071.001"], confidence=0.8)
        assert len(mappings) == 1
        assert mappings[0].technique_name == "Application Layer Protocol: Web Protocols"
        assert mappings[0].tactic == "Command and Control"

    def test_map_techniques_unknown(self):
        """Unknown technique IDs should still produce a mapping."""
        mappings = map_techniques(["T9999.001"], confidence=0.5)
        assert len(mappings) == 1
        assert "T9999.001" in mappings[0].technique_name

    def test_map_analysis_to_attack(self):
        """Full analysis should produce MITRE mappings."""
        analysis = {
            "threats": [{
                "mitre_techniques": ["T1071.001", "T1573.001"],
                "summary": "C2 beacon",
                "overall_score": 0.8,
            }]
        }
        mappings = map_analysis_to_attack(analysis)
        assert len(mappings) == 2
        techniques = [m.technique_id for m in mappings]
        assert "T1071.001" in techniques
        assert "T1573.001" in techniques

    def test_map_analysis_empty(self):
        """Empty threats should produce empty mapping."""
        mappings = map_analysis_to_attack({"threats": []})
        assert mappings == []

    def test_attack_mapping_to_dict(self):
        """AttackMapping should serialize to dict."""
        m = AttackMapping(
            technique_id="T1071.001",
            technique_name="Web Protocols",
            tactic="Command and Control",
            tactic_order=9,
            confidence=0.8,
        )
        d = m.to_dict()
        assert d["technique_id"] == "T1071.001"
        assert d["confidence"] == 0.8