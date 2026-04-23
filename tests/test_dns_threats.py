"""Tests for DNS threat detection (engine/detection/dns_threats.py)."""

import pytest
from engine.detection.dns_threats import analyze_dns, detect_dga, detect_dns_tunneling


class TestDetectDGA:
    """Tests for DGA domain detection."""

    def test_high_entropy_domain_flags_dga(self):
        """High-entropy domain names should trigger DGA flag."""
        # Random-looking domain
        threats = analyze_dns("xkrqzmwjtpbd.vvcc", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) > 0, "High-entropy domain should flag DGA"

    def test_hex_domain_flags_dga(self):
        """Hex-only domain labels should trigger DGA flag."""
        threats = analyze_dns("a3f8b2c1d9e7f0.example.com", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) > 0, "Hex domain label should flag DGA"

    def test_known_good_domain_no_flag(self):
        """Well-known legitimate domains should not flag DGA."""
        threats = analyze_dns("google.com", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) == 0, "google.com should not flag DGA"

    def test_very_short_domain_no_flag(self):
        """Short, normal domains should not flag."""
        threats = analyze_dns("a.com", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) == 0, "Short domain should not flag DGA"

    def test_localhost_no_flag(self):
        """localhost and .arpa should be skipped."""
        threats = analyze_dns("localhost", "A")
        assert len(threats) == 0

        threats = analyze_dns("1.0.0.10.in-addr.arpa", "A")
        assert len(threats) == 0


class TestDetectDNSTunneling:
    """Tests for DNS tunneling detection."""

    def test_txt_query_type_flags_tunneling(self):
        """TXT query type is a strong tunneling indicator."""
        threats = analyze_dns("data.exfil.com", "TXT")
        tunnel_threats = [t for t in threats if t.threat_type == "tunneling"]
        assert len(tunnel_threats) > 0, "TXT query should flag tunneling"

    def test_long_subdomain_flags_tunneling(self):
        """Very long subdomain labels suggest data encoding (tunneling)."""
        long_sub = "a" * 40 + ".exfil.com"
        threats = analyze_dns(long_sub, "A")
        tunnel_threats = [t for t in threats if t.threat_type == "tunneling"]
        assert len(tunnel_threats) > 0, "Long subdomain should flag tunneling"

    def test_normal_domain_no_tunneling(self):
        """Regular domain should not flag tunneling."""
        threats = analyze_dns("www.example.com", "A")
        tunnel_threats = [t for t in threats if t.threat_type == "tunneling"]
        assert len(tunnel_threats) == 0, "Normal domain should not flag tunneling"

    def test_null_query_type_flags_tunneling(self):
        """NULL query type is unusual and should flag tunneling."""
        threats = analyze_dns("tunnel.evil.com", "NULL")
        tunnel_threats = [t for t in threats if t.threat_type == "tunneling"]
        assert len(tunnel_threats) > 0, "NULL query type should flag tunneling"


class TestAnalyzeDNS:
    """Integration tests for the combined analyze_dns function."""

    def test_returns_list(self):
        """analyze_dns should always return a list."""
        result = analyze_dns("anything.com", "A")
        assert isinstance(result, list)

    def test_dga_and_tunneling_both_flagged(self):
        """A domain can be flagged for both DGA and tunneling."""
        # Hex-like subdomain + TXT query
        threats = analyze_dns("a3f8b2c1d9e7f0123456789abcdef.evil.com", "TXT")
        types = {t.threat_type for t in threats}
        assert "dga" in types, "Should flag DGA"
        assert "tunneling" in types, "Should flag tunneling"