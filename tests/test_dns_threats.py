"""Tests for DNS threat detection (engine/detection/dns_threats.py)."""

from engine.detection.dns_threats import analyze_dns, detect_dga


class TestDetectDGA:
    """Tests for DGA domain detection."""

    def test_high_entropy_domain_flags_dga(self):
        """High-entropy domain names should trigger DGA flag."""
        # Random-looking domain
        threats = analyze_dns("xkrqzmwjtpbd.vvcc", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) > 0, "High-entropy domain should flag DGA"

    def test_hex_domain_flags_dga(self):
        """A hex-only SLD (the registrable label) should trigger DGA. A hex
        *subdomain* of a legit SLD (e.g. cb922b3f.fanoutcdn.com) must NOT -
        real CDNs use hash subdomains."""
        threats = analyze_dns("a3f8b2c1d9e7f0.com", "A")  # SLD is hex
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) > 0, "Hex SLD should flag DGA"
        # And a hex subdomain of a known CDN must NOT flag DGA.
        threats2 = analyze_dns("cb922b3f.fanoutcdn.com", "A")
        dga2 = [t for t in threats2 if t.threat_type == "dga"]
        assert len(dga2) == 0, "Hex subdomain of a CDN must not flag DGA"

    def test_known_good_domain_no_flag(self):
        """Well-known legitimate domains should not flag DGA."""
        threats = analyze_dns("google.com", "A")
        dga_threats = [t for t in threats if t.threat_type == "dga"]
        assert len(dga_threats) == 0, "google.com should not flag DGA"

    def test_known_good_sld_skips_filter(self):
        """A domain whose registrable SLD is a known-good service is skipped."""
        # SLD label = 'amazon' (known-good) → filtered out before DGA scoring.
        assert detect_dga("evil.amazon.com") is None
        assert detect_dga("something.aws") is None

    def test_substring_match_no_longer_skips(self):
        """Audit M-06: a domain that merely CONTAINS a known-good substring
        (e.g. 'aws') but whose SLD is not known-good must still be analyzed.
        The old substring filter would skip this and hide a real DGA domain."""
        # 'awsxkqzlwyt' contains the substring 'aws' but is not the exact
        # known-good SLD 'aws' (audit M-06: the old substring filter would have
        # skipped it). Exact-SLD matching means it is analyzed, and the
        # consonant cluster flags DGA.
        result = detect_dga("awsxkqzlwyt.com")
        assert result is not None, "Substring 'aws' must not skip a non-known-good SLD"
        assert result.threat_type == "dga"

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
        # Hex SLD (DGA) + TXT query type (tunneling).
        threats = analyze_dns("a3f8b2c1d9e7f0123456789.com", "TXT")
        types = {t.threat_type for t in threats}
        assert "dga" in types, "Should flag DGA"
        assert "tunneling" in types, "Should flag tunneling"
