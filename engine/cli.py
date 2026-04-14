"""GHOSTWIRE CLI — network forensics from the terminal.

Usage:
    ghostwire analyze <pcap_file> [--output json|summary] [--parser dpkt|scapy]
    ghostwire hunt <pcap_file> --query <hunt_query>
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from engine import __version__
from engine.parser.pcap_loader import load_pcap
from engine.parser.protocol import identify_protocol
from engine.parser.session import reconstruct_sessions
from engine.fingerprint.ja4_engine import fingerprint_stream as tls_fingerprint
from engine.fingerprint.ja4h_engine import fingerprint_stream as http_fingerprint
from engine.fingerprint.ja4ssh_engine import fingerprint_stream as ssh_fingerprint
from engine.fingerprint.c2_database import match_all
from engine.detection.beacon import detect_beacons
from engine.detection.dns_threats import analyze_dns
from engine.detection.scorer import score_session

console = Console()
logger = logging.getLogger("ghostwire")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(name)s %(levelname)s: %(message)s")


@click.group()
@click.version_option(version=__version__, prog_name="GHOSTWIRE")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def cli(verbose: bool):
    """GHOSTWIRE — Network Forensics Engine. The wire remembers everything."""
    _setup_logging(verbose)


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["json", "summary"]), default="summary",
              help="Output format")
@click.option("--parser", type=click.Choice(["dpkt", "scapy", "auto"]), default="auto",
              help="PCAP parser to use")
@click.option("--min-score", type=float, default=0.25,
              help="Minimum threat score to report (0.0-1.0)")
@click.option("--min-packets", type=int, default=10,
              help="Minimum packets per session for beacon analysis")
def analyze(pcap_file: str, output: str, parser: str, min_score: float, min_packets: int):
    """Analyze a PCAP file for threats, C2 beacons, and fingerprints."""

    start_time = time.time()

    # === 1. LOAD PCAP ===
    with Progress(console=console, transient=True) as progress:
        task = progress.add_task("[green]Loading PCAP...", total=None)
        packets = load_pcap(pcap_file, parser=parser)
        progress.update(task, completed=True)

    if not packets:
        console.print("[red]No packets found in file[/red]")
        sys.exit(1)

    # === 2. PROTOCOL IDENTIFICATION ===
    for pkt in packets:
        if pkt.raw_payload:
            result = identify_protocol(
                pkt.src_port, pkt.dst_port, pkt.raw_payload,
                pkt.protocol_l4, pkt.metadata
            )
            if result.l7_protocol:
                pkt.protocol_l7 = result.l7_protocol
                from dataclasses import asdict
                pkt.metadata["protocol_result"] = {
                    "tls": asdict(result.tls) if result.tls else None,
                    "dns": asdict(result.dns) if result.dns else None,
                    "http": asdict(result.http) if result.http else None,
                    "ssh": asdict(result.ssh) if result.ssh else None,
                    "icmp": asdict(result.icmp) if result.icmp else None,
                }

    # === 3. SESSION RECONSTRUCTION ===
    sessions = reconstruct_sessions(packets)

    # === 4. FINGERPRINTING ===
    tls_fps = tls_fingerprint(packets)
    http_fps = http_fingerprint(packets)
    ssh_fps = ssh_fingerprint(packets)

    # Collect C2 matches from fingerprints
    all_c2_matches: dict[str, list] = {}
    for fp in tls_fps:
        key = f"{fp.source_ip}:{fp.source_port}"
        matches = match_all(ja4=fp.ja4, ja3=fp.ja3_hash)
        if matches:
            all_c2_matches.setdefault(key, []).extend(matches)

    for fp in http_fps:
        key = f"{fp.source_ip}"
        matches = match_all(user_agent=fp.user_agent)
        if matches:
            all_c2_matches.setdefault(key, []).extend(matches)

    for fp in ssh_fps:
        matches = match_all(ssh_banner=fp.client_banner, ssh_software=fp.client_software)
        if matches:
            key = f"{fp.source_ip}"
            all_c2_matches.setdefault(key, []).extend(matches)

    # === 5. BEACON DETECTION ===
    beacons = detect_beacons(sessions, min_packets=min_packets, min_score=min_score)

    # === 6. DNS THREAT DETECTION ===
    dns_threats_all: list[dict] = []
    for pkt in packets:
        if pkt.protocol_l7 == "DNS" and pkt.metadata.get("protocol_result", {}).get("dns"):
            dns_info = pkt.metadata["protocol_result"]["dns"]
            if dns_info and dns_info.get("query_name"):
                threats = analyze_dns(
                    dns_info["query_name"],
                    dns_info.get("query_type", "A"),
                    dns_info.get("response_code", "NOERROR"),
                )
                for t in threats:
                    dns_threats_all.append(t.to_dict())

    # === 7. COMPOSITE SCORING ===
    beacon_map = {b.session_id: b for b in beacons}
    threat_scores = []
    for session in sessions:
        c2 = all_c2_matches.get(f"{session.src_ip}:{session.src_port}", [])
        # Also check reverse direction
        c2 += all_c2_matches.get(f"{session.dst_ip}:{session.dst_port}", [])
        beacon = beacon_map.get(session.session_id)
        score = score_session(session.session_id, beacon=beacon, c2_matches=c2)
        if score.overall_score >= min_score:
            threat_scores.append(score)

    threat_scores.sort(key=lambda s: s.overall_score, reverse=True)

    elapsed = time.time() - start_time

    # === OUTPUT ===
    if output == "json":
        result = {
            "ghostwire_version": __version__,
            "file": str(pcap_file),
            "analysis_time": round(elapsed, 2),
            "packets_total": len(packets),
            "sessions_total": len(sessions),
            "tls_fingerprints": len(tls_fps),
            "http_fingerprints": len(http_fps),
            "ssh_fingerprints": len(ssh_fps),
            "beacons_detected": len(beacons),
            "dns_threats": len(dns_threats_all),
            "c2_matches": sum(len(v) for v in all_c2_matches.values()),
            "threats": [t.to_dict() for t in threat_scores[:50]],
        }
        click.echo(json.dumps(result, indent=2))

    else:
        # Rich summary
        console.print()
        console.print(Panel.fit(
            f"[bold green]GHOSTWIRE[/] v{__version__} — Network Forensics Engine\n"
            f"[dim]The wire remembers everything[/]",
            border_style="green",
        ))

        # Overview table
        overview = Table(title="Analysis Summary", show_header=False, border_style="dim")
        overview.add_column("Key", style="cyan")
        overview.add_column("Value", style="white")
        overview.add_row("File", str(pcap_file))
        overview.add_row("Packets", str(len(packets)))
        overview.add_row("Sessions", str(len(sessions)))
        overview.add_row("TLS Fingerprints", str(len(tls_fps)))
        overview.add_row("HTTP Fingerprints", str(len(http_fps)))
        overview.add_row("SSH Fingerprints", str(len(ssh_fps)))
        overview.add_row("C2 Matches", str(sum(len(v) for v in all_c2_matches.values())))
        overview.add_row("Beacons Detected", str(len(beacons)))
        overview.add_row("DNS Threats", str(len(dns_threats_all)))
        overview.add_row("Analysis Time", f"{elapsed:.2f}s")
        console.print(overview)

        # Protocol breakdown
        proto_counts: dict[str, int] = {}
        for pkt in packets:
            p = pkt.protocol_l7 or pkt.protocol_l4 or "Other"
            proto_counts[p] = proto_counts.get(p, 0) + 1

        proto_table = Table(title="Protocol Breakdown", border_style="dim")
        proto_table.add_column("Protocol", style="cyan")
        proto_table.add_column("Packets", justify="right", style="white")
        proto_table.add_column("%", justify="right", style="dim")
        for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            pct = count / len(packets) * 100
            proto_table.add_row(proto, str(count), f"{pct:.1f}%")
        console.print(proto_table)

        # Threats table
        if threat_scores:
            threat_table = Table(title="⚠ Threats Detected", border_style="red")
            threat_table.add_column("Target", style="red")
            threat_table.add_column("Score", justify="right")
            threat_table.add_column("Confidence", style="bold")
            threat_table.add_column("Summary")
            for t in threat_scores[:20]:
                color = "red" if t.confidence in ("HIGH", "CRITICAL") else "yellow" if t.confidence == "MEDIUM" else "dim"
                threat_table.add_row(
                    t.target,
                    f"{t.overall_score:.2f}",
                    f"[{color}]{t.confidence}[/]",
                    t.summary,
                )
            console.print(threat_table)
        else:
            console.print("[green]✓ No significant threats detected[/green]")

        # TLS fingerprints
        if tls_fps:
            fp_table = Table(title="TLS Fingerprints", border_style="dim")
            fp_table.add_column("Source", style="cyan")
            fp_table.add_column("JA4/JA3")
            fp_table.add_column("SNI", style="green")
            fp_table.add_column("Direction")
            for fp in tls_fps[:15]:
                fp_table.add_row(
                    f"{fp.source_ip}:{fp.source_port}",
                    fp.ja4 or fp.ja3_hash or "—",
                    fp.sni or "—",
                    "Client Hello" if fp.is_client_hello else "Server Hello" if fp.is_server_hello else "—",
                )
            console.print(fp_table)

        console.print()


def main():
    cli()


if __name__ == "__main__":
    main()