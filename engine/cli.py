"""GHOSTWIRE CLI — network forensics from the terminal.

Usage:
    ghostwire analyze <pcap_file> [--output json|summary] [--parser dpkt|scapy]
    ghostwire hunt <pcap_file> [--query <name>|--all]
    ghostwire report <pcap_file> [--format markdown|text|stix] [--output-file <path>]
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from scapy.all import Scapy_Exception

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
from engine.detection.hunt import BUILTIN_QUERIES, run_hunt, run_all_hunts
from engine.export.stix import build_stix_bundle, iocs_from_analysis, export_stix
from engine.export.report import generate_markdown_report, generate_text_report, save_report
from engine.export.mitre_map import map_analysis_to_attack

console = Console()
logger = logging.getLogger("ghostwire")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(name)s %(levelname)s: %(message)s")


def _full_analysis(pcap_file: str, parser: str = "auto", min_packets: int = 10):
    """Run the full analysis pipeline and return results dict."""
    packets = load_pcap(pcap_file, parser=parser)

    # Protocol identification
    for pkt in packets:
        if pkt.raw_payload:
            result = identify_protocol(
                pkt.src_port, pkt.dst_port, pkt.raw_payload,
                pkt.protocol_l4, pkt.metadata
            )
            if result.l7_protocol:
                pkt.protocol_l7 = result.l7_protocol
                pkt.metadata["protocol_result"] = {
                    "tls": asdict(result.tls) if result.tls else None,
                    "dns": asdict(result.dns) if result.dns else None,
                    "http": asdict(result.http) if result.http else None,
                    "ssh": asdict(result.ssh) if result.ssh else None,
                    "icmp": asdict(result.icmp) if result.icmp else None,
                }

    sessions = reconstruct_sessions(packets)

    # Fingerprinting
    tls_fps = tls_fingerprint(packets)
    http_fps = http_fingerprint(packets)
    ssh_fps = ssh_fingerprint(packets)

    # C2 matching
    all_c2_matches: dict[str, list] = {}
    for fp in tls_fps:
        key = f"{fp.source_ip}:{fp.source_port}"
        matches = match_all(ja4=fp.ja4, ja3=fp.ja3_hash)
        if matches:
            all_c2_matches.setdefault(key, []).extend(matches)
    for fp in http_fps:
        matches = match_all(user_agent=fp.user_agent)
        if matches:
            all_c2_matches.setdefault(fp.source_ip, []).extend(matches)
    for fp in ssh_fps:
        matches = match_all(ssh_banner=fp.client_banner, ssh_software=fp.client_software)
        if matches:
            all_c2_matches.setdefault(fp.source_ip, []).extend(matches)

    # Beacon detection
    beacons = detect_beacons(sessions, min_packets=min_packets)

    # DNS threats
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

    # Composite scoring
    beacon_map = {b.session_id: b for b in beacons}
    threat_scores = []
    for session in sessions:
        c2 = all_c2_matches.get(f"{session.src_ip}:{session.src_port}", [])
        c2 += all_c2_matches.get(f"{session.dst_ip}:{session.dst_port}", [])
        beacon = beacon_map.get(session.session_id)
        score = score_session(session.session_id, beacon=beacon, c2_matches=c2)
        threat_scores.append(score)

    return {
        "packets": packets,
        "sessions": sessions,
        "tls_fps": tls_fps,
        "http_fps": http_fps,
        "ssh_fps": ssh_fps,
        "all_c2_matches": all_c2_matches,
        "beacons": beacons,
        "dns_threats_all": dns_threats_all,
        "threat_scores": threat_scores,
    }


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
    try:
        results = _full_analysis(pcap_file, parser=parser, min_packets=min_packets)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)
    elapsed = time.time() - start_time

    # Filter threats by min_score
    threat_scores = [t for t in results["threat_scores"] if t.overall_score >= min_score]
    threat_scores.sort(key=lambda s: s.overall_score, reverse=True)

    if output == "json":
        result = {
            "ghostwire_version": __version__,
            "file": str(pcap_file),
            "analysis_time": round(elapsed, 2),
            "packets_total": len(results["packets"]),
            "sessions_total": len(results["sessions"]),
            "tls_fingerprints": len(results["tls_fps"]),
            "http_fingerprints": len(results["http_fps"]),
            "ssh_fingerprints": len(results["ssh_fps"]),
            "beacons_detected": len(results["beacons"]),
            "dns_threats": len(results["dns_threats_all"]),
            "c2_matches": sum(len(v) for v in results["all_c2_matches"].values()),
            "threats": [t.to_dict() for t in threat_scores[:50]],
        }
        click.echo(json.dumps(result, indent=2))

    else:
        _print_rich_summary(pcap_file, results, threat_scores, elapsed)


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--query", "-q", type=click.Choice(list(BUILTIN_QUERIES.keys())),
              help="Run a specific hunt query")
@click.option("--all", "run_all", is_flag=True, help="Run all hunt queries")
@click.option("--output", "-o", type=click.Choice(["json", "summary"]), default="summary")
def hunt(pcap_file: str, query: Optional[str], run_all: bool, output: str):
    """Hunt for threats using predefined queries."""

    try:
        packets = load_pcap(pcap_file)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)

    # Protocol identification
    for pkt in packets:
        if pkt.raw_payload:
            result = identify_protocol(pkt.src_port, pkt.dst_port, pkt.raw_payload, pkt.protocol_l4, pkt.metadata)
            if result.l7_protocol:
                pkt.protocol_l7 = result.l7_protocol

    sessions = reconstruct_sessions(packets)

    if run_all:
        hunt_results = run_all_hunts(sessions, packets)
    elif query:
        hunt_results = {query: run_hunt(query, sessions, packets)}
    else:
        # Show available queries
        console.print()
        console.print(Panel.fit("[bold green]GHOSTWIRE[/] Hunt Mode", border_style="green"))
        table = Table(title="Available Hunt Queries", border_style="dim")
        table.add_column("Query", style="cyan")
        table.add_column("Name")
        table.add_column("Category", style="dim")
        table.add_column("Description")
        for name, meta in BUILTIN_QUERIES.items():
            table.add_row(name, meta["name"], meta["category"], meta["description"])
        console.print(table)
        console.print("\nRun: [cyan]ghostwire hunt capture.pcap --query suspicious_beacons[/]")
        return

    if output == "json":
        click.echo(json.dumps(hunt_results, indent=2, default=str))
    else:
        console.print()
        console.print(Panel.fit("[bold green]GHOSTWIRE[/] Hunt Results", border_style="green"))
        for name, findings in hunt_results.items():
            meta = BUILTIN_QUERIES.get(name, {})
            console.print(f"\n[bold]{meta.get('name', name)}[/] — {len(findings)} findings")
            if findings:
                for f in findings[:10]:
                    reason = f.get("reason", "")
                    console.print(f"  [dim]•[/] {reason}")
            else:
                console.print("  [dim]No findings[/]")


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", type=click.Choice(["markdown", "text", "stix"]), default="markdown",
              help="Report format")
@click.option("--output-file", "-o", type=click.Path(), help="Output file path")
@click.option("--min-score", type=float, default=0.25)
def report(pcap_file: str, fmt: str, output_file: Optional[str], min_score: float):
    """Generate threat analysis report."""

    try:
        results = _full_analysis(pcap_file)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)

    analysis = {
        "ghostwire_version": __version__,
        "file": str(pcap_file),
        "analysis_time": 0,
        "packets_total": len(results["packets"]),
        "sessions_total": len(results["sessions"]),
        "tls_fingerprints": len(results["tls_fps"]),
        "http_fingerprints": len(results["http_fps"]),
        "ssh_fingerprints": len(results["ssh_fps"]),
        "beacons_detected": len(results["beacons"]),
        "dns_threats": len(results["dns_threats_all"]),
        "c2_matches": sum(len(v) for v in results["all_c2_matches"].values()),
        "threats": [t.to_dict() for t in results["threat_scores"] if t.overall_score >= min_score],
    }

    if fmt == "stix":
        iocs = iocs_from_analysis(analysis)
        bundle = build_stix_bundle(iocs, source_file=str(pcap_file))
        content = json.dumps(bundle, indent=2)
        if not output_file:
            output_file = str(Path(pcap_file).with_suffix(".stix.json"))

    elif fmt == "markdown":
        content = generate_markdown_report(analysis)
        if not output_file:
            output_file = str(Path(pcap_file).with_suffix(".report.md"))

    else:  # text
        content = generate_text_report(analysis)
        if not output_file:
            output_file = str(Path(pcap_file).with_suffix(".report.txt"))

    save_report(content, output_file)
    console.print(f"[green]✓[/] Report saved to [cyan]{output_file}[/]")


def _print_rich_summary(pcap_file, results, threat_scores, elapsed):
    """Print rich terminal dashboard."""
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
    overview.add_row("Packets", str(len(results["packets"])))
    overview.add_row("Sessions", str(len(results["sessions"])))
    overview.add_row("TLS Fingerprints", str(len(results["tls_fps"])))
    overview.add_row("HTTP Fingerprints", str(len(results["http_fps"])))
    overview.add_row("SSH Fingerprints", str(len(results["ssh_fps"])))
    overview.add_row("C2 Matches", str(sum(len(v) for v in results["all_c2_matches"].values())))
    overview.add_row("Beacons Detected", str(len(results["beacons"])))
    overview.add_row("DNS Threats", str(len(results["dns_threats_all"])))
    overview.add_row("Analysis Time", f"{elapsed:.2f}s")
    console.print(overview)

    # Protocol breakdown
    proto_counts: dict[str, int] = {}
    for pkt in results["packets"]:
        p = pkt.protocol_l7 or pkt.protocol_l4 or "Other"
        proto_counts[p] = proto_counts.get(p, 0) + 1

    proto_table = Table(title="Protocol Breakdown", border_style="dim")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Packets", justify="right", style="white")
    proto_table.add_column("%", justify="right", style="dim")
    for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        pct = count / len(results["packets"]) * 100
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
    if results["tls_fps"]:
        fp_table = Table(title="TLS Fingerprints", border_style="dim")
        fp_table.add_column("Source", style="cyan")
        fp_table.add_column("JA4/JA3")
        fp_table.add_column("SNI", style="green")
        fp_table.add_column("Direction")
        for fp in results["tls_fps"][:15]:
            fp_table.add_row(
                f"{fp.source_ip}:{fp.source_port}",
                fp.ja4 or fp.ja3_hash or "—",
                fp.sni or "—",
                "Client Hello" if fp.is_client_hello else "Server Hello" if fp.is_server_hello else "—",
            )
        console.print(fp_table)

    # MITRE ATT&CK mapping
    attack_map = map_analysis_to_attack({
        "threats": [t.to_dict() for t in threat_scores]
    })
    if attack_map:
        mitre_table = Table(title="MITRE ATT&CK Mapping", border_style="dim")
        mitre_table.add_column("Tactic", style="cyan")
        mitre_table.add_column("Technique")
        mitre_table.add_column("ID", style="yellow")
        for m in attack_map:
            mitre_table.add_row(m.tactic, m.technique_name, m.technique_id)
        console.print(mitre_table)

    console.print()


def main():
    cli()


if __name__ == "__main__":
    main()