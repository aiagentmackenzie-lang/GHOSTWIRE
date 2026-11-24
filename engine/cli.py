"""GHOSTWIRE CLI — network forensics from the terminal.

Usage:
    ghostwire analyze <pcap_file> [--output json|summary] [--parser dpkt|scapy]
    ghostwire hunt <pcap_file> [--query <name>|--all]
    ghostwire report <pcap_file> [--format markdown|text|stix] [--output-file <path>]

Every command renders the same evidence: ``engine.analysis`` produces one
versioned result (run metadata, coverage, observations, findings, conversation
assessments, selection counters) and the CLI only chooses how much of it to
show. Counting units and thresholds are printed next to the numbers so an
empty table can be told apart from an empty capture.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# scapy is an optional fast-path dependency (pcap_loader falls back to dpkt).
# Import Scapy_Exception lazily so the CLI still starts when scapy is absent.
try:
    from scapy.all import Scapy_Exception
except ImportError:
    class Scapy_Exception(Exception):  # type: ignore[no-redef]
        """Fallback so `except (ValueError, Scapy_Exception)` is valid without scapy."""

from engine import __version__
from engine.analysis import AnalysisResult, run_analysis
from engine.detection.hunt import BUILTIN_QUERIES, run_all_hunts, run_hunt
from engine.evidence import COVERAGE_COMPLETE, COVERAGE_LABELS
from engine.export.mitre_map import map_analysis_to_attack
from engine.export.report import generate_markdown_report, generate_text_report, save_report
from engine.export.stix import build_bundle_from_analysis, validate_bundle

console = Console()
logger = logging.getLogger("ghostwire")

#: Historical JSON cap on returned session rows. Now surfaced in
#: ``selection.truncation`` instead of silently applied.
MAX_THREAT_ROWS = 50


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(name)s %(levelname)s: %(message)s")


def _distinct_c2_count(all_c2_matches: dict | None = None) -> int:
    """Deprecated shim retained for callers of the old helper.

    Counting now happens in :mod:`engine.analysis` from findings, so two views
    cannot disagree about what a "C2 match" is.
    """
    if not all_c2_matches:
        return 0
    seen = set()
    for matches in all_c2_matches.values():
        for m in matches:
            seen.add((m.tool_name, m.match_type, m.matched_value))
    return len(seen)


def _full_analysis(pcap_file: str, parser: str = "auto", min_packets: int = 10,
                   keep_packets: bool = False, min_score: float = 0.25) -> dict:
    """Run the pipeline and return the internal (live-object) result dict.

    Retained for tests and internal callers that need the TCPSession and
    fingerprint objects. The analyst-facing shape is
    :meth:`engine.analysis.AnalysisResult.to_output`.
    """
    result = run_analysis(
        pcap_file, parser=parser, min_packets=min_packets,
        min_score=min_score, keep_packets=keep_packets,
    )
    return result.legacy_dict()


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
@click.option("--min-score", type=float, default=0.25, show_default=True,
              help="Minimum conversation score to list as a session row (0.0-1.0). "
                   "Findings are listed regardless.")
@click.option("--min-packets", type=int, default=10, show_default=True,
              help="Minimum packets per session for beacon analysis")
def analyze(pcap_file: str, output: str, parser: str, min_score: float, min_packets: int):
    """Analyze a PCAP file for threats, C2 beacons, and fingerprints."""

    start_time = time.time()
    try:
        result = run_analysis(pcap_file, parser=parser, min_packets=min_packets,
                              min_score=min_score)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)
    elapsed = time.time() - start_time

    if output == "json":
        click.echo(json.dumps(result.to_output(), indent=2, default=str))
    else:
        _print_rich_summary(pcap_file, result, elapsed)


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--query", "-q", type=click.Choice(list(BUILTIN_QUERIES.keys())),
              help="Run a specific hunt query")
@click.option("--all", "run_all", is_flag=True, help="Run all hunt queries")
@click.option("--output", "-o", type=click.Choice(["json", "summary"]), default="summary")
def hunt(pcap_file: str, query: str | None, run_all: bool, output: str):
    """Hunt for threats using predefined queries.

    Hunt groups evidence differently from ``analyze`` (it returns candidate
    observations, one row per reason), but every row carries the same frame,
    timestamp and endpoint references so the two views can be reconciled.
    """
    from engine.analysis import run_analysis as _run

    try:
        # One analysis pass supplies protocol decoding, sessions and the
        # capture/coverage identity the rows reference.
        analysis = _run(pcap_file, min_score=0.0, keep_packets=True)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)

    packets = analysis.packets
    sessions = analysis.sessions

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
        payload = {
            **hunt_results,
            "_meta": {
                "schema_version": analysis.run.schema_version,
                "ghostwire_version": __version__,
                "run": analysis.run.to_dict(),
                "coverage": analysis.coverage.to_dict(),
                "counting": {
                    "unit": "one row per candidate observation or reason",
                    "note": ("Hunt rows are pre-selection: they are not filtered by "
                             "--min-score and do not imply a conversation score."),
                },
            },
        }
        click.echo(json.dumps(payload, indent=2, default=str))
    else:
        console.print()
        console.print(Panel.fit("[bold green]GHOSTWIRE[/] Hunt Results", border_style="green"))
        console.print(
            f"[dim]Capture {analysis.run.capture.get('sha256', '')[:16]}… · "
            f"coverage: {analysis.coverage.status} · "
            f"{analysis.coverage.frames_decoded}/{analysis.coverage.frames_read} frames decoded[/]"
        )
        if analysis.coverage.status != COVERAGE_COMPLETE:
            for reason in analysis.coverage.reasons:
                console.print(f"[yellow]![/] {reason}")
        for name, findings in hunt_results.items():
            meta = BUILTIN_QUERIES.get(name, {})
            console.print(f"\n[bold]{meta.get('name', name)}[/] — {len(findings)} row(s)")
            if findings:
                for f in findings[:10]:
                    reason = f.get("reason", "")
                    where = f.get("frame")
                    where_txt = f" [dim](frame {where})[/]" if where else ""
                    console.print(f"  [dim]•[/] {reason}{where_txt}")
            else:
                console.print("  [dim]No observations matched this query[/]")


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", type=click.Choice(["markdown", "text", "stix"]), default="markdown",
              help="Report format")
@click.option("--output-file", "-o", type=click.Path(), help="Output file path")
@click.option("--min-score", type=float, default=0.25, show_default=True,
              help="Minimum conversation score to list as a session row (0.0-1.0)")
@click.option("--min-packets", type=int, default=10, show_default=True,
              help="Minimum packets per session for beacon analysis")
def report(pcap_file: str, fmt: str, output_file: str | None, min_score: float, min_packets: int):
    """Generate threat analysis report."""

    start_time = time.time()
    try:
        result = run_analysis(pcap_file, min_packets=min_packets,
                              min_score=min_score, keep_packets=True)
    except (ValueError, Scapy_Exception) as exc:
        console.print(f"[red]✗ Parse error:[/] {exc}")
        console.print("[dim]The file may be corrupt or not a valid PCAP/PCAPNG capture.[/]")
        sys.exit(1)
    except FileNotFoundError as exc:
        console.print(f"[red]✗ File not found:[/] {exc}")
        sys.exit(1)
    elapsed = time.time() - start_time

    analysis = result.to_output()
    analysis["analysis_time"] = round(elapsed, 3)
    analysis["report"] = {
        "selection_min_score": min_score,
        "min_packets": min_packets,
        "elapsed_seconds": round(elapsed, 3),
    }
    result.elapsed_seconds = elapsed

    if fmt == "stix":
        bundle = build_bundle_from_analysis(analysis)
        problems = validate_bundle(bundle)
        if problems:
            console.print("[yellow]![/] STIX structural check reported issues:")
            for p in problems[:5]:
                console.print(f"  [dim]{p}[/]")
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


def _print_rich_summary(pcap_file, result: AnalysisResult, elapsed: float):
    """Print the terminal view of the same evidence the JSON carries."""
    run = result.run
    capture = run.capture
    coverage = result.coverage

    console.print()
    console.print(Panel.fit(
        f"[bold green]GHOSTWIRE[/] v{__version__} — Network Forensics Engine\n"
        f"[dim]The wire remembers everything[/]",
        border_style="green",
    ))

    overview = Table(title="Analysis Summary", show_header=False, border_style="dim")
    overview.add_column("Key", style="cyan")
    overview.add_column("Value", style="white")
    overview.add_row("File", str(pcap_file))
    overview.add_row("Capture SHA-256", capture.get("sha256", "unavailable")[:32] + "…")
    overview.add_row("Parser", f"{capture.get('parser_used') or 'unavailable'}"
                     + (" (fallback)" if capture.get("parser_fallback") else ""))
    overview.add_row("Link type", str(capture.get("link_type_name") or "unknown"))
    overview.add_row("Frames", f"{capture.get('frames_read', 0)} read, "
                                f"{capture.get('frames_decoded', 0)} decoded")
    overview.add_row("Time span", _fmt_duration(capture.get("duration_seconds")))
    overview.add_row("Ordering anomalies", str(capture.get("ordering_anomalies", 0)))
    overview.add_row("Coverage", f"{coverage.status} — {COVERAGE_LABELS.get(coverage.status, '')}")
    overview.add_row("TCP sessions", str(len(result.sessions)))
    overview.add_row("Findings", f"{len(result.findings)} recorded, "
                                 f"{result.selection.counts.get('findings_returned', 0)} shown")
    overview.add_row("Conversation rows", f"{result.selection.counts.get('sessions_returned', 0)} "
                                          f"at min-score {result.settings.get('min_score')}")
    overview.add_row("Beacons", str(len(result.beacons)))
    overview.add_row("TLS / HTTP / SSH fingerprints",
                     f"{len(result.tls_fps)} / {len(result.http_fps)} / {len(result.ssh_fps)}")
    overview.add_row("Analysis Time", f"{elapsed:.3f}s")
    console.print(overview)

    if coverage.status != COVERAGE_COMPLETE:
        console.print(Panel("\n".join(f"• {r}" for r in coverage.reasons),
                            title=f"[yellow]{COVERAGE_LABELS.get(coverage.status, coverage.status)}[/]",
                            border_style="yellow"))
    for limit in coverage.limits:
        console.print(f"[dim]limit: {limit}[/]")

    # Protocol breakdown — packet counts, one denominator.
    proto_counts = result.protocol_counts or {}
    total_packets = result.packets_total
    proto_table = Table(title=f"Protocol Breakdown (denominator: {total_packets} packets)",
                        border_style="dim")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Packets", justify="right", style="white")
    proto_table.add_column("%", justify="right", style="dim")
    if total_packets > 0:
        for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            proto_table.add_row(proto, str(count), f"{count / total_packets * 100:.1f}%")
    console.print(proto_table)

    # Findings — the evidence, independent of the session threshold.
    if result.findings:
        finding_table = Table(title="Findings (evidence, not filtered by session score)",
                              border_style="red")
        finding_table.add_column("Kind", style="cyan")
        finding_table.add_column("Subject")
        finding_table.add_column("Frame", justify="right")
        finding_table.add_column("Rule", style="dim")
        finding_table.add_column("Score", justify="right")
        finding_table.add_column("Why")
        for f in result.findings[:20]:
            frame: str = "—"
            if f.observation_ids:
                obs = next((o for o in result.observations
                            if o.observation_id == f.observation_ids[0]), None)
                if obs is not None:
                    frame = str(obs.frame) if obs.frame else "stream"
            finding_table.add_row(
                f.kind,
                _truncate(f.subject_value, 48),
                frame,
                f"{f.rule_id}@r{f.rule_revision}",
                f"{f.score:.3f}",
                " | ".join(r.detail for r in f.reasons[:2]) or f.summary,
            )
        console.print(finding_table)
        if len(result.findings) > 20:
            console.print(f"[dim]… {len(result.findings) - 20} further finding(s) in the JSON output[/]")
    else:
        console.print(f"[green]✓[/] {result.summary}")

    # DNS findings get their own section: they have no TCP session to sit in.
    dns_findings = [f for f in result.findings if f.kind == "dns"]
    if dns_findings:
        dns_table = Table(title="DNS Findings (independent of TCP sessions)", border_style="yellow")
        dns_table.add_column("Domain", style="yellow")
        dns_table.add_column("Frame", justify="right")
        dns_table.add_column("Rule")
        dns_table.add_column("Reasons")
        for f in dns_findings[:15]:
            frame_no = next((o.frame for o in result.observations
                             if f.observation_ids and o.observation_id == f.observation_ids[0]), 0)
            dns_table.add_row(f.subject_value, str(frame_no), f.rule_id, str(len(f.reasons)))
        console.print(dns_table)

    if result.threat_scores:
        threat_table = Table(
            title=f"Conversation Assessments (min-score {result.settings.get('min_score')})",
            border_style="red")
        threat_table.add_column("Conversation", style="red")
        threat_table.add_column("Score", justify="right")
        threat_table.add_column("Severity", style="bold")
        threat_table.add_column("Findings", justify="right")
        threat_table.add_column("Summary")
        for t in result.threat_scores[:20]:
            color = ("red" if t.confidence in ("HIGH", "CRITICAL")
                     else "yellow" if t.confidence == "MEDIUM" else "dim")
            threat_table.add_row(
                t.target,
                f"{t.overall_score:.3f}",
                f"[{color}]{t.confidence}[/]",
                str(len(t.finding_ids)),
                t.summary,
            )
        console.print(threat_table)
    elif result.findings:
        console.print(Panel(
            result.selection.explanation,
            title="[yellow]No conversation reached the session threshold[/]",
            border_style="yellow",
        ))
    else:
        console.print(f"[green]✓[/] {result.summary}")

    if result.selection.truncation.get("sessions_truncated"):
        console.print(
            f"[yellow]![/] Showing the first "
            f"{result.selection.truncation.get('sessions_limit')} conversation rows; "
            "the rest are omitted (ranked, not filtered)."
        )

    # TLS fingerprints
    if result.tls_fps:
        fp_table = Table(title="TLS Fingerprints", border_style="dim")
        fp_table.add_column("Client", style="cyan")
        fp_table.add_column("JA4")
        fp_table.add_column("JA3")
        fp_table.add_column("SNI", style="green")
        fp_table.add_column("Direction")
        for fp in result.tls_fps[:15]:
            fp_table.add_row(
                f"{fp.source_ip}:{fp.source_port}",
                fp.ja4 or "—",
                fp.ja3_hash or "—",
                fp.sni or "—",
                "Client Hello" if fp.is_client_hello else "Server Hello" if fp.is_server_hello else "—",
            )
        console.print(fp_table)

    # MITRE ATT&CK mapping
    attack_map = map_analysis_to_attack(result.to_output())
    if attack_map:
        mitre_table = Table(title="MITRE ATT&CK Mapping (from matched rules)", border_style="dim")
        mitre_table.add_column("Tactic", style="cyan")
        mitre_table.add_column("Technique")
        mitre_table.add_column("ID", style="yellow")
        for m in attack_map:
            mitre_table.add_row(m.tactic, m.technique_name, m.technique_id)
        console.print(mitre_table)

    console.print(f"[dim]{result.summary}[/]")
    console.print()


def _fmt_duration(seconds) -> str:
    if seconds is None:
        return "unavailable"
    return f"{seconds:.3f}s"


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


@cli.command("refresh-feeds")
@click.option("--feeds-dir", "feeds_dir", type=click.Path(exists=True, file_okay=False),
              default=str(Path(__file__).resolve().parent / "feeds"),
              show_default=True,
              help="Directory of *.json feed files to validate and summarize.")
def refresh_feeds(feeds_dir: str):
    """Validate and summarize C2 IOC feeds without running an analysis (Phase 4.2)."""
    from engine.feeds.loader import load_feeds_from_dir
    entries = load_feeds_from_dir(feeds_dir)
    if not entries:
        console.print(f"[yellow]No feed entries loaded from {feeds_dir}[/]")
        return
    by_tool: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for e in entries:
        by_tool[e.tool] = by_tool.get(e.tool, 0) + 1
        by_type[e.match_type] = by_type.get(e.match_type, 0) + 1
    console.print(f"[green]Loaded {len(entries)} feed entries from {feeds_dir}[/]")
    table = Table(title="Feeds by tool")
    table.add_column("Tool")
    table.add_column("Entries", justify="right")
    for tool, n in sorted(by_tool.items()):
        table.add_row(tool, str(n))
    console.print(table)
    table2 = Table(title="Feeds by match_type")
    table2.add_column("Match type")
    table2.add_column("Entries", justify="right")
    for mt, n in sorted(by_type.items()):
        table2.add_row(mt, str(n))
    console.print(table2)


def main():
    cli()


if __name__ == "__main__":
    main()
