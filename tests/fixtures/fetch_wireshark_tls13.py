"""Re-extract the Wireshark TLS 1.3 reference frame payloads (offline check).

The committed ``wireshark_tls13_rfc8446.json`` holds only the TCP payload bytes
for frames 1–7 of Wireshark's ``test/captures/tls13-rfc8446.pcap`` at commit
``62874e37``. Those bytes are what the JA3/JA4 conformance test consumes, so
the suite runs offline and does not redistribute the upstream capture.

Run this when refreshing the fixture (it needs network access)::

    python tests/fixtures/fetch_wireshark_tls13.py            # verify
    python tests/fixtures/fetch_wireshark_tls13.py --write    # re-extract

Verification fails if the upstream file digest changed, which would mean the
reference values no longer describe the pinned capture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

UPSTREAM = {
    "project": "wireshark",
    "path": "test/captures/tls13-rfc8446.pcap",
    "commit": "62874e37789272afdcf97d25339428b60b2c84b0",
    "url": (
        "https://raw.githubusercontent.com/wireshark/wireshark/"
        "62874e37789272afdcf97d25339428b60b2c84b0/test/captures/tls13-rfc8446.pcap"
    ),
    "sha256": "e24aaedb2912f9ea371f8a1fbd360ccccc0154737aa5e422e206cd8bc0b783aa",
    "license": "GPL-2.0-or-later (Wireshark)",
}

FRAMES = (1, 2, 3, 4, 5, 6, 7)
FIXTURE = Path(__file__).with_name("wireshark_tls13_rfc8446.json")


def extract(path: Path) -> dict:
    from scapy.all import TCP, rdpcap

    packets = rdpcap(str(path))
    frames: dict[str, dict] = {}
    for n in FRAMES:
        pkt = packets[n - 1]
        tcp = pkt[TCP]
        frames[str(n)] = {
            "src": pkt["IP"].src,
            "sport": tcp.sport,
            "dst": pkt["IP"].dst,
            "dport": tcp.dport,
            "seq": tcp.seq,
            "ts": float(pkt.time),
            "payload": bytes(tcp.payload).hex(),
        }
    return frames


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="rewrite the fixture")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "tls13-rfc8446.pcap"
        print(f"downloading {UPSTREAM['url']}")
        urllib.request.urlretrieve(UPSTREAM["url"], target)  # noqa: S310 (pinned URL)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        print(f"sha256 {digest}")
        if digest != UPSTREAM["sha256"]:
            print("UPSTREAM DIGEST CHANGED — the reference values no longer apply",
                  file=sys.stderr)
            return 2
        extracted = extract(target)

    current = json.loads(FIXTURE.read_text())
    if args.write:
        current["frames"] = extracted
        FIXTURE.write_text(json.dumps(current, indent=1) + "\n")
        print(f"rewrote {FIXTURE}")
        return 0

    if current.get("frames") != extracted:
        print("FIXTURE MISMATCH — run with --write and re-check expected digests",
              file=sys.stderr)
        return 1
    print("fixture matches the pinned upstream capture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
