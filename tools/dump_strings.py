#!/usr/bin/env python3
"""Phase 0 - extracting strings from the NFS Rivals binary.

Blaze/DirtySDK are statically linked into NFS14.exe, so the binary contains
the client's string tables: backend host names, command names, SDK versions.
This is our first source of truth about the protocol - the EA servers have been
dead since 2025-10-07 and server->client traffic can no longer be recorded.

Usage:
    python tools/dump_strings.py "D:\\...\\NFS14.exe"
    python tools/dump_strings.py "...\\NFS14.exe" --all      # + full dump
    python tools/dump_strings.py "...\\NFS14.exe" --tags     # + TDF tag candidates
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MIN_LEN = 4

# Categories are ordered by importance for phase 0. Every string lands in the
# first matching category, so the report does not repeat itself.
CATEGORIES: list[tuple[str, str, str]] = [
    (
        "hosts",
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
        r"(?:ea|easports|eamobile|origin|dice|nfs)\.com",
        "EA backend host names - the most important result. This is where we look for the redirector.",
    ),
    (
        "urls",
        r"https?://[^\s\"'<>]{4,}",
        "Full URLs - HTTPS endpoints to stub out (config, telemetry, QoS).",
    ),
    (
        "blaze",
        r"(?i)blaze",
        "Everything that touches BlazeSDK - component names, connection states, errors.",
    ),
    (
        "dirtysdk",
        r"(?i)protossl|dirtysock|dirtysdk|netconn|protohttp|protoupnp|protoadvt"
        r"|protossl|protostream|netgame|commudp|protomangle",
        "DirtySDK - EA's network layer. The ProtoSSL version decides whether "
        "the forged certificate trick will work.",
    ),
    (
        "components",
        r"(?i)preauth|postauth|usersession|gamemanager|matchmak|associationlist"
        r"|gamereport|playgroup|censusdata|clientmetrics|redirector|util(?:comp)?"
        r"|authentication|messaging|leaderboard|telemetry",
        "Blaze component and command names - the map of RPCs we have to handle.",
    ),
    (
        "auth",
        r"(?i)nucleus|persona|entitlement|authtoken|logintoken|handoff"
        r"|\borigin\b|accesstoken|sessionkey",
        "Login layer - how the client gets a token from the EA App and what it does with it.",
    ),
    (
        "netcode",
        r"(?i)\bnat\b|upnp|qos\b|latency|ping\b|peer\b|topology|mesh\b|hostmigrat"
        r"|alldrive|multiplayer|session",
        "P2P gameplay - topology, NAT, AllDrive. Important for phases 2 and 5.",
    ),
    (
        "versions",
        r"(?i)\bver(?:sion)?\s*[:=]|\bsdk\b|\bbuild\b\s*[:=]|\d+\.\d+\.\d+\.\d+",
        "SDK and build versions - let us match our emulator to the right Blaze era.",
    ),
]

# TDF tag candidates: 4 characters [A-Z0-9], they often come in series.
TDF_TAG_RE = re.compile(r"^[A-Z][A-Z0-9]{3}$")

ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass(frozen=True)
class Found:
    offset: int
    encoding: str
    text: str


def extract(data: bytes) -> list[Found]:
    """Extracts ASCII and UTF-16LE strings together with their file offset.

    The offset will come in handy later in Ghidra - it lets you find the code
    that uses a given string.
    """
    out: list[Found] = []
    for m in ASCII_RE.finditer(data):
        out.append(Found(m.start(), "ascii", m.group().decode("ascii")))
    for m in UTF16_RE.finditer(data):
        out.append(Found(m.start(), "utf16", m.group().decode("utf-16-le")))
    out.sort(key=lambda f: f.offset)
    return out


def categorize(found: list[Found]) -> dict[str, list[Found]]:
    compiled = [(name, re.compile(pat)) for name, pat, _ in CATEGORIES]
    buckets: dict[str, list[Found]] = {name: [] for name, _, _ in CATEGORIES}
    for f in found:
        for name, rx in compiled:
            if rx.search(f.text):
                buckets[name].append(f)
                break
    return buckets


def dedupe(items: list[Found]) -> list[Found]:
    """Keeps the first occurrence of every unique text."""
    seen: set[str] = set()
    out: list[Found] = []
    for f in items:
        if f.text not in seen:
            seen.add(f.text)
            out.append(f)
    return out


def tdf_tag_candidates(found: list[Found]) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for f in found:
        if TDF_TAG_RE.match(f.text):
            counts[f.text] += 1
    return counts.most_common()


def render_report(exe: Path, found: list[Found], buckets: dict[str, list[Found]],
                  tags: list[tuple[str, int]] | None) -> str:
    lines = [
        f"# String dump: {exe.name}",
        "",
        f"- File: `{exe}`",
        f"- Size: {exe.stat().st_size:,} B",
        f"- Strings found (>= {MIN_LEN} characters): {len(found):,}",
        "",
        "Offsets are file positions (not RVAs) - for use in a hex editor.",
        "",
    ]
    for name, _, desc in CATEGORIES:
        items = dedupe(buckets[name])
        lines += [f"## {name} ({len(items)})", "", f"_{desc}_", ""]
        if not items:
            lines += ["(no matches)", ""]
            continue
        lines.append("```")
        for f in items:
            lines.append(f"{f.offset:#010x}  {f.encoding:5}  {f.text}")
        lines += ["```", ""]

    if tags is not None:
        lines += [
            f"## TDF tag candidates ({len(tags)})",
            "",
            "_4-character strings [A-Z][A-Z0-9]{3}. Lots of false positives, but "
            "real TDF tags look exactly like this._",
            "",
            "```",
        ]
        for tag, count in tags:
            lines.append(f"{tag}  x{count}")
        lines += ["```", ""]

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", type=Path, help="path to NFS14.exe")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"),
                    help="output directory (default docs/recon)")
    ap.add_argument("--all", action="store_true",
                    help="also write a full dump of all strings")
    ap.add_argument("--tags", action="store_true",
                    help="add a section with TDF tag candidates")
    args = ap.parse_args()

    if not args.exe.is_file():
        print(f"no such file: {args.exe}", file=sys.stderr)
        return 1

    data = args.exe.read_bytes()
    found = extract(data)
    buckets = categorize(found)
    tags = tdf_tag_candidates(found) if args.tags else None

    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.exe.stem
    report_path = args.out / f"strings_{stem}.md"
    report_path.write_text(render_report(args.exe, found, buckets, tags),
                           encoding="utf-8")
    print(f"report -> {report_path}")

    if args.all:
        all_path = args.out / f"strings_{stem}_all.txt"
        with all_path.open("w", encoding="utf-8") as fh:
            for f in found:
                fh.write(f"{f.offset:#010x}\t{f.encoding}\t{f.text}\n")
        print(f"full dump -> {all_path}")

    print()
    for name, _, _ in CATEGORIES:
        print(f"  {name:12} {len(dedupe(buckets[name])):6,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
