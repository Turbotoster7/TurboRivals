#!/usr/bin/env python3
"""Extracting TDF metadata from the .rdata of the NFS Rivals binary.

Phase 0 finding: NFS14.exe contains tables of records in which a 24-bit TDF
tag sits right next to a pointer to the field name. Examples verified by
hand: 'BID ' -> mBlazeId, 'MAIL' -> mEmail, 'PASS' -> mPassword.

Record layout (24 or 32 bytes, the tail depends on the field type):

    +0  uint64  packed: bytes 1..3 are the TDF tag, bytes 4..7 are type metadata
    +8  ptr     field name ('m' + CamelCase convention)
    +16 ...     type-dependent tail

We do not rely on a fixed record size - we look for the pattern
(valid tag) + (pointer to a field name), which is robust against the
variable tail length.

Usage:
    python tools/extract_tdf_meta.py "D:\\...\\NFS14.exe"
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe_probe import PE, decode_tdf_tag  # noqa: E402

# Field names in BlazeSDK: 'm' + CamelCase. We require an uppercase letter after
# 'm', so we don't catch random words.
MEMBER_RE = re.compile(r"^m[A-Z][A-Za-z0-9_]{1,60}$")

# TDF tag: 4 characters, allowed A-Z 0-9 and underscore, spaces only as
# padding at the end (tags shorter than 4 characters).
TAG_RE = re.compile(r"^[A-Z0-9_][A-Z0-9_]*[ ]*$")


def valid_tag(tag: str) -> bool:
    return len(tag) == 4 and bool(TAG_RE.match(tag))


# Sections holding field tables. Initially we only scanned .rdata and because of
# that whole classes were missing: the QosConfigInfo table sits in .data (@0x141a32d80),
# so the class looked non-existent even though the game uses it. A memory dump also
# has dedicated TDF metadata sections (fieldinf/typeinfo).
DEFAULT_SECTIONS = (".rdata", ".data", "fieldinf", "typeinfo", ".rodata", "_RDATA")


def scan(pe: PE, section_names: tuple[str, ...] = DEFAULT_SECTIONS) -> list[dict]:
    """Walks the given sections every 8 bytes looking for (tag, field name) pairs."""
    secs = [s for s in pe.sections if s.name in section_names]
    if not secs:
        raise SystemExit(f"no sections {section_names} in the image")

    out: list[dict] = []
    seen: set[int] = set()
    for sec in secs:
        out.extend(_scan_section(pe, sec, seen))
    out.sort(key=lambda e: e["va"])
    return out


def _scan_section(pe: PE, sec, seen: set[int]) -> list[dict]:
    lo, hi = sec.raw_ptr, sec.raw_ptr + sec.raw_size
    data = pe.data
    out: list[dict] = []

    for off in range(lo, hi - 16, 8):
        q0, q1 = struct.unpack_from("<QQ", data, off)
        tag24 = (q0 >> 8) & 0xFFFFFF
        if tag24 == 0:
            continue
        tag = decode_tdf_tag(tag24)
        if not valid_tag(tag):
            continue
        if not (0x140000000 <= q1 < 0x150000000):
            continue
        name = pe.cstring_at(q1, limit=72)
        if name is None or not MEMBER_RE.match(name):
            continue
        va = pe.off_to_va(off)
        if va in seen:
            continue
        seen.add(va)
        out.append({
            "va": va,
            "sec": sec.name,
            "tag": tag,
            "name": name,
            # bytes 4..7 of the packed qword - candidates for the type code,
            # size and field offset in the structure
            "meta": [(q0 >> (8 * i)) & 0xFF for i in (4, 5, 6, 7)],
        })
    return out


def group_runs(entries: list[dict], gap: int = 64) -> list[list[dict]]:
    """Splits entries into contiguous blocks - candidates for single-class tables."""
    runs: list[list[dict]] = []
    current: list[dict] = []
    prev_va = None
    for e in entries:
        if prev_va is not None and e["va"] - prev_va > gap:
            runs.append(current)
            current = []
        current.append(e)
        prev_va = e["va"]
    if current:
        runs.append(current)
    return runs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", type=Path,
                    help="NFS14.exe OR a full .dmp minidump (more sections from RAM)")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"))
    ap.add_argument("--sections", default=",".join(DEFAULT_SECTIONS),
                    help="which sections to scan (comma-separated)")
    args = ap.parse_args()

    if not args.exe.is_file():
        print(f"no such file: {args.exe}", file=sys.stderr)
        return 1

    # .dmp = image from memory (also has fieldinf/typeinfo); .exe = file from disk
    if args.exe.read_bytes()[:4] == b"MDMP":
        from dump_image import load_dump
        pe = load_dump(args.exe)
    else:
        pe = PE(args.exe.read_bytes())
    wanted = tuple(s.strip() for s in args.sections.split(",") if s.strip())
    entries = scan(pe, wanted)
    per_sec = Counter(e["sec"] for e in entries)
    print("records per section: " +
          ", ".join(f"{k}={v:,}" for k, v in per_sec.most_common()))
    runs = group_runs(entries)

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "tdf_members.json"
    json_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")

    # Dictionary tag -> names. One tag can mean different things in different
    # classes, so we keep a set.
    by_tag: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        by_tag[e["tag"]].add(e["name"])

    lines = [
        "# TDF metadata extracted from NFS14.exe",
        "",
        f"- (tag, field) pairs found: **{len(entries):,}**",
        f"- Unique tags: **{len(by_tag):,}**",
        f"- Contiguous blocks (class candidates): **{len(runs):,}**",
        "",
        "A tag is a 24-bit value unpacked into 4 characters of 6 bits each "
        "(0 = space). These are exactly the tags that go over the wire.",
        "",
        "## Dictionary tag -> field",
        "",
        "| tag | field names |",
        "| --- | --- |",
    ]
    for tag in sorted(by_tag):
        names = ", ".join(sorted(by_tag[tag]))
        lines.append(f"| `{tag}` | {names} |")

    lines += ["", "## Blocks in address order", ""]
    for i, run in enumerate(runs):
        if len(run) < 2:
            continue
        head = run[0]["va"]
        lines.append(f"### block {i} @ {head:#014x} ({len(run)} fields)")
        lines.append("")
        lines.append("```")
        for e in run:
            meta = " ".join(f"{b:02x}" for b in e["meta"])
            lines.append(f"{e['tag']}  {meta}  {e['name']}")
        lines.append("```")
        lines.append("")

    md_path = args.out / "tdf_members.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"(tag, field) pairs:  {len(entries):,}")
    print(f"unique tags:         {len(by_tag):,}")
    print(f"blocks:              {len(runs):,}")
    print(f"-> {json_path}")
    print(f"-> {md_path}")

    # The 'meta[0]' byte is the best candidate for the TDF type code - we show
    # its distribution to see whether it has few discrete values.
    print("\nmeta[0] distribution (type code candidate):")
    for val, n in Counter(e["meta"][0] for e in entries).most_common(16):
        print(f"  {val:#04x}  {n:6,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
