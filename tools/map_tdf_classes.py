#!/usr/bin/env python3
"""Mapping TDF classes to their field tables.

NOTE: this tool does not work on the Steam binary - the .text section is
encrypted (entropy 1.000), so the instruction scan returns noise. Kept for
later: it will be useful on a memory dump of the process once the code has
been decrypted. Details in docs/decisions.md.

Field tables and class names have no absolute references in the binary - x64
code addresses them RIP-relatively. Instead of a full disassembler we only
scan `lea r64, [rip+disp32]` instructions (48/4C 8D /r), because that is
exactly how the code loads addresses of static tables.

Method:
  1. find all `lea`s and compute their targets,
  2. targets that land in the set of field records = starts of class tables
     (this solves the glued-blocks problem - the boundaries come from the code,
      not from guessing gaps),
  3. take the class name from a nearby `lea` to a "Blaze::..." string.

Usage:
    python tools/map_tdf_classes.py "D:\\...\\NFS14.exe"
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe_probe import PE  # noqa: E402

# lea r64, [rip+disp32] -- REX.W (48) or REX.WR (4C), opcode 8D,
# modrm with mod=00 and rm=101 (RIP-relative): 05,0D,15,1D,25,2D,35,3D
LEA_RE = re.compile(rb"[\x48\x4C]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]", re.DOTALL)
LEA_LEN = 7

CLASS_NAME_RE = re.compile(r"^Blaze::[A-Za-z0-9_]+::[A-Za-z0-9_]+$")


def find_lea_refs(pe: PE) -> list[tuple[int, int]]:
    """Returns (instruction_offset, target_VA) for every rip-relative lea."""
    text = next(s for s in pe.sections if s.name == ".text")
    lo, hi = text.raw_ptr, text.raw_ptr + text.raw_size
    blob = pe.data[lo:hi]
    base_va = pe.image_base + text.va

    refs: list[tuple[int, int]] = []
    for m in LEA_RE.finditer(blob):
        i = m.start()
        if i + LEA_LEN > len(blob):
            continue
        disp = struct.unpack_from("<i", blob, i + 3)[0]
        # address is relative to the next instruction
        target = base_va + i + LEA_LEN + disp
        refs.append((lo + i, target))
    return refs


def find_class_names(pe: PE) -> dict[int, str]:
    """VA -> class name for strings of the form Blaze::Component::Type."""
    out: dict[int, str] = {}
    for m in re.finditer(rb"Blaze::[A-Za-z0-9_]+::[A-Za-z0-9_]+\x00", pe.data):
        text = m.group()[:-1].decode("ascii")
        if not CLASS_NAME_RE.match(text):
            continue
        va = pe.off_to_va(m.start())
        if va is not None:
            out[va] = text
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", type=Path,
                    help="NFS14.exe OR a full .dmp minidump (decrypted .text from RAM)")
    ap.add_argument("--members", type=Path, default=Path("docs/recon/tdf_members.json"))
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"))
    ap.add_argument("--window", type=int, default=256,
                    help="how many bytes of code around a lea to search for a name/table pair")
    args = ap.parse_args()

    # .exe -> PE (on disk, .text encrypted); .dmp -> image from memory
    # (.text decrypted). Told apart by the MDMP signature.
    head = args.exe.read_bytes()[:4]
    if head == b"MDMP":
        from dump_image import load_dump
        pe = load_dump(args.exe)
    else:
        pe = PE(args.exe.read_bytes())
    members: list[dict] = json.loads(args.members.read_text(encoding="utf-8"))
    members.sort(key=lambda e: e["va"])
    member_vas = {e["va"] for e in members}
    member_va_list = [e["va"] for e in members]

    class_names = find_class_names(pe)
    refs = find_lea_refs(pe)
    print(f"lea rip-relative:     {len(refs):,}")
    print(f"Blaze class names:    {len(class_names):,}")

    # lea targets that hit a field record exactly = table starts.
    array_starts = sorted({t for _, t in refs if t in member_vas})
    print(f"field table starts:   {len(array_starts):,}")

    # Index: code offset -> target, sorted, so we can search the neighbourhood.
    refs.sort()
    ref_offsets = [o for o, _ in refs]

    # For every lea to a class name, look nearby for a lea to a field table.
    pairs: dict[int, str] = {}          # array_start -> class name
    conflicts: dict[int, set[str]] = defaultdict(set)
    for off, target in refs:
        name = class_names.get(target)
        if name is None:
            continue
        lo = bisect.bisect_left(ref_offsets, off - args.window)
        hi = bisect.bisect_right(ref_offsets, off + args.window)
        best: tuple[int, int] | None = None      # (distance, array_start)
        for j in range(lo, hi):
            cand = refs[j][1]
            if cand not in member_vas:
                continue
            dist = abs(refs[j][0] - off)
            if best is None or dist < best[0]:
                best = (dist, cand)
        if best is None:
            continue
        start = best[1]
        if start in pairs and pairs[start] != name:
            conflicts[start].add(pairs[start])
            conflicts[start].add(name)
        pairs[start] = name

    print(f"paired classes:       {len(pairs):,}")
    if conflicts:
        print(f"collisions (several names for one table): {len(conflicts):,}")

    # Each table extends up to the next table start.
    boundaries = sorted(set(array_starts) | set(pairs))
    lines = [
        "# TDF classes and their fields (reconstructed from NFS14.exe)",
        "",
        "> Older heuristic (table boundaries from `lea` instructions): it glues neighbouring "
        "classes together. The exact boundaries come from `tools/tdf_classes.py` (a record with "
        "`meta[1] == 0` ends its class) - see docs/protocol.md, section 3.",
        "",
        f"- Field records: **{len(members):,}**",
        f"- Detected tables (boundaries from `lea` instructions in the code): **{len(boundaries):,}**",
        f"- Named classes: **{len(pairs):,}**",
        "",
        "Field order is the order from the table, i.e. the TDF encoding order. "
        "`meta` is the record's 4 bytes of metadata (candidates: type code, "
        "field offset in the structure, size).",
        "",
    ]

    named = 0
    for i, start in enumerate(boundaries):
        end = boundaries[i + 1] if i + 1 < len(boundaries) else None
        lo_i = bisect.bisect_left(member_va_list, start)
        hi_i = bisect.bisect_left(member_va_list, end) if end else len(members)
        fields = members[lo_i:hi_i]
        if not fields:
            continue
        name = pairs.get(start)
        if name:
            named += 1
        title = name or f"(unnamed table @ {start:#014x})"
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"`{start:#014x}` - {len(fields)} fields")
        lines.append("")
        lines.append("| tag | field | meta |")
        lines.append("| --- | --- | --- |")
        for f in fields:
            meta = " ".join(f"{b:02x}" for b in f["meta"])
            lines.append(f"| `{f['tag']}` | {f['name']} | `{meta}` |")
        lines.append("")

    out_md = args.out / "tdf_classes.md"
    out_md.write_text("\n".join(lines), encoding="utf-8")

    out_json = args.out / "tdf_classes.json"
    out_json.write_text(json.dumps(
        {f"{k:#014x}": v for k, v in sorted(pairs.items())}, indent=1),
        encoding="utf-8")

    print(f"named tables in the report: {named:,}")
    print(f"-> {out_md}")
    print(f"-> {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
