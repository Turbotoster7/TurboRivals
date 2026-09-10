#!/usr/bin/env python3
"""Ekstrakcja metadanych TDF z .rdata binarki NFS Rivals.

Odkrycie z fazy 0: NFS14.exe zawiera tablice rekordow, w ktorych 24-bitowy
tag TDF lezy tuz obok wskaznika na nazwe pola. Przyklady zweryfikowane
recznie: 'BID ' -> mBlazeId, 'MAIL' -> mEmail, 'PASS' -> mPassword.

Uklad rekordu (24 lub 32 bajty, ogon zalezy od typu pola):

    +0  uint64  spakowane: bajty 1..3 to tag TDF, bajty 4..7 to metadane typu
    +8  ptr     nazwa pola (konwencja 'm' + CamelCase)
    +16 ...     ogon zalezny od typu

Nie polegamy na stalym rozmiarze rekordu - szukamy wzorca
(prawidlowy tag) + (wskaznik na nazwe pola), co jest odporne na
zmienna dlugosc ogona.

Uzycie:
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

# Nazwy pol w BlazeSDK: 'm' + CamelCase. Wymagamy wielkiej litery po 'm',
# zeby nie lapac przypadkowych slow.
MEMBER_RE = re.compile(r"^m[A-Z][A-Za-z0-9_]{1,60}$")

# Tag TDF: 4 znaki, dozwolone A-Z 0-9 i podkreslnik, spacje tylko jako
# wypelnienie na koncu (tagi krotsze niz 4 znaki).
TAG_RE = re.compile(r"^[A-Z0-9_][A-Z0-9_]*[ ]*$")


def valid_tag(tag: str) -> bool:
    return len(tag) == 4 and bool(TAG_RE.match(tag))


# Sekcje, w ktorych leza tablice pol. Poczatkowo skanowalismy tylko .rdata i
# przez to brakowalo calych klas: tablica QosConfigInfo siedzi w .data (@0x141a32d80),
# wiec klasa wygladala na nieistniejaca, choc gra jej uzywa. Zrzut z pamieci ma
# tez wydzielone sekcje metadanych TDF (fieldinf/typeinfo).
DEFAULT_SECTIONS = (".rdata", ".data", "fieldinf", "typeinfo", ".rodata", "_RDATA")


def scan(pe: PE, section_names: tuple[str, ...] = DEFAULT_SECTIONS) -> list[dict]:
    """Przechodzi wskazane sekcje co 8 bajtow szukajac par (tag, nazwa pola)."""
    secs = [s for s in pe.sections if s.name in section_names]
    if not secs:
        raise SystemExit(f"brak sekcji {section_names} w obrazie")

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
            # bajty 4..7 spakowanego qworda - kandydaci na kod typu,
            # rozmiar i offset pola w strukturze
            "meta": [(q0 >> (8 * i)) & 0xFF for i in (4, 5, 6, 7)],
        })
    return out


def group_runs(entries: list[dict], gap: int = 64) -> list[list[dict]]:
    """Dzieli wpisy na ciagle bloki - kandydatow na tablice pojedynczych klas."""
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
                    help="NFS14.exe LUB pelny minidump .dmp (wiecej sekcji z RAM)")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"))
    ap.add_argument("--sections", default=",".join(DEFAULT_SECTIONS),
                    help="ktore sekcje skanowac (po przecinku)")
    args = ap.parse_args()

    if not args.exe.is_file():
        print(f"nie ma takiego pliku: {args.exe}", file=sys.stderr)
        return 1

    # .dmp = obraz z pamieci (ma tez fieldinf/typeinfo); .exe = plik z dysku
    if args.exe.read_bytes()[:4] == b"MDMP":
        from dump_image import load_dump
        pe = load_dump(args.exe)
    else:
        pe = PE(args.exe.read_bytes())
    wanted = tuple(s.strip() for s in args.sections.split(",") if s.strip())
    entries = scan(pe, wanted)
    per_sec = Counter(e["sec"] for e in entries)
    print("rekordow wg sekcji: " +
          ", ".join(f"{k}={v:,}" for k, v in per_sec.most_common()))
    runs = group_runs(entries)

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "tdf_members.json"
    json_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")

    # Slownik tag -> nazwy. Jeden tag moze miec kilka znaczen w roznych
    # klasach, wiec trzymamy zbior.
    by_tag: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        by_tag[e["tag"]].add(e["name"])

    lines = [
        "# Metadane TDF wyciagniete z NFS14.exe",
        "",
        f"- Znalezionych par (tag, pole): **{len(entries):,}**",
        f"- Unikalnych tagow: **{len(by_tag):,}**",
        f"- Ciaglych blokow (kandydaci na klasy): **{len(runs):,}**",
        "",
        "Tag to 24-bitowa wartosc rozpakowywana na 4 znaki po 6 bitow "
        "(0 = spacja). To dokladnie te tagi, ktore leca po drucie.",
        "",
        "## Slownik tag -> pole",
        "",
        "| tag | nazwy pol |",
        "| --- | --- |",
    ]
    for tag in sorted(by_tag):
        names = ", ".join(sorted(by_tag[tag]))
        lines.append(f"| `{tag}` | {names} |")

    lines += ["", "## Bloki w kolejnosci adresow", ""]
    for i, run in enumerate(runs):
        if len(run) < 2:
            continue
        head = run[0]["va"]
        lines.append(f"### blok {i} @ {head:#014x} ({len(run)} pol)")
        lines.append("")
        lines.append("```")
        for e in run:
            meta = " ".join(f"{b:02x}" for b in e["meta"])
            lines.append(f"{e['tag']}  {meta}  {e['name']}")
        lines.append("```")
        lines.append("")

    md_path = args.out / "tdf_members.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"par (tag, pole):     {len(entries):,}")
    print(f"unikalnych tagow:    {len(by_tag):,}")
    print(f"blokow:              {len(runs):,}")
    print(f"-> {json_path}")
    print(f"-> {md_path}")

    # Bajt 'meta[0]' to najlepszy kandydat na kod typu TDF - pokazujemy
    # rozklad, zeby zobaczyc, czy ma malo dyskretnych wartosci.
    print("\nrozklad meta[0] (kandydat na kod typu):")
    for val, n in Counter(e["meta"][0] for e in entries).most_common(16):
        print(f"  {val:#04x}  {n:6,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
