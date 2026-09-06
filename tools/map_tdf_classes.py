#!/usr/bin/env python3
"""Mapowanie klas TDF na ich tablice pol.

UWAGA: na binarce ze Steama to narzedzie nie zadziala - sekcja .text jest
zaszyfrowana (entropia 1.000), wiec skan instrukcji zwraca szum. Zostawione
na pozniej: bedzie uzyteczne na zrzucie pamieci procesu po odszyfrowaniu
kodu. Szczegoly w docs/decisions.md.

Tablice pol i nazwy klas nie maja w binarce referencji absolutnych - kod
x64 adresuje je RIP-relatywnie. Zamiast pelnego disassemblera skanujemy
tylko instrukcje `lea r64, [rip+disp32]` (48/4C 8D /r), bo wlasnie nimi
kod laduje adresy statycznych tablic.

Metoda:
  1. znajdz wszystkie `lea` i policz ich cele,
  2. cele lezace w zbiorze rekordow pol = poczatki tablic klas
     (to rozwiazuje problem sklejonych blokow - granice biora sie z kodu,
      nie ze zgadywania odstepow),
  3. nazwe klasy bierz z pobliskiego `lea` na string "Blaze::...".

Uzycie:
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

# lea r64, [rip+disp32] -- REX.W (48) lub REX.WR (4C), opcode 8D,
# modrm z mod=00 i rm=101 (RIP-relative): 05,0D,15,1D,25,2D,35,3D
LEA_RE = re.compile(rb"[\x48\x4C]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]", re.DOTALL)
LEA_LEN = 7

CLASS_NAME_RE = re.compile(r"^Blaze::[A-Za-z0-9_]+::[A-Za-z0-9_]+$")


def find_lea_refs(pe: PE) -> list[tuple[int, int]]:
    """Zwraca (offset_instrukcji, docelowy_VA) dla kazdego lea rip-relative."""
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
        # adres liczony od nastepnej instrukcji
        target = base_va + i + LEA_LEN + disp
        refs.append((lo + i, target))
    return refs


def find_class_names(pe: PE) -> dict[int, str]:
    """VA -> nazwa klasy dla stringow postaci Blaze::Component::Type."""
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
    ap.add_argument("exe", type=Path)
    ap.add_argument("--members", type=Path, default=Path("docs/recon/tdf_members.json"))
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"))
    ap.add_argument("--window", type=int, default=256,
                    help="ile bajtow kodu wokol lea szukac pary nazwa/tablica")
    args = ap.parse_args()

    pe = PE(args.exe.read_bytes())
    members: list[dict] = json.loads(args.members.read_text(encoding="utf-8"))
    members.sort(key=lambda e: e["va"])
    member_vas = {e["va"] for e in members}
    member_va_list = [e["va"] for e in members]

    class_names = find_class_names(pe)
    refs = find_lea_refs(pe)
    print(f"lea rip-relative:     {len(refs):,}")
    print(f"nazwy klas Blaze:     {len(class_names):,}")

    # Cele lea, ktore trafiaja dokladnie w rekord pola = poczatki tablic.
    array_starts = sorted({t for _, t in refs if t in member_vas})
    print(f"poczatki tablic pol:  {len(array_starts):,}")

    # Indeks: offset kodu -> cel, posortowany, zeby szukac sasiedztwa.
    refs.sort()
    ref_offsets = [o for o, _ in refs]

    # Dla kazdego lea na nazwe klasy szukamy w poblizu lea na tablice pol.
    pairs: dict[int, str] = {}          # array_start -> class name
    conflicts: dict[int, set[str]] = defaultdict(set)
    for off, target in refs:
        name = class_names.get(target)
        if name is None:
            continue
        lo = bisect.bisect_left(ref_offsets, off - args.window)
        hi = bisect.bisect_right(ref_offsets, off + args.window)
        best: tuple[int, int] | None = None      # (dystans, array_start)
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

    print(f"sparowanych klas:     {len(pairs):,}")
    if conflicts:
        print(f"kolizji (kilka nazw na jedna tablice): {len(conflicts):,}")

    # Kazda tablica ciagnie sie do nastepnego poczatku tablicy.
    boundaries = sorted(set(array_starts) | set(pairs))
    lines = [
        "# Klasy TDF i ich pola (rekonstrukcja z NFS14.exe)",
        "",
        f"- Rekordow pol: **{len(members):,}**",
        f"- Wykrytych tablic (granice z instrukcji `lea` w kodzie): **{len(boundaries):,}**",
        f"- Nazwanych klas: **{len(pairs):,}**",
        "",
        "Kolejnosc pol jest kolejnoscia z tablicy, czyli kolejnoscia kodowania "
        "w TDF. `meta` to 4 bajty metadanych rekordu (kandydaci: kod typu, "
        "offset pola w strukturze, rozmiar).",
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
        title = name or f"(nienazwana tablica @ {start:#014x})"
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"`{start:#014x}` - {len(fields)} pol")
        lines.append("")
        lines.append("| tag | pole | meta |")
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

    print(f"nazwanych tablic w raporcie: {named:,}")
    print(f"-> {out_md}")
    print(f"-> {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
