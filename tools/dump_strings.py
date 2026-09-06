#!/usr/bin/env python3
"""Faza 0 - ekstrakcja stringow z binarki NFS Rivals.

Blaze/DirtySDK sa wlinkowane statycznie w NFS14.exe, wiec binarka zawiera
tablice stringow klienta: nazwy hostow backendu, nazwy komend, wersje SDK.
To nasze pierwsze zrodlo prawdy o protokole - serwery EA sa martwe od
2025-10-07 i nie da sie juz nagrac ruchu serwer->klient.

Uzycie:
    python tools/dump_strings.py "D:\\...\\NFS14.exe"
    python tools/dump_strings.py "...\\NFS14.exe" --all      # + pelny zrzut
    python tools/dump_strings.py "...\\NFS14.exe" --tags     # + kandydaci na tagi TDF
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MIN_LEN = 4

# Kategorie sa uporzadkowane wg waznosci dla fazy 0. Kazdy string trafia
# do pierwszej pasujacej kategorii, zeby raport nie powtarzal tego samego.
CATEGORIES: list[tuple[str, str, str]] = [
    (
        "hosts",
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
        r"(?:ea|easports|eamobile|origin|dice|nfs)\.com",
        "Hostnamy backendu EA - najwazniejszy wynik. Tu szukamy redirectora.",
    ),
    (
        "urls",
        r"https?://[^\s\"'<>]{4,}",
        "Pelne URL-e - endpointy HTTPS do zaslepienia (config, telemetria, QoS).",
    ),
    (
        "blaze",
        r"(?i)blaze",
        "Wszystko co dotyka BlazeSDK - nazwy komponentow, stany polaczenia, bledy.",
    ),
    (
        "dirtysdk",
        r"(?i)protossl|dirtysock|dirtysdk|netconn|protohttp|protoupnp|protoadvt"
        r"|protossl|protostream|netgame|commudp|protomangle",
        "DirtySDK - warstwa sieciowa EA. Wersja ProtoSSL decyduje o tym, czy "
        "zadziala sztuczka z podrobionym certyfikatem.",
    ),
    (
        "components",
        r"(?i)preauth|postauth|usersession|gamemanager|matchmak|associationlist"
        r"|gamereport|playgroup|censusdata|clientmetrics|redirector|util(?:comp)?"
        r"|authentication|messaging|leaderboard|telemetry",
        "Nazwy komponentow i komend Blaze - mapa RPC, ktore musimy obsluzyc.",
    ),
    (
        "auth",
        r"(?i)nucleus|persona|entitlement|authtoken|logintoken|handoff"
        r"|\borigin\b|accesstoken|sessionkey",
        "Warstwa logowania - jak klient dostaje token z EA App i co z nim robi.",
    ),
    (
        "netcode",
        r"(?i)\bnat\b|upnp|qos\b|latency|ping\b|peer\b|topology|mesh\b|hostmigrat"
        r"|alldrive|multiplayer|session",
        "Rozgrywka P2P - topologia, NAT, AllDrive. Wazne dla fazy 2 i 5.",
    ),
    (
        "versions",
        r"(?i)\bver(?:sion)?\s*[:=]|\bsdk\b|\bbuild\b\s*[:=]|\d+\.\d+\.\d+\.\d+",
        "Wersje SDK i buildu - pozwalaja dopasowac nasz emulator do wlasciwej ery Blaze.",
    ),
]

# Kandydaci na tagi TDF: 4 znaki [A-Z0-9], czesto wystepuja seriami.
TDF_TAG_RE = re.compile(r"^[A-Z][A-Z0-9]{3}$")

ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass(frozen=True)
class Found:
    offset: int
    encoding: str
    text: str


def extract(data: bytes) -> list[Found]:
    """Wyciaga stringi ASCII i UTF-16LE razem z offsetem w pliku.

    Offset przyda sie pozniej w Ghidrze - pozwala znalezc kod, ktory
    danego stringa uzywa.
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
    """Zostawia pierwsze wystapienie kazdego unikalnego tekstu."""
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
        f"# Zrzut stringow: {exe.name}",
        "",
        f"- Plik: `{exe}`",
        f"- Rozmiar: {exe.stat().st_size:,} B",
        f"- Znalezionych stringow (>= {MIN_LEN} znakow): {len(found):,}",
        "",
        "Offsety sa pozycjami w pliku (nie RVA) - do uzycia w hex edytorze.",
        "",
    ]
    for name, _, desc in CATEGORIES:
        items = dedupe(buckets[name])
        lines += [f"## {name} ({len(items)})", "", f"_{desc}_", ""]
        if not items:
            lines += ["(brak trafien)", ""]
            continue
        lines.append("```")
        for f in items:
            lines.append(f"{f.offset:#010x}  {f.encoding:5}  {f.text}")
        lines += ["```", ""]

    if tags is not None:
        lines += [
            f"## kandydaci na tagi TDF ({len(tags)})",
            "",
            "_4-znakowe stringi [A-Z][A-Z0-9]{3}. Duzo falszywych trafien, ale "
            "prawdziwe tagi TDF wygladaja wlasnie tak._",
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
    ap.add_argument("exe", type=Path, help="sciezka do NFS14.exe")
    ap.add_argument("-o", "--out", type=Path, default=Path("docs/recon"),
                    help="katalog wynikowy (domyslnie docs/recon)")
    ap.add_argument("--all", action="store_true",
                    help="zapisz rowniez pelny zrzut wszystkich stringow")
    ap.add_argument("--tags", action="store_true",
                    help="dodaj sekcje z kandydatami na tagi TDF")
    args = ap.parse_args()

    if not args.exe.is_file():
        print(f"nie ma takiego pliku: {args.exe}", file=sys.stderr)
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
    print(f"raport -> {report_path}")

    if args.all:
        all_path = args.out / f"strings_{stem}_all.txt"
        with all_path.open("w", encoding="utf-8") as fh:
            for f in found:
                fh.write(f"{f.offset:#010x}\t{f.encoding}\t{f.text}\n")
        print(f"pelny zrzut -> {all_path}")

    print()
    for name, _, _ in CATEGORIES:
        print(f"  {name:12} {len(dedupe(buckets[name])):6,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
