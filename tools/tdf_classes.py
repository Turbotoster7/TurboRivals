"""Klasy TDF z tablic pol - szukanie ukladu pol bez zagladania do binarki.

Granica klasy: rekord pola z meta[1] == 0 to OSTATNIE pole klasy. Ta reguła
tnie 2864 rekordy na 975 klas i zadna z nich nie ma tagow poza kolejnoscia
rosnaca - czyli granice sa dokladne. Wczesniejsza heurystyka ("tag mniejszy od
poprzedniego") dawala 784 klasy, bo SKLEJALA sasiadujace klasy o rosnacych
tagach; tak wlasnie zniknelo QosPingSiteInfo (PSA/PSP/SNA doklejone do klasy
cennika).

Uzycie:
    python tools/tdf_classes.py --tag QOSS        # klasy zawierajace pole QOSS
    python tools/tdf_classes.py --tag PSA,PSP,SNA # klasa z wszystkimi tagami
    python tools/tdf_classes.py --name PingSite   # szukaj po nazwie pola
    python tools/tdf_classes.py --at 0x1416d7ac0  # klasa pod adresem
    python tools/tdf_classes.py --stats
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# meta[0] = kod typu pola. Mapowanie odczytane z klas, ktore juz rozgryzlismy
# (np. ServerInstanceInfo: HOST=5 string, IP=21 int32, PORT=19 uint16).
TYPES = {
    1: "map", 2: "list", 5: "string", 6: "variable", 7: "enum/int",
    9: "union", 10: "struct", 12: "objid", 14: "bool", 19: "uint16",
    20: "uint32", 21: "int32", 22: "uint8?", 23: "int64", 24: "blazeid",
}


def load_classes(members_path: Path) -> list[list[dict]]:
    """Rekordy pol -> lista klas (kazda to lista pol w kolejnosci kodowania)."""
    members = json.loads(members_path.read_text(encoding="utf-8", errors="replace"))
    classes, cur = [], []
    for r in members:
        cur.append(r)
        if r["meta"][1] == 0:          # ostatnie pole klasy
            classes.append(cur)
            cur = []
    if cur:
        classes.append(cur)
    return classes


def fmt_class(cls: list[dict]) -> str:
    lines = [f"--- klasa @{cls[0]['va']:#x} ({len(cls)} pol) ---"]
    for r in cls:
        t = TYPES.get(r["meta"][0], f"typ{r['meta'][0]}")
        lines.append(f"    {r['tag']:<5} {t:<10} {r['name']:<32} meta={r['meta']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--members", type=Path, default=Path("docs/recon/tdf_members.json"))
    ap.add_argument("--tag", help="tag pola; kilka po przecinku = klasa musi miec WSZYSTKIE")
    ap.add_argument("--name", help="fragment nazwy pola (bez rozroznienia wielkosci)")
    ap.add_argument("--at", help="adres tablicy pol, np. 0x1416d7ac0")
    ap.add_argument("--stats", action="store_true", help="podsumowanie segmentacji")
    args = ap.parse_args()

    classes = load_classes(args.members)

    if args.stats:
        total = sum(len(c) for c in classes)
        bad = [c for c in classes if [r["tag"] for r in c] != sorted(r["tag"] for r in c)]
        sizes = sorted(len(c) for c in classes)
        print(f"rekordow pol:            {total:,}")
        print(f"klas (meta[1]==0):       {len(classes):,}")
        print(f"klas z tagami nie-rosnaco: {len(bad)}  (0 = granice poprawne)")
        print(f"najwieksza klasa:        {sizes[-1]} pol")
        print(f"mediana rozmiaru:        {sizes[len(sizes) // 2]} pol")
        return 0

    hits: list[list[dict]] = []
    if args.at:
        va = int(args.at, 0)
        hits = [c for c in classes if any(r["va"] == va for r in c)]
    elif args.tag:
        want = {t.strip().upper() for t in args.tag.split(",")}
        hits = [c for c in classes if want <= {r["tag"].strip().upper() for r in c}]
    elif args.name:
        frag = args.name.lower()
        hits = [c for c in classes if any(frag in r["name"].lower() for r in c)]
    else:
        ap.error("podaj --tag, --name, --at albo --stats")

    if not hits:
        print("brak trafien")
        return 1
    for c in hits:
        print("\n" + fmt_class(c))
    print(f"\n{len(hits)} klas(y)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
