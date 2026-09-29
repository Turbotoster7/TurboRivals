"""TDF classes from field tables - look up a field layout without opening the binary.

Class boundary: a field record with meta[1] == 0 is the LAST field of its class.
This rule splits 2864 records into 975 classes and none of them has tags out of
ascending order - so the boundaries are exact. The earlier heuristic ("tag
smaller than the previous one") gave 784 classes, because it GLUED together
neighbouring classes with ascending tags; that is exactly how QosPingSiteInfo
disappeared (PSA/PSP/SNA got appended to the pricing class).

Usage:
    python tools/tdf_classes.py --tag QOSS        # classes containing field QOSS
    python tools/tdf_classes.py --tag PSA,PSP,SNA # class with all of these tags
    python tools/tdf_classes.py --name PingSite   # search by field name
    python tools/tdf_classes.py --at 0x1416d7ac0  # class at an address
    python tools/tdf_classes.py --stats
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# meta[0] = field type code. Mapping read off classes we have already cracked
# (e.g. ServerInstanceInfo: HOST=5 string, IP=21 int32, PORT=19 uint16).
TYPES = {
    1: "map", 2: "list", 5: "string", 6: "variable", 7: "enum/int",
    9: "union", 10: "struct", 12: "objid", 14: "bool", 19: "uint16",
    20: "uint32", 21: "int32", 22: "uint8?", 23: "int64", 24: "blazeid",
}


def load_classes(members_path: Path) -> list[list[dict]]:
    """Field records -> list of classes (each one a list of fields in encoding order)."""
    members = json.loads(members_path.read_text(encoding="utf-8", errors="replace"))
    classes, cur = [], []
    for r in members:
        cur.append(r)
        if r["meta"][1] == 0:          # last field of the class
            classes.append(cur)
            cur = []
    if cur:
        classes.append(cur)
    return classes


def fmt_class(cls: list[dict]) -> str:
    lines = [f"--- class @{cls[0]['va']:#x} ({len(cls)} fields) ---"]
    for r in cls:
        t = TYPES.get(r["meta"][0], f"type{r['meta'][0]}")
        lines.append(f"    {r['tag']:<5} {t:<10} {r['name']:<32} meta={r['meta']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--members", type=Path, default=Path("docs/recon/tdf_members.json"))
    ap.add_argument("--tag", help="field tag; several comma-separated = class must have ALL of them")
    ap.add_argument("--name", help="fragment of a field name (case-insensitive)")
    ap.add_argument("--at", help="address of a field table, e.g. 0x1416d7ac0")
    ap.add_argument("--stats", action="store_true", help="segmentation summary")
    args = ap.parse_args()

    classes = load_classes(args.members)

    if args.stats:
        total = sum(len(c) for c in classes)
        bad = [c for c in classes if [r["tag"] for r in c] != sorted(r["tag"] for r in c)]
        sizes = sorted(len(c) for c in classes)
        print(f"field records:           {total:,}")
        print(f"classes (meta[1]==0):    {len(classes):,}")
        print(f"classes with non-ascending tags: {len(bad)}  (0 = boundaries correct)")
        print(f"largest class:           {sizes[-1]} fields")
        print(f"median size:             {sizes[len(sizes) // 2]} fields")
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
        ap.error("pass --tag, --name, --at or --stats")

    if not hits:
        print("no matches")
        return 1
    for c in hits:
        print("\n" + fmt_class(c))
    print(f"\n{len(hits)} class(es)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
