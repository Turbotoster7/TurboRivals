#!/usr/bin/env python3
"""Toggles entries in the hosts file - redirects the EA backend to ourselves.

It modifies a system file, so it:
  - requires administrator rights,
  - makes a backup before the first change,
  - keeps its entries in a marked block, so that `off` removes exactly what
    we added and nothing else.

IMPORTANT: always run `off` once the session is over. A leftover entry breaks
the EA App and other EA games.

Usage (console as administrator):
    python tools/hosts_switch.py status
    python tools/hosts_switch.py on
    python tools/hosts_switch.py on --all --ip 192.168.1.10
    python tools/hosts_switch.py off
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import os
import shutil
import sys
from pathlib import Path

HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"

BEGIN = "# >>> TurboRivals >>>"
END = "# <<< TurboRivals <<<"

# The redirector the game actually uses. Established by observation:
# NFS14.exe connected to 159.153.51.18:42127, and that address is
# gosredirector.ea.com (not ".online.", which has IP 159.153.49.27).
PRIMARY = ["gosredirector.ea.com"]

# The rest of the backend. We only redirect these once we know the client
# actually reaches for them - every unnecessary entry is one more variable
# when diagnosing.
EXTRA = [
    "gosredirector.online.ea.com",
    "gosredirector.stest.ea.com",
    "gosredirector.scert.ea.com",
    "gosca.ea.com",
    "demangler.ea.com",
    "peach.online.ea.com",
]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_hosts() -> list[str]:
    return HOSTS.read_text(encoding="utf-8", errors="replace").splitlines()


def strip_block(lines: list[str]) -> list[str]:
    out, inside = [], False
    for line in lines:
        if line.strip() == BEGIN:
            inside = True
            continue
        if line.strip() == END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return out


def cmd_status(_args) -> int:
    lines = read_hosts()
    inside = False
    found = []
    for line in lines:
        if line.strip() == BEGIN:
            inside = True
            continue
        if line.strip() == END:
            inside = False
            continue
        if inside and line.strip():
            found.append(line.strip())
    if found:
        print(f"TurboRivals block ACTIVE ({len(found)} entries):")
        for f in found:
            print(f"  {f}")
    else:
        print("TurboRivals block absent - hosts is clean")
    return 0


def cmd_on(args) -> int:
    if not is_admin():
        print("administrator rights required", file=sys.stderr)
        return 1

    names = PRIMARY + (EXTRA if args.all else [])
    lines = strip_block(read_hosts())

    backup = HOSTS.with_suffix(f".turborivals-{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
    shutil.copy2(HOSTS, backup)

    block = [BEGIN] + [f"{args.ip}\t{n}" for n in names] + [END]
    HOSTS.write_text("\n".join(lines + block) + "\n", encoding="utf-8")

    print(f"backup: {backup}")
    print(f"redirected {len(names)} hosts to {args.ip}:")
    for n in names:
        print(f"  {n}")
    print("\nremember to run `hosts_switch.py off` once the session is over")
    return 0


def cmd_off(_args) -> int:
    if not is_admin():
        print("administrator rights required", file=sys.stderr)
        return 1
    lines = read_hosts()
    cleaned = strip_block(lines)
    if len(cleaned) == len(lines):
        print("nothing to remove")
        return 0
    HOSTS.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    print("TurboRivals block removed - hosts restored")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(func=cmd_status)
    p = sub.add_parser("on")
    p.add_argument("--ip", default="127.0.0.1")
    p.add_argument("--all", action="store_true",
                   help="also redirect the remaining EA hosts")
    p.set_defaults(func=cmd_on)
    sub.add_parser("off").set_defaults(func=cmd_off)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
