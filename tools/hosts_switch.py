#!/usr/bin/env python3
"""Przelacznik wpisow w pliku hosts - przekierowanie backendu EA na siebie.

Modyfikuje plik systemowy, wiec:
  - wymaga uprawnien administratora,
  - przed pierwsza zmiana robi kopie zapasowa,
  - wpisy trzyma w oznaczonym bloku, zeby `off` usunelo dokladnie to,
    co dodalismy, i nic wiecej.

WAZNE: po skonczonej sesji zawsze `off`. Zostawiony wpis psuje EA App
i inne gry EA.

Uzycie (konsola jako administrator):
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

# Redirector, ktorego gra faktycznie uzywa. Ustalone obserwacja:
# NFS14.exe laczyl sie z 159.153.51.18:42127, a ten adres to
# gosredirector.ea.com (nie ".online.", ktory ma IP 159.153.49.27).
PRIMARY = ["gosredirector.ea.com"]

# Reszta backendu. Przekierowujemy dopiero wtedy, gdy wiemy, ze klient
# faktycznie sie tam dobija - kazdy zbedny wpis to dodatkowa zmienna
# przy diagnozie.
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
        print(f"blok TurboRivals AKTYWNY ({len(found)} wpisow):")
        for f in found:
            print(f"  {f}")
    else:
        print("blok TurboRivals nieobecny - hosts czysty")
    return 0


def cmd_on(args) -> int:
    if not is_admin():
        print("potrzebne uprawnienia administratora", file=sys.stderr)
        return 1

    names = PRIMARY + (EXTRA if args.all else [])
    lines = strip_block(read_hosts())

    backup = HOSTS.with_suffix(f".turborivals-{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
    shutil.copy2(HOSTS, backup)

    block = [BEGIN] + [f"{args.ip}\t{n}" for n in names] + [END]
    HOSTS.write_text("\n".join(lines + block) + "\n", encoding="utf-8")

    print(f"kopia zapasowa: {backup}")
    print(f"przekierowano {len(names)} hostow na {args.ip}:")
    for n in names:
        print(f"  {n}")
    print("\npamietaj o `hosts_switch.py off` po skonczonej sesji")
    return 0


def cmd_off(_args) -> int:
    if not is_admin():
        print("potrzebne uprawnienia administratora", file=sys.stderr)
        return 1
    lines = read_hosts()
    cleaned = strip_block(lines)
    if len(cleaned) == len(lines):
        print("nie bylo czego usuwac")
        return 0
    HOSTS.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    print("blok TurboRivals usuniety - hosts przywrocony")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(func=cmd_status)
    p = sub.add_parser("on")
    p.add_argument("--ip", default="127.0.0.1")
    p.add_argument("--all", action="store_true",
                   help="przekieruj rowniez pozostale hosty EA")
    p.set_defaults(func=cmd_on)
    sub.add_parser("off").set_defaults(func=cmd_off)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
