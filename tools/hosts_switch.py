#!/usr/bin/env python3
"""Toggles entries in the hosts file - redirects the EA backend to ourselves.

It modifies a system file, so it:
  - requires administrator rights,
  - makes a backup before the first change,
  - keeps its entries in a marked block.

Both `on` and `off` also take out any OTHER line that maps the same names -
typically one added by hand (the old readme told players to append one). Such
a line wins over the block: Windows hands back every matching address in file
order and the game takes the first, so a stale `127.0.0.1 gosredirector.ea.com`
above the block sends a joining player's game to itself while the host's log
stays silent.

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
import stat
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


# latin-1 maps every byte to one character and back, so lines we do not touch are written back
# byte for byte - whatever codepage another tool or a hand edit used for them. Reading as UTF-8
# with errors="replace" turned such bytes into U+FFFD for good.
ENCODING = "latin-1"


def read_hosts(path: Path | None = None) -> list[str]:
    """The file's lines; none when there is no hosts file at all. Some Windows installs have none -
    only hosts.ics, which name resolution never reads (a player on 01.10) - and that is the same
    as an empty one: write_hosts creates it."""
    try:
        raw = (path or HOSTS).read_bytes()
    except FileNotFoundError:
        return []
    # Not splitlines(): it also breaks on \x85 and a few control bytes, and 0x85 is the ellipsis in
    # cp1250/cp1252 - a comment holding one would come back as two lines.
    lines = raw.decode(ENCODING).split("\n")
    if lines[-1] == "":
        lines.pop()                                   # the last line ending, not an empty line
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def write_hosts(lines: list[str], path: Path | None = None) -> None:
    """Writes the lines back with the file's own line ending: CRLF unless the file has none
    (Windows ships hosts with CRLF), LF for a file that uses bare LF. A read-only hosts file -
    set by hand or by a "protection" tool - is made writable once; anything else that refuses
    (an antivirus guarding the file) raises PermissionError for the caller to explain."""
    path = path or HOSTS
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = b""
    newline = "\n" if b"\n" in raw and b"\r\n" not in raw else "\r\n"
    data = (newline.join(lines) + newline).encode(ENCODING)
    try:
        path.write_bytes(data)
    except PermissionError:
        if not path.exists() or os.access(path, os.W_OK):
            raise
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)  # clears the read-only attribute
        path.write_bytes(data)


def backup_hosts(path: Path | None = None) -> Path | None:
    """A dated copy next to the file before a change; None when there is no file to copy."""
    path = path or HOSTS
    if not path.exists():
        return None
    backup = path.with_suffix(f".turborivals-{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
    shutil.copy2(path, backup)
    return backup


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


def _mapped_names(line: str) -> tuple[str, list[str]] | None:
    """(address, names) of an active hosts line, None for a comment or a blank."""
    fields = line.split("#", 1)[0].split()
    if len(fields) < 2:
        return None
    return fields[0], fields[1:]


def strip_redirects(lines: list[str],
                    names: list[str] | None = None) -> tuple[list[str], list[str]]:
    """strip_block, plus every line outside the block that maps one of `names`
    (default PRIMARY + EXTRA). A line mapping other names as well keeps those.
    Returns (lines, the removed foreign lines as they were)."""
    wanted = {n.lower() for n in (names or PRIMARY + EXTRA)}
    out, removed = [], []
    for line in strip_block(lines):
        mapped = _mapped_names(line)
        if mapped is None or not wanted & {n.lower() for n in mapped[1]}:
            out.append(line)
            continue
        removed.append(line.strip())
        address, hostnames = mapped
        keep = [n for n in hostnames if n.lower() not in wanted]
        if keep:
            out.append("\t".join([address] + keep))
    return out, removed


def foreign_redirects(lines: list[str], name: str) -> list[str]:
    """Lines outside the block that map `name`."""
    return strip_redirects(lines, [name])[1]


def effective_address(lines: list[str], name: str) -> str | None:
    """The address the first line mapping `name` gives - what the game connects to."""
    for line in lines:
        mapped = _mapped_names(line)
        if mapped and name.lower() in (n.lower() for n in mapped[1]):
            return mapped[0]
    return None


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
        print("TurboRivals block absent")
    foreign = strip_redirects(lines)[1]
    if foreign:
        print(f"\nWARNING - {len(foreign)} other line(s) redirect the same names; the first "
              f"match wins, so these may override the block (`on`/`off` removes them):")
        for f in foreign:
            print(f"  {f}")
    print(f"\n{PRIMARY[0]} -> {effective_address(lines, PRIMARY[0]) or 'real DNS'}")
    return 0


def cmd_on(args) -> int:
    if not is_admin():
        print("administrator rights required", file=sys.stderr)
        return 1

    names = PRIMARY + (EXTRA if args.all else [])
    lines, removed = strip_redirects(read_hosts())

    backup = backup_hosts()

    block = [BEGIN] + [f"{args.ip}\t{n}" for n in names] + [END]
    write_hosts(lines + block)

    print(f"backup: {backup}" if backup else f"no hosts file existed - created {HOSTS}")
    for line in removed:
        print(f"removed an old entry outside the block: {line}")
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
    cleaned, removed = strip_redirects(lines)
    if cleaned == lines:
        print("nothing to remove")
        return 0
    if removed:
        print(f"backup: {backup_hosts()}")
    write_hosts(cleaned)
    for line in removed:
        print(f"removed an old entry outside the block: {line}")
    print("TurboRivals redirect removed - hosts restored")
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
