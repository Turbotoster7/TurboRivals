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

TURBORIVALS_HOSTS=<file> points everything here at another file - for tests and for trying
the launcher on a machine whose real hosts file should stay untouched.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import ipaddress
import os
import shutil
import sys
from pathlib import Path

HOSTS = Path(os.environ.get("TURBORIVALS_HOSTS")
             or Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts")

BEGIN = "# >>> TurboRivals >>>"
END = "# <<< TurboRivals <<<"
BACKUP_GLOB = "hosts.turborivals-*.bak"
BACKUPS_KEPT = 5            # every `on` makes one; without a cap they pile up in drivers\etc

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


def read_hosts_text() -> tuple[str, str]:
    """(content, encoding to write it back with). Usually UTF-8; a file saved in a legacy
    codepage (a comment with Polish letters, say) is read as Latin-1, which maps every byte to
    one character and back - decoding it as UTF-8 with replacement would destroy those comments
    on the next write. A UTF-8 BOM is dropped: in front of the first entry it breaks that entry.
    A missing file is an empty one, as it is to Windows (some clean-up tools delete it)."""
    try:
        raw = HOSTS.read_bytes()
    except FileNotFoundError:
        return "", "utf-8"
    try:
        return raw.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1"


def read_hosts() -> list[str]:
    return read_hosts_text()[0].splitlines()


def write_hosts(lines: list[str], encoding: str = "utf-8") -> None:
    """Writes the file in place and reads it back. In place, not replaced: a new file would not
    carry the original's permissions. OSError when the write fails or does not stick."""
    text = "\n".join(lines) + "\n"
    with open(HOSTS, "w", encoding=encoding) as f:
        f.write(text)
    if read_hosts_text()[0].replace("\r\n", "\n") != text:
        raise OSError(f"{HOSTS} did not read back as written - something else holds the file")


def backup() -> Path:
    """A timestamped copy next to the file; only the newest BACKUPS_KEPT are kept."""
    target = HOSTS.with_suffix(f".turborivals-{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
    if HOSTS.exists():
        shutil.copy2(HOSTS, target)
    else:
        target.write_bytes(b"")
    for old in sorted(HOSTS.parent.glob(BACKUP_GLOB))[:-BACKUPS_KEPT]:
        try:
            old.unlink()
        except OSError:
            pass
    return target


def restore(copy: Path) -> bool:
    """Puts a backup back after a failed write - best effort, the caller reports the failure."""
    try:
        shutil.copyfile(copy, HOSTS)
        return True
    except OSError:
        return False


def valid_address(ip: str) -> bool:
    """Only an IPv4 address belongs in front of the redirector names: the game resolves them for
    IPv4 (AF_INET), and a typo here would be written into a system file."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return (isinstance(addr, ipaddress.IPv4Address) and not addr.is_unspecified
            and not addr.is_multicast and addr != ipaddress.IPv4Address("255.255.255.255"))


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

    if not valid_address(args.ip):
        print(f"not an IPv4 address: {args.ip}", file=sys.stderr)
        return 1
    names = PRIMARY + (EXTRA if args.all else [])
    text, encoding = read_hosts_text()
    lines, removed = strip_redirects(text.splitlines())

    copy = backup()
    block = [BEGIN] + [f"{args.ip}\t{n}" for n in names] + [END]
    try:
        write_hosts(lines + block, encoding)
    except OSError as e:
        restore(copy)
        print(f"writing hosts failed: {e}", file=sys.stderr)
        return 1

    print(f"backup: {copy}")
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
    text, encoding = read_hosts_text()
    lines = text.splitlines()
    cleaned, removed = strip_redirects(lines)
    if cleaned == lines:
        print("nothing to remove")
        return 0
    copy = backup()
    if removed:
        print(f"backup: {copy}")
    try:
        write_hosts(cleaned, encoding)
    except OSError as e:
        restore(copy)
        print(f"writing hosts failed: {e}", file=sys.stderr)
        return 1
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
