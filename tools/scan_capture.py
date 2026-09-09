"""Podsumowanie zrzutow ramek Blaze z docs/recon/capture/.

Po kazdej sesji z gra jedno polecenie mowi, czy sekwencja posunela sie dalej:
wypisuje per sesja liczbe ramek, licznik comp/cmd i kolejnosc BEZ pingow (9/2),
bo ping to heartbeat co 15 s i zaslania obraz.

    python tools/scan_capture.py                # wszystkie sesje
    python tools/scan_capture.py -n 5           # tylko 5 ostatnich
    python tools/scan_capture.py --all-frames   # nie pomijaj pingow
"""
from __future__ import annotations

import argparse
import collections
import struct
from pathlib import Path

FIRE2_HDR = 12
PING = (9, 2)

# Nazwy poznanych komend - zeby log czytalo sie bez zagladania do notatek.
NAMES = {
    (5, 1): "Redirector.getServerInstance",
    (9, 1): "Util.fetchClientConfig",
    (9, 2): "Util.ping",
    (9, 5): "Util.getTelemetryServer",
    (9, 7): "Util.preAuth",
    (9, 8): "Util.postAuth",
    (9, 0xB): "Util.userSettingsSave",
    (9, 0xC): "Util.userSettingsLoadAll",
    (1, 152): "Authentication.login",
}


def read_frame(path: Path) -> tuple[int, int, int, int] | None:
    """(component, command, messageId, dlugosc pliku) albo None gdy to nie ramka."""
    b = path.read_bytes()
    if len(b) < FIRE2_HDR:
        return None
    _size, comp, cmd, _err = struct.unpack_from(">HHHH", b, 0)
    seq = struct.unpack_from(">H", b, 10)[0]
    return comp, cmd, seq, len(b)


def session_of(path: Path) -> str:
    # blaze-<HHMMSS>-<nnn>-<kk>.bin  ->  "<HHMMSS>-<nnn>"; starsze: blaze-first-<...>
    parts = path.stem.split("-")
    return "-".join(parts[1:3]) if len(parts) >= 4 else "-".join(parts[1:])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--dir", type=Path, default=Path("docs/recon/capture"))
    ap.add_argument("-n", "--last", type=int, default=0,
                    help="pokaz tylko N ostatnich sesji (0 = wszystkie)")
    ap.add_argument("--all-frames", action="store_true",
                    help="nie pomijaj pingow w linii kolejnosci")
    args = ap.parse_args()

    files = sorted(args.dir.glob("blaze-*.bin"), key=lambda p: p.stat().st_mtime)
    if not files:
        print(f"brak zrzutow w {args.dir}")
        return 1

    sessions: dict[str, list] = collections.OrderedDict()
    for f in files:
        fr = read_frame(f)
        if fr is not None:
            sessions.setdefault(session_of(f), []).append(fr)

    items = list(sessions.items())
    if args.last:
        items = items[-args.last:]

    for sess, frames in items:
        counts = collections.Counter((c, d) for c, d, _, _ in frames)
        pings = counts.get(PING, 0)
        print(f"\n=== sesja {sess}: {len(frames)} ramek "
              f"({pings} pingow) ===")
        shown = frames if args.all_frames else [f for f in frames if (f[0], f[1]) != PING]
        for comp, cmd, seq, size in shown:
            name = NAMES.get((comp, cmd), "?")
            print(f"    {comp}/{cmd:<3} #{seq:<5} {size:>4} B   {name}")
        if not args.all_frames and pings:
            print(f"    (+ {pings}x 9/2 ping - pominiete)")

    print("\nlegenda: '?' = komenda bez handlera / jeszcze nierozpoznana")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
