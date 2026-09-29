"""Summary of the Blaze frame dumps in docs/recon/capture/.

After every session with the game, one command tells whether the sequence got
any further: per session it prints the frame count, the comp/cmd tally and the
order WITHOUT pings (9/2), because ping is a heartbeat every 15 s and clutters
the picture.

    python tools/scan_capture.py                # all sessions
    python tools/scan_capture.py -n 5           # only the last 5
    python tools/scan_capture.py --all-frames   # do not skip pings
"""
from __future__ import annotations

import argparse
import collections
import struct
from pathlib import Path

FIRE2_HDR = 12
PING = (9, 2)

# Names of known commands - so the log reads without looking at the notes.
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
    """(component, command, messageId, file length) or None when it is not a frame."""
    b = path.read_bytes()
    if len(b) < FIRE2_HDR:
        return None
    _size, comp, cmd, _err = struct.unpack_from(">HHHH", b, 0)
    seq = struct.unpack_from(">H", b, 10)[0]
    return comp, cmd, seq, len(b)


def session_of(path: Path) -> str:
    # blaze-<HHMMSS>-<nnn>-<kk>.bin  ->  "<HHMMSS>-<nnn>"; older ones: blaze-first-<...>
    parts = path.stem.split("-")
    return "-".join(parts[1:3]) if len(parts) >= 4 else "-".join(parts[1:])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--dir", type=Path, default=Path("docs/recon/capture"))
    ap.add_argument("-n", "--last", type=int, default=0,
                    help="show only the last N sessions (0 = all)")
    ap.add_argument("--all-frames", action="store_true",
                    help="do not skip pings in the order line")
    args = ap.parse_args()

    files = sorted(args.dir.glob("blaze-*.bin"), key=lambda p: p.stat().st_mtime)
    if not files:
        print(f"no dumps in {args.dir}")
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
        print(f"\n=== session {sess}: {len(frames)} frames "
              f"({pings} pings) ===")
        shown = frames if args.all_frames else [f for f in frames if (f[0], f[1]) != PING]
        for comp, cmd, seq, size in shown:
            name = NAMES.get((comp, cmd), "?")
            print(f"    {comp}/{cmd:<3} #{seq:<5} {size:>4} B   {name}")
        if not args.all_frames and pings:
            print(f"    (+ {pings}x 9/2 ping - skipped)")

    print("\nlegend: '?' = command without a handler / not recognised yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
