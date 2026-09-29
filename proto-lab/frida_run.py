#!/usr/bin/env python3
"""Frida launcher without the CLI - uses the `frida` module (works even without frida.exe in PATH).

Attaches a JS script to the running game process and prints its logs.

Usage (game already started through the EA App):
    python proto-lab/frida_run.py                       # hook_origin.js by default
    python proto-lab/frida_run.py proto-lab/other.js
    python proto-lab/frida_run.py hook_origin.js --proc NFS14.exe

Or the other way round - script first, then the game:
    python proto-lab/frida_run.py --wait                # waits 120 s for the game to start

Test with a game restart (e.g. returning to a session after host migration):
    python proto-lab/frida_run.py --wait --follow       # after the game closes, waits for the
                                                        # next launch and attaches again
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

try:
    import frida
except ImportError:
    sys.exit("frida module missing - run: python -m pip install frida-tools")

# The PowerShell console on a Polish Windows has stdout in cp1250, and the hooks
# print raw buffers (QoS XML, TDF payloads) - every byte outside cp1250 crashed
# Frida's log thread with UnicodeEncodeError and lost the ENTIRE message. Switch to
# utf-8 and replace unprintable characters instead of raising.
# line_buffering=True is JUST as important here as the encoding: without it, when
# redirected (`| Tee-Object file`), Python block-buffers stdout and for a long time
# the log only has the banner - it looks as if Frida never attached, while in
# reality the hooks were running and waiting for a flush. That cost the run of
# 2026-09-12 13:24. The terminator handles this with the -u flag; here we force it
# in code, so the command works without -u too.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except (AttributeError, OSError, ValueError):
    pass


def on_message(message, data):
    if message.get("type") == "log":
        print(message.get("payload"))
    elif message.get("type") == "error":
        print("[JS ERROR] " + message.get("stack", message.get("description", "?")))
    else:
        print("[msg] " + str(message))


def list_processes():
    """Process list. In Frida 17 `frida.enumerate_processes` no longer exists -
    it lives on the device (get_local_device); older versions have both."""
    dev = frida.get_local_device()
    return dev.enumerate_processes()


def find_pid(name: str) -> int | None:
    """PID by full name or by fragment (NFS14 == NFS14.exe)."""
    frag = name.lower().removesuffix(".exe")
    for p in list_processes():
        if p.name.lower() == name.lower() or frag in p.name.lower():
            return p.pid
    return None


def attach(proc: str, wait_seconds: int, settle: int = 0):
    """Attaches to the game; with --wait it waits until the process is up.

    frida.attach(name) raises ProcessNotFoundError when the game is not running yet -
    we catch it and either wait or print WHAT we can see, instead of dumping a stack trace.
    """
    deadline = time.monotonic() + wait_seconds
    announced = False
    while True:
        pid = find_pid(proc)
        if pid is not None:
            if settle:
                print(f"[*] found PID {pid} - waiting {settle} s for the game "
                      f"to unpack its code")
                time.sleep(settle)
            print(f"[*] attaching to PID {pid}")
            return frida.attach(pid)
        if time.monotonic() >= deadline:
            break
        if not announced:
            print(f"[*] waiting for the game to start (up to {wait_seconds} s)... "
                  f"launch NFS Rivals")
            announced = True
        time.sleep(1)

    print(f"[!] process '{proc}' not found. Start the game first, or run "
          f"this script with --wait and only then the game.")
    others = [p for p in list_processes()
              if "nfs" in p.name.lower() or "need" in p.name.lower()
              or "origin" in p.name.lower() or "eaapp" in p.name.lower()]
    if others:
        print("    processes that may be related:")
        for p in others:
            print(f"      {p.pid:6}  {p.name}")
    return None


def follow(session, js: str, args) -> int:
    """--follow mode: the attachment survives a game restart. After detaching (game closed
    or crashed) we wait for a new process and inject the script again. Ctrl+C quits."""
    run = 1
    try:
        while True:
            detached = threading.Event()
            session.on("detached", lambda *a: detached.set())
            script = session.create_script(js)
            script.on("message", on_message)
            script.load()
            print(f"[*] script loaded (game launch #{run}). Ctrl+C quits.\n")
            while not detached.wait(1):
                pass
            print(f"\n[*] ===== game #{run} detached at {time.strftime('%H:%M:%S')} (local "
                  f"time) - waiting for the next launch =====\n")
            time.sleep(2)            # don't catch the dying process yet
            session = None
            while session is None:
                try:
                    session = attach(args.proc, 3600, args.settle)
                except Exception as e:  # a freshly starting process can refuse (VirtualAllocEx)
                    print(f"[!] failed to attach ({e}) - retrying in 2 s")
                    time.sleep(2)
            run += 1
    except KeyboardInterrupt:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script", nargs="?",
                    default=str(Path(__file__).parent / "hook_origin.js"),
                    help=".js file to inject (default hook_origin.js)")
    ap.add_argument("--proc", default="NFS14.exe", help="game process name")
    ap.add_argument("--wait", type=int, nargs="?", const=120, default=0,
                    metavar="SEC",
                    help="wait until the game is up (default 120 s) instead of failing "
                         "with an error - run this BEFORE starting the game")
    ap.add_argument("--duration", type=int, default=0, metavar="SEC",
                    help="stay attached for N seconds and exit, instead of waiting "
                         "for Ctrl+C (for running in the background with a log file)")
    ap.add_argument("--settle", type=int, default=8, metavar="SEC",
                    help="wait N s after finding the process before injecting "
                         "the script - a freshly started game still has .text "
                         "ENCRYPTED and some hooks fail with 'unable to intercept "
                         "function'. Default 8 s (run of 2026-09-12: without it "
                         "OriginRequestTicket, the error report and 2 decoders failed). "
                         "0 = attach immediately")
    ap.add_argument("--follow", action="store_true",
                    help="after the game closes, wait for the next launch and attach "
                         "again - the whole test with game restarts in one log (tests 53, 54 "
                         "and 57 only caught the FIRST instance, while the kick happened after returning)")
    args = ap.parse_args()

    js = Path(args.script).read_text(encoding="utf-8")

    print(f"[*] frida {frida.__version__} - attaching to {args.proc} ...")
    session = attach(args.proc, args.wait, args.settle)
    if session is None:
        return 1
    if args.follow:
        return follow(session, js, args)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[*] script loaded. Go ONLINE in the game.\n")

    # We wait for logs from the script. sys.stdin.read() returns immediately when
    # stdin is not a terminal (running in the background) - and isatty() can lie
    # in that case, so we do not guess: --duration says outright that we should
    # wait on a timer.
    try:
        if args.duration:
            print(f"    (holding for {args.duration} s)")
            end = time.monotonic() + args.duration
            while time.monotonic() < end:
                time.sleep(1)
        else:
            print("    (Ctrl+C quits)")
            sys.stdin.read()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
