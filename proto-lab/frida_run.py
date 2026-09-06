#!/usr/bin/env python3
"""Launcher Fridy bez CLI - uzywa modulu `frida` (dziala mimo braku frida.exe w PATH).

Podpina skrypt JS do dzialajacego procesu gry i wypisuje jego logi.

Uzycie (gra juz uruchomiona przez EA App):
    python proto-lab/frida_run.py                       # domyslnie hook_origin.js
    python proto-lab/frida_run.py proto-lab/inny.js
    python proto-lab/frida_run.py hook_origin.js --proc NFS14.exe
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import frida
except ImportError:
    sys.exit("brak modulu frida - uruchom: python -m pip install frida-tools")


def on_message(message, data):
    if message.get("type") == "log":
        print(message.get("payload"))
    elif message.get("type") == "error":
        print("[JS ERROR] " + message.get("stack", message.get("description", "?")))
    else:
        print("[msg] " + str(message))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script", nargs="?",
                    default=str(Path(__file__).parent / "hook_origin.js"),
                    help="plik .js do wstrzykniecia (domyslnie hook_origin.js)")
    ap.add_argument("--proc", default="NFS14.exe", help="nazwa procesu gry")
    args = ap.parse_args()

    js = Path(args.script).read_text(encoding="utf-8")

    print(f"[*] frida {frida.__version__} - lacze z {args.proc} ...")
    try:
        session = frida.attach(args.proc)
    except frida.ProcessNotFoundError:
        # sprobuj po fragmencie nazwy
        procs = [p for p in frida.enumerate_processes()
                 if args.proc.lower().rstrip(".exe") in p.name.lower()]
        if not procs:
            print("[!] nie znalazlem procesu gry. Czy NFS14 dziala? Procesy 'NFS':")
            for p in frida.enumerate_processes():
                if "nfs" in p.name.lower() or "need" in p.name.lower():
                    print(f"      {p.pid:6}  {p.name}")
            return 1
        print(f"[*] lacze z PID {procs[0].pid} ({procs[0].name})")
        session = frida.attach(procs[0].pid)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[*] skrypt zaladowany. Wejdz w grze w ONLINE. Ctrl+C konczy.\n")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
