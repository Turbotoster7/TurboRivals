#!/usr/bin/env python3
"""Launcher Fridy bez CLI - uzywa modulu `frida` (dziala mimo braku frida.exe w PATH).

Podpina skrypt JS do dzialajacego procesu gry i wypisuje jego logi.

Uzycie (gra juz uruchomiona przez EA App):
    python proto-lab/frida_run.py                       # domyslnie hook_origin.js
    python proto-lab/frida_run.py proto-lab/inny.js
    python proto-lab/frida_run.py hook_origin.js --proc NFS14.exe

Albo odwrotnie - najpierw skrypt, potem gra:
    python proto-lab/frida_run.py --wait                # czeka 120 s na start gry
"""

from __future__ import annotations

import argparse
import sys
import time
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


def list_processes():
    """Lista procesow. We Fridzie 17 `frida.enumerate_processes` juz nie istnieje -
    jest na urzadzeniu (get_local_device); starsze wersje maja obie."""
    dev = frida.get_local_device()
    return dev.enumerate_processes()


def find_pid(name: str) -> int | None:
    """PID po pelnej nazwie albo po fragmencie (NFS14 == NFS14.exe)."""
    frag = name.lower().removesuffix(".exe")
    for p in list_processes():
        if p.name.lower() == name.lower() or frag in p.name.lower():
            return p.pid
    return None


def attach(proc: str, wait_seconds: int):
    """Podpina sie do gry; z --wait czeka, az proces wstanie.

    frida.attach(nazwa) rzuca ProcessNotFoundError, gdy gra jeszcze nie dziala -
    lapiemy to i albo czekamy, albo wypisujemy CO widac, zamiast wywalac stos.
    """
    deadline = time.monotonic() + wait_seconds
    announced = False
    while True:
        pid = find_pid(proc)
        if pid is not None:
            print(f"[*] lacze z PID {pid}")
            return frida.attach(pid)
        if time.monotonic() >= deadline:
            break
        if not announced:
            print(f"[*] czekam na start gry (do {wait_seconds} s)... "
                  f"uruchom NFS Rivals")
            announced = True
        time.sleep(1)

    print(f"[!] nie znalazlem procesu '{proc}'. Uruchom gre najpierw, albo odpal "
          f"ten skrypt z --wait i dopiero potem gre.")
    others = [p for p in list_processes()
              if "nfs" in p.name.lower() or "need" in p.name.lower()
              or "origin" in p.name.lower() or "eaapp" in p.name.lower()]
    if others:
        print("    procesy, ktore moga byc powiazane:")
        for p in others:
            print(f"      {p.pid:6}  {p.name}")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script", nargs="?",
                    default=str(Path(__file__).parent / "hook_origin.js"),
                    help="plik .js do wstrzykniecia (domyslnie hook_origin.js)")
    ap.add_argument("--proc", default="NFS14.exe", help="nazwa procesu gry")
    ap.add_argument("--wait", type=int, nargs="?", const=120, default=0,
                    metavar="SEK",
                    help="czekaj az gra wstanie (domyslnie 120 s) zamiast konczyc "
                         "bledem - odpal to PRZED uruchomieniem gry")
    args = ap.parse_args()

    js = Path(args.script).read_text(encoding="utf-8")

    print(f"[*] frida {frida.__version__} - lacze z {args.proc} ...")
    session = attach(args.proc, args.wait)
    if session is None:
        return 1

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
