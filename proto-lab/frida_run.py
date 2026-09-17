#!/usr/bin/env python3
"""Launcher Fridy bez CLI - uzywa modulu `frida` (dziala mimo braku frida.exe w PATH).

Podpina skrypt JS do dzialajacego procesu gry i wypisuje jego logi.

Uzycie (gra juz uruchomiona przez EA App):
    python proto-lab/frida_run.py                       # domyslnie hook_origin.js
    python proto-lab/frida_run.py proto-lab/inny.js
    python proto-lab/frida_run.py hook_origin.js --proc NFS14.exe

Albo odwrotnie - najpierw skrypt, potem gra:
    python proto-lab/frida_run.py --wait                # czeka 120 s na start gry

Test z restartem gry (np. powrot do sesji po migracji hosta):
    python proto-lab/frida_run.py --wait --follow       # po zamknieciu gry czeka na kolejne
                                                        # uruchomienie i podpina sie znowu
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
    sys.exit("brak modulu frida - uruchom: python -m pip install frida-tools")

# Konsola PowerShella na PL Windows ma stdout w cp1250, a hooki wypisuja surowe
# bufory (XML QoS, payloady TDF) - kazdy bajt spoza cp1250 wywracal watek logow
# Fridy z UnicodeEncodeError i gubil CALA wiadomosc. Zamiana na utf-8 z
# podmiana niedrukowalnych zamiast wyjatku.
# line_buffering=True jest tu ROWNIE wazne jak kodowanie: bez tego Python przy
# przekierowaniu (`| Tee-Object plik`) buforuje stdout blokowo i log przez dlugi
# czas ma tylko baner - wyglada to tak, jakby Frida sie nie podpiela, a w
# rzeczywistosci hooki dzialaly i czekaly na flush. Kosztowalo to przebieg
# 2026-09-12 13:24. Terminator ma to zalatwione flaga -u; tutaj wymuszamy w kodzie,
# zeby polecenie bez -u tez dzialalo.
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


def attach(proc: str, wait_seconds: int, settle: int = 0):
    """Podpina sie do gry; z --wait czeka, az proces wstanie.

    frida.attach(nazwa) rzuca ProcessNotFoundError, gdy gra jeszcze nie dziala -
    lapiemy to i albo czekamy, albo wypisujemy CO widac, zamiast wywalac stos.
    """
    deadline = time.monotonic() + wait_seconds
    announced = False
    while True:
        pid = find_pid(proc)
        if pid is not None:
            if settle:
                print(f"[*] znalazlem PID {pid} - czekam {settle} s, az gra "
                      f"rozpakuje kod")
                time.sleep(settle)
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


def follow(session, js: str, args) -> int:
    """Tryb --follow: podpiecie przezywa restart gry. Po odlaczeniu (gra zamknieta albo
    padla) czekamy na nowy proces i wstrzykujemy skrypt od nowa. Ctrl+C konczy."""
    run = 1
    try:
        while True:
            detached = threading.Event()
            session.on("detached", lambda *a: detached.set())
            script = session.create_script(js)
            script.on("message", on_message)
            script.load()
            print(f"[*] skrypt zaladowany (uruchomienie gry #{run}). Ctrl+C konczy.\n")
            while not detached.wait(1):
                pass
            print(f"\n[*] ===== gra #{run} odlaczona o {time.strftime('%H:%M:%S')} (czas "
                  f"lokalny) - czekam na kolejne uruchomienie =====\n")
            time.sleep(2)            # nie lap jeszcze umierajacego procesu
            session = None
            while session is None:
                try:
                    session = attach(args.proc, 3600, args.settle)
                except Exception as e:  # swiezo startujacy proces potrafi odmowic (VirtualAllocEx)
                    print(f"[!] nie udalo sie podpiac ({e}) - ponawiam za 2 s")
                    time.sleep(2)
            run += 1
    except KeyboardInterrupt:
        return 0


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
    ap.add_argument("--duration", type=int, default=0, metavar="SEK",
                    help="trzymaj podpiecie przez N sekund i wyjdz, zamiast czekac "
                         "na Ctrl+C (do uruchamiania w tle z logiem do pliku)")
    ap.add_argument("--settle", type=int, default=8, metavar="SEK",
                    help="odczekaj N s po znalezieniu procesu, zanim wstrzykniesz "
                         "skrypt - swiezo wystartowana gra ma .text jeszcze "
                         "ZASZYFROWANA i czesc hookow pada z 'unable to intercept "
                         "function'. Domyslnie 8 s (przebieg 2026-09-12: bez tego "
                         "padly OriginRequestTicket, raport bledow i 2 dekodery). "
                         "0 = podpnij natychmiast")
    ap.add_argument("--follow", action="store_true",
                    help="po zamknieciu gry czekaj na kolejne uruchomienie i podepnij sie "
                         "znowu - caly test z restartami gry w jednym logu (testy 53, 54 i 57 "
                         "zlapaly tylko PIERWSZA instancje, a wyrzucalo te po powrocie)")
    args = ap.parse_args()

    js = Path(args.script).read_text(encoding="utf-8")

    print(f"[*] frida {frida.__version__} - lacze z {args.proc} ...")
    session = attach(args.proc, args.wait, args.settle)
    if session is None:
        return 1
    if args.follow:
        return follow(session, js, args)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[*] skrypt zaladowany. Wejdz w grze w ONLINE.\n")

    # Czekamy na logi ze skryptu. sys.stdin.read() konczy sie natychmiast, gdy
    # wejscie nie jest terminalem (uruchomienie w tle) - a isatty() potrafi w
    # takim wypadku sklamac, wiec nie zgadujemy: --duration wprost mowi, ze mamy
    # czekac na czasie.
    try:
        if args.duration:
            print(f"    (trzymam {args.duration} s)")
            end = time.monotonic() + args.duration
            while time.monotonic() < end:
                time.sleep(1)
        else:
            print("    (Ctrl+C konczy)")
            sys.stdin.read()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
