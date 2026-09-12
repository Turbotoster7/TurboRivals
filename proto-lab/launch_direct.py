#!/usr/bin/env python3
"""Bezposrednie uruchomienie NFS14.exe z pominieciem bramki aktywacji EA.

PO CO (Tor B, 2026-09-12): po nacisnieciu "Graj" w Steamie odpala sie
Core/ActivationUI.exe - bramka aktywacji EA. Gdy EA App nie ma swiezego auth code
(w srodowisku startowym gry widac EAAuthCode=NeedsAFreshAuthCode), bramka nie
potrafi zweryfikowac entitlementu i pokazuje okno logowania, a gra nie dochodzi
do menu.

Kluczowa obserwacja z dezasemblacji: NFS14.exe z calego bloku zmiennych EA* ma w
sobie JAKO STRING tylko EALaunchOfflineMode - reszte (EALaunchUserAuthToken,
EALicenseToken, EAAuthCode, EASecureLaunchTokenTemp) konsumuje LAUNCHER, nie sama
gra. To znaczy, ze gra NIE re-waliduje entitlementu po tych zmiennych - robi to
ActivationUI. Jesli wiec ustawimy srodowisko tak, jak zrobilby to launcher, i
odpalimy NFS14.exe bezposrednio (przy dzialajacym EA App dla LSX 127.0.0.1:3216),
gra powinna pominac aktywacje i pojsc prosto do Origin SDK / LSX - a tam nasz hook
0xec3c80 (hook_origin.js) i tak podmienia token.

To jest EKSPERYMENT weryfikujacy hipoteze "gra nie waliduje sama". Jesli gra
mimo to zazada aktywacji - znaczy, ze ActivationUI przekazuje jej stan innym
kanalem (uchwyt/pamiec dzielona/rejestr), nie tylko przez srodowisko.

SEKRETY: EALaunchUserAuthToken (JWT konta), EASecureLaunchTokenTemp, EALaunchCode
sa SESYJNE i wygasaja. NIE hardkodujemy ich w repo. Skrypt czyta je z lokalnego,
gitignorowanego pliku proto-lab/ea_launch_env.txt (szablon: ea_launch_env.example.txt).
Wartosci bierze sie z ZYWEJ sesji EA App - najprosciej ze zrzutu pamieci
ActivationUI/EADesktop (blok srodowiska), albo docelowo z LSX.

Uzycie:
    # 1. skopiuj szablon i wpisz swieze wartosci z zywej sesji EA App
    copy proto-lab\\ea_launch_env.example.txt proto-lab\\ea_launch_env.txt
    # 2. (osobny terminal) odpal serwer i Fride --wait, potem:
    python proto-lab/launch_direct.py
    python proto-lab/launch_direct.py --game-dir "D:\\SteamLibrary\\...\\Need for Speed(TM) Rivals"
    python proto-lab/launch_direct.py --dry-run     # tylko pokaz srodowisko
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Nazwy uznane za sekret - w logu pokazujemy tylko dlugosc, nigdy wartosci.
SECRET_KEYS = {
    "EALaunchUserAuthToken",
    "EASecureLaunchTokenTemp",
    "EALaunchCode",
    "EARtPLaunchCode",
    "EAAuthCode",
}

ENV_FILE = Path(__file__).parent / "ea_launch_env.txt"


def read_env_file(path: Path) -> dict[str, str]:
    """Czyta KEY=VALUE (jedna para na linie, # = komentarz)."""
    if not path.exists():
        sys.exit(
            f"brak pliku {path}\n"
            f"Skopiuj szablon i wpisz swieze wartosci z zywej sesji EA App:\n"
            f"  copy proto-lab\\ea_launch_env.example.txt proto-lab\\ea_launch_env.txt"
        )
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            print(f"[!] pomijam linie bez '=': {line!r}")
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def looks_like_placeholder(env: dict[str, str]) -> list[str]:
    """Zwraca sekrety, ktore wygladaja na niewypelniony szablon (<...>)."""
    bad = []
    for k in SECRET_KEYS:
        v = env.get(k, "")
        if v.startswith("<") and v.endswith(">"):
            bad.append(k)
    return bad


def find_game_dir(cli: str | None) -> Path:
    """Katalog gry: z argumentu, z rejestru (klucz z installScript.vdf), albo blad."""
    if cli:
        d = Path(cli)
        if not (d / "NFS14.exe").exists():
            sys.exit(f"w {d} nie ma NFS14.exe")
        return d
    # Rejestr - ten sam klucz, ktory ustawia instalator Steam (installScript.vdf).
    try:
        import winreg

        for hive, key in (
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\EA Games\Need for Speed(TM) Rivals"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\EA Games\Need for Speed(TM) Rivals"),
        ):
            try:
                with winreg.OpenKey(hive, key) as h:
                    val, _ = winreg.QueryValueEx(h, "Install Dir")
                    d = Path(val)
                    if (d / "NFS14.exe").exists():
                        return d
            except OSError:
                continue
    except ImportError:
        pass
    sys.exit(
        "nie znalazlem katalogu gry w rejestrze - podaj recznie:\n"
        '  python proto-lab/launch_direct.py --game-dir "D:\\SteamLibrary\\'
        'steamapps\\common\\Need for Speed(TM) Rivals"'
    )


def redacted(k: str, v: str) -> str:
    if k in SECRET_KEYS:
        return f"<{len(v)} znakow, ukryte>"
    return v


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--game-dir", help="katalog z NFS14.exe (domyslnie z rejestru)")
    ap.add_argument("--env-file", type=Path, default=ENV_FILE,
                    help=f"plik ze zmiennymi EA* (domyslnie {ENV_FILE.name})")
    ap.add_argument("--dry-run", action="store_true",
                    help="tylko wypisz srodowisko i komende, nie uruchamiaj gry")
    ap.add_argument("--offline", action="store_true",
                    help="wymus EALaunchOfflineMode=true (do porownania - online "
                         "NIE zadziala, ale sprawdza, czy gra w ogole wstaje)")
    args = ap.parse_args()

    ea_env = read_env_file(args.env_file)
    if not ea_env:
        sys.exit(f"{args.env_file} nie zawiera zadnych zmiennych")

    placeholders = looks_like_placeholder(ea_env)
    if placeholders and not args.dry_run:
        sys.exit("te sekrety maja wciaz wartosc-placeholder z szablonu: "
                 + ", ".join(placeholders)
                 + "\nWpisz swieze wartosci z zywej sesji EA App.")

    if args.offline:
        ea_env["EALaunchOfflineMode"] = "true"

    game_dir = find_game_dir(args.game_dir)
    exe = game_dir / "NFS14.exe"

    print(f"katalog gry: {game_dir}")
    print("srodowisko EA* przekazane grze:")
    for k in sorted(ea_env):
        print(f"    {k}={redacted(k, ea_env[k])}")

    # Startujemy od PELNEGO srodowiska tej powloki + nakladamy EA* - gra potrzebuje
    # tez zwyklego PATH/SystemRoot itd., wiec nie budujemy env od zera.
    child_env = dict(os.environ)
    child_env.update(ea_env)

    if args.dry_run:
        print(f"\n[dry-run] uruchomilbym: {exe}  (cwd={game_dir})")
        return 0

    print(f"\nuruchamiam {exe.name} bezposrednio (z pominieciem ActivationUI)...")
    print("PAMIETAJ: EA App ma dzialac (LSX 127.0.0.1:3216 do handshake), a Frida "
          "--wait powinna juz czekac na proces.\n")
    try:
        proc = subprocess.Popen([str(exe)], cwd=str(game_dir), env=child_env)
    except OSError as e:
        sys.exit(f"nie udalo sie uruchomic gry: {e}")
    print(f"gra wystartowala, PID {proc.pid}. Ten skrypt nie czeka na jej koniec.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
