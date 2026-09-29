#!/usr/bin/env python3
"""Launching NFS14.exe directly, skipping the EA activation gate.

WHY (Track B, 2026-09-12): after pressing "Play" in Steam, Core/ActivationUI.exe
starts - the EA activation gate. When the EA App has no fresh auth code (the
game's launch environment shows EAAuthCode=NeedsAFreshAuthCode), the gate cannot
verify the entitlement and shows a login window, and the game never reaches the
menu.

Key observation from the disassembly: out of the whole block of EA* variables,
NFS14.exe only contains EALaunchOfflineMode AS A STRING - the rest
(EALaunchUserAuthToken, EALicenseToken, EAAuthCode, EASecureLaunchTokenTemp) is
consumed by the LAUNCHER, not the game itself. That means the game does NOT
re-validate the entitlement from these variables - ActivationUI does. So if we
set up the environment the way the launcher would and start NFS14.exe directly
(with the EA App running for LSX 127.0.0.1:3216), the game should skip activation
and go straight to the Origin SDK / LSX - and there our hook at 0xec3c80
(hook_origin.js) swaps the token anyway.

This is an EXPERIMENT verifying the "the game does not validate by itself"
hypothesis. If the game still asks for activation, it means ActivationUI passes
its state through another channel (handle/shared memory/registry), not only
through the environment.

SECRETS: EALaunchUserAuthToken (account JWT), EASecureLaunchTokenTemp, EALaunchCode
are PER-SESSION and expire. We do NOT hardcode them in the repo. The script reads
them from a local, gitignored file proto-lab/ea_launch_env.txt (template:
ea_launch_env.example.txt). The values come from a LIVE EA App session - easiest
from a memory dump of ActivationUI/EADesktop (the environment block), or
eventually from LSX.

Usage:
    # 1. copy the template and fill in fresh values from a live EA App session
    copy proto-lab\\ea_launch_env.example.txt proto-lab\\ea_launch_env.txt
    # 2. (separate terminal) start the server and Frida --wait, then:
    python proto-lab/launch_direct.py
    python proto-lab/launch_direct.py --game-dir "D:\\SteamLibrary\\...\\Need for Speed(TM) Rivals"
    python proto-lab/launch_direct.py --dry-run     # only show the environment
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Names treated as secrets - the log only shows their length, never the value.
SECRET_KEYS = {
    "EALaunchUserAuthToken",
    "EASecureLaunchTokenTemp",
    "EALaunchCode",
    "EARtPLaunchCode",
    "EAAuthCode",
}

ENV_FILE = Path(__file__).parent / "ea_launch_env.txt"


def read_env_file(path: Path) -> dict[str, str]:
    """Reads KEY=VALUE (one pair per line, # = comment)."""
    if not path.exists():
        sys.exit(
            f"missing file {path}\n"
            f"Copy the template and fill in fresh values from a live EA App session:\n"
            f"  copy proto-lab\\ea_launch_env.example.txt proto-lab\\ea_launch_env.txt"
        )
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            print(f"[!] skipping line without '=': {line!r}")
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def looks_like_placeholder(env: dict[str, str]) -> list[str]:
    """Returns the secrets that look like an unfilled template (<...>)."""
    bad = []
    for k in SECRET_KEYS:
        v = env.get(k, "")
        if v.startswith("<") and v.endswith(">"):
            bad.append(k)
    return bad


def find_game_dir(cli: str | None) -> Path:
    """Game directory: from the argument, from the registry (key from installScript.vdf), or an error."""
    if cli:
        d = Path(cli)
        if not (d / "NFS14.exe").exists():
            sys.exit(f"no NFS14.exe in {d}")
        return d
    # Registry - the same key the Steam installer sets (installScript.vdf).
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
        "game directory not found in the registry - pass it by hand:\n"
        '  python proto-lab/launch_direct.py --game-dir "D:\\SteamLibrary\\'
        'steamapps\\common\\Need for Speed(TM) Rivals"'
    )


def redacted(k: str, v: str) -> str:
    if k in SECRET_KEYS:
        return f"<{len(v)} characters, hidden>"
    return v


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--game-dir", help="directory containing NFS14.exe (default: from the registry)")
    ap.add_argument("--env-file", type=Path, default=ENV_FILE,
                    help=f"file with the EA* variables (default {ENV_FILE.name})")
    ap.add_argument("--dry-run", action="store_true",
                    help="only print the environment and the command, do not start the game")
    ap.add_argument("--offline", action="store_true",
                    help="force EALaunchOfflineMode=true (for comparison - online "
                         "will NOT work, but it checks whether the game starts at all)")
    args = ap.parse_args()

    ea_env = read_env_file(args.env_file)
    if not ea_env:
        sys.exit(f"{args.env_file} contains no variables")

    placeholders = looks_like_placeholder(ea_env)
    if placeholders and not args.dry_run:
        sys.exit("these secrets still have the placeholder value from the template: "
                 + ", ".join(placeholders)
                 + "\nFill in fresh values from a live EA App session.")

    if args.offline:
        ea_env["EALaunchOfflineMode"] = "true"

    game_dir = find_game_dir(args.game_dir)
    exe = game_dir / "NFS14.exe"

    print(f"game directory: {game_dir}")
    print("EA* environment passed to the game:")
    for k in sorted(ea_env):
        print(f"    {k}={redacted(k, ea_env[k])}")

    # We start from the FULL environment of this shell + overlay EA* - the game
    # also needs the usual PATH/SystemRoot etc., so we do not build env from scratch.
    child_env = dict(os.environ)
    child_env.update(ea_env)

    if args.dry_run:
        print(f"\n[dry-run] would start: {exe}  (cwd={game_dir})")
        return 0

    print(f"\nstarting {exe.name} directly (skipping ActivationUI)...")
    print("REMEMBER: the EA App has to be running (LSX 127.0.0.1:3216 for the handshake), "
          "and Frida --wait should already be waiting for the process.\n")
    try:
        proc = subprocess.Popen([str(exe)], cwd=str(game_dir), env=child_env)
    except OSError as e:
        sys.exit(f"failed to start the game: {e}")
    print(f"game started, PID {proc.pid}. This script does not wait for it to exit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
