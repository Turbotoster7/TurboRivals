"""Shared setup for the tests: imported first by every test module.

Points the launcher at a throw-away folder BEFORE commands.py is imported (it reads these at
import time): TURBORIVALS_HOME for config, certificate, logs and pictures, TURBORIVALS_HOSTS for a
hosts file of our own. The real ones on the machine running the tests are never touched.

Run everything from the repository root:
    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import atexit
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path(tempfile.mkdtemp(prefix="turborivals-test-"))
HOSTS = HOME / "hosts"

os.environ["TURBORIVALS_HOME"] = str(HOME)
os.environ["TURBORIVALS_HOSTS"] = str(HOSTS)
os.environ["LOCALAPPDATA"] = str(HOME / "localappdata")      # no EA App here: ea_identity finds nothing

for sub in ("launcher", "tools", "proto-lab"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)

atexit.register(shutil.rmtree, HOME, True)

SAMPLE_HOSTS = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\n"
    "#\n"
    "# localhost name resolution is handled within DNS itself.\n"
    "#\t127.0.0.1       localhost\n"
    "10.0.0.5\tnas.local\n"
)


def write_hosts(text: str = SAMPLE_HOSTS, encoding: str = "utf-8") -> None:
    HOSTS.chmod(0o644) if HOSTS.exists() else None
    HOSTS.write_bytes(text.encode(encoding))


def ports_free(*ports: tuple[str, int]) -> bool:
    """Free the way the server binds them (tls_terminator._bind_exclusive)."""
    for proto, port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "TCP" else socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            elif proto == "TCP":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
        except OSError:
            return False
        finally:
            s.close()
    return True
