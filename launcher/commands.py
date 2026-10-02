"""TurboRivals - launcher logic.

The UI (web/) never touches the system directly. Everything that needs
privileges, processes or files lives here; app.py only exposes it to
JavaScript.

Scope (phase 3 in the readme): hosts, firewall rules and player names
without a console.

Nothing in here may raise into the UI for an expected failure (a tool that is
missing, a file that is locked, a host that does not answer): every function
returns a dict with "ok" and an "error" a player can act on.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import errno
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LAUNCHER_DIR = Path(__file__).resolve().parent
IS_WINDOWS = os.name == "nt"

# Frozen (PyInstaller) vs running from the repo. The two differ in one way that
# matters: PyInstaller unpacks the bundle into a temp directory it wipes on
# exit, so ROOT is readable but NOT a place to keep anything.
FROZEN = getattr(sys, "frozen", False)

# %LOCALAPPDATA%\TurboRivals: the player's picture, save backups and server logs, whether the
# launcher runs frozen or from the repo (run from the repo, DATA_DIR is the repository itself).
USER_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "TurboRivals"

if os.environ.get("TURBORIVALS_HOME"):
    # Everything the launcher writes in one separate folder - tests (the installer's smoke test
    # runs the packaged launcher this way), and a second setup next to the real one.
    USER_DIR = DATA_DIR = Path(os.environ["TURBORIVALS_HOME"])
    ROOT = Path(sys._MEIPASS) if FROZEN else LAUNCHER_DIR.parent
    CONFIG_PATH = DATA_DIR / "config.json"
    PKI_DIR = DATA_DIR / "pki"
    CAPTURE_DIR = DATA_DIR / "capture"
elif FROZEN:
    ROOT = Path(sys._MEIPASS)                    # bundled, read-only, temporary
    DATA_DIR = USER_DIR
    CONFIG_PATH = DATA_DIR / "config.json"
    PKI_DIR = DATA_DIR / "pki"
    CAPTURE_DIR = DATA_DIR / "capture"
else:
    ROOT = LAUNCHER_DIR.parent                   # repository root
    DATA_DIR = ROOT
    CONFIG_PATH = LAUNCHER_DIR / "config.json"
    PKI_DIR = ROOT / "proto-lab" / "pki"
    CAPTURE_DIR = ROOT / "docs" / "recon" / "capture"

try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass


def _load_sibling(name: str, folder: str):
    """Imports a module that is a plain file in the repo but a bundled module
    in the frozen exe."""
    try:
        return __import__(name)
    except ImportError:
        sys.path.insert(0, str(ROOT / folder))
        return __import__(name)


# The hosts file goes through tools/hosts_switch.py so that the launcher and
# the console share EXACTLY the same marker block - otherwise one would wipe
# the other's entries.
hosts_switch = _load_sibling("hosts_switch", "tools")

# Which career save this machine's game loads - the server uses the same module for the host.
ea_identity = _load_sibling("ea_identity", "proto-lab")

HOSTS = hosts_switch.HOSTS
BEGIN, END = hosts_switch.BEGIN, hosts_switch.END
REDIRECTOR = hosts_switch.PRIMARY[0]             # gosredirector.ea.com


def _read_version() -> str:
    """The one place the version lives: the VERSION file at the repository root.

    The spec ships it as bundled data, the Inno script reads the same file, and
    the window shows what this returns - so a release cannot end up stamped
    three different ways.
    """
    try:
        return (ROOT / "VERSION").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


APP_VERSION = _read_version()

MAX_GUESTS = 5          # host + 5 guests = 6 slots (MaxClientCount in NFS14.exe)
STEAM_APP_ID = "1262600"
NAME_MAX = 32           # the server cuts a reported nickname to this (tls_terminator.NAME_MAX)

# Ports from the readme. The host needs all of them, a joining player only P2P.
FIREWALL_RULES = {
    "host": [
        ("TurboRivals", "TCP", "42127,14219,17502"),
        ("TurboRivals QoS", "UDP", "17502-17503"),
        ("NFS Rivals P2P", "UDP", "3659"),
    ],
    "client": [
        ("NFS Rivals P2P", "UDP", "3659"),
    ],
}

# What the server binds (tls_terminator.main): it refuses to start when any of these is taken.
SERVER_PORTS = (
    ("TCP", 42127, "redirector"),
    ("TCP", 14219, "Blaze"),
    ("TCP", 17502, "QoS HTTP + launchers"),
    ("UDP", 17502, "QoS probes"),
    ("UDP", 17503, "QoS probes"),
)

NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW


def _run(args: list[str], timeout: float = 10, **kwargs) -> subprocess.CompletedProcess | None:
    """subprocess.run for the Windows console tools (tasklist, netsh, ipconfig, netstat):
    bytes out, and None instead of an exception when the tool is missing or hangs."""
    try:
        return subprocess.run(args, capture_output=True, creationflags=NO_WINDOW,
                              timeout=timeout, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return None


def _console_text(raw: bytes | None) -> str:
    """Console tool output. 'oem' is the console codepage - only the localised prose needs it,
    the names and numbers are ASCII either way. It exists on Windows only."""
    raw = raw or b""
    for encoding in ("oem", "utf-8"):
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            continue
    return raw.decode("latin-1")


def _redact(text: str) -> str:
    """A path as it may appear in a screenshot or a bug report: without the Windows user name."""
    home = str(Path.home())
    if home and home not in ("/", "\\"):
        text = text.replace(home, "%USERPROFILE%" if IS_WINDOWS else "~")
    return text


# =======================================================================================
#                               SYSTEM
# =======================================================================================

def is_admin() -> bool:
    if IS_WINDOWS:
        return hosts_switch.is_admin()
    return hasattr(os, "geteuid") and os.geteuid() == 0


WATCHED_PROCESSES = {"ea_app": "EADesktop.exe", "game": "NFS14.exe"}


def parse_tasklist(text: str) -> dict[int, str]:
    """`tasklist /FO CSV /NH` -> {pid: image name}."""
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].strip().isdigit():
            out[int(row[1])] = row[0].strip()
    return out


def _processes_toolhelp() -> dict[int, str] | None:
    """{pid: image name} straight from Windows (CreateToolhelp32Snapshot) - a few milliseconds,
    where starting tasklist.exe costs a process and a console host every few seconds."""
    try:
        import ctypes
        from ctypes import wintypes

        class ProcessEntry(ctypes.Structure):          # PROCESSENTRY32W
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)         # TH32CS_SNAPPROCESS
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:    # INVALID_HANDLE_VALUE
            return None
        try:
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(ProcessEntry)
            found = {}
            more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while more:
                found[int(entry.th32ProcessID)] = entry.szExeFile
                more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            return found or None
        finally:
            kernel32.CloseHandle(snapshot)
    except Exception:                            # noqa: BLE001 - tasklist is the fallback
        return None


def _processes_tasklist() -> dict[int, str] | None:
    result = _run(["tasklist", "/FO", "CSV", "/NH"])
    if result is None or result.returncode != 0:
        return None
    return parse_tasklist(_console_text(result.stdout))


def running_processes() -> dict[int, str] | None:
    """Every process as {pid: image name}; None when there is no way to tell (not Windows)."""
    if not IS_WINDOWS:
        return None
    return _processes_toolhelp() or _processes_tasklist()


def process_status(processes: dict[int, str] | None = None) -> dict:
    """Is the EA App up, is the game running - one look at the process list for both.

    The EA App is worth its own check because it is the most common reason a
    session fails, and the failure is silent: without the EA App the game never
    receives an Origin token, so it connects, exchanges Util.preAuth and
    Util.ping, then closes without ever sending Authentication.login (1/152).
    The server now says so in its log ([hint]), but only after the fact.
    """
    procs = running_processes() if processes is None else processes
    names = {name.lower() for name in (procs or {}).values()}
    return {"known": procs is not None,
            **{key: image.lower() in names for key, image in WATCHED_PROCESSES.items()}}


def ea_app_running() -> bool:
    return process_status()["ea_app"]


def relaunch_as_admin() -> bool:
    """Starts this same launcher elevated (UAC prompt).

    Frozen, sys.executable is the launcher itself and takes no script argument.
    """
    if not IS_WINDOWS:
        return False
    import ctypes

    params = "" if FROZEN else f'"{LAUNCHER_DIR / "app.py"}"'
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(LAUNCHER_DIR), 1)
    return rc > 32


def windows_version() -> str:
    if not IS_WINDOWS:
        return platform.platform()
    build = sys.getwindowsversion().build
    release = platform.release()
    if release == "10" and build >= 22000:      # platform says "10" on Windows 11 too
        release = "11"
    return f"Windows {release} (build {build})"


def open_folder(path: Path, create: bool = True) -> dict:
    """Shows a folder in Explorer (or the desktop's file manager). create=False for a folder
    that is not the launcher's own - the game's save folder is the game's to make."""
    if not create and not path.is_dir():
        return {"ok": False, "error": f"{_redact(str(path))} does not exist yet"}
    try:
        path.mkdir(parents=True, exist_ok=True)
        if IS_WINDOWS:
            os.startfile(str(path))
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except OSError as e:
        return {"ok": False, "error": f"could not open {_redact(str(path))}: {e}"}
    return {"ok": True, "path": _redact(str(path))}


PROJECT_URL = "https://github.com/Turbotoster7/TurboRivals"


def open_url(url: str) -> dict:
    """The project's pages only (readme, issues, discussions) - not a general link opener."""
    if not (url == PROJECT_URL or url.startswith(PROJECT_URL + "/")
            or url.startswith(PROJECT_URL + "#")):
        return {"ok": False, "error": "not a TurboRivals link"}
    try:
        webbrowser.open(url)
    except Exception as e:                       # noqa: BLE001 - no browser is not our crash
        return {"ok": False, "error": str(e)}
    return {"ok": True}


# =======================================================================================
#                               HOSTS / DNS
# =======================================================================================

valid_ipv4 = hosts_switch.valid_address


def flush_dns() -> bool:
    result = _run(["ipconfig", "/flushdns"])
    return result is not None and result.returncode == 0


def can_edit_hosts() -> bool:
    """Windows guards the hosts file with its ACL, which os.access does not read - there only
    administrator rights tell. Elsewhere (and with TURBORIVALS_HOSTS) the file's own mode does."""
    if IS_WINDOWS and HOSTS == hosts_switch.DEFAULT_HOSTS:
        return is_admin()
    return os.access(HOSTS if HOSTS.exists() else HOSTS.parent, os.W_OK)


def hosts_status() -> dict:
    """What the launcher wrote into hosts: whether the block is on, and where it points.

    effective_ip is where the game actually goes - the FIRST line mapping the
    redirector, which is not the block when an older line (foreign) sits above it.
    """
    entries, inside = [], False
    try:
        lines = hosts_switch.read_hosts()
    except OSError as e:
        return {"active": False, "ip": None, "entries": [], "foreign": [],
                "effective_ip": None, "error": str(e), "path": _redact(str(HOSTS))}

    for line in lines:
        stripped = line.strip()
        if stripped == BEGIN:
            inside = True
            continue
        if stripped == END:
            inside = False
            continue
        if inside and stripped:
            entries.append(stripped)

    ip = None
    for entry in entries:
        parts = entry.split()
        if len(parts) >= 2 and parts[1] == REDIRECTOR:
            ip = parts[0]
            break
    return {"active": bool(entries), "ip": ip, "entries": entries,
            "foreign": hosts_switch.foreign_redirects(lines, REDIRECTOR),
            "effective_ip": hosts_switch.effective_address(lines, REDIRECTOR), "error": None,
            "path": _redact(str(HOSTS))}


def _hosts_write_error(error: OSError, ip: str = "") -> str:
    """What to do about a hosts file that would not take the change - down to the line to add or
    remove by hand when nothing else helps."""
    hint = ""
    try:
        import stat

        if getattr(os.stat(HOSTS), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_READONLY:
            hint = (" - the file is marked read-only (some tools lock it): untick Read-only in "
                    "its Properties and try again")
    except (OSError, AttributeError, ImportError):
        pass
    if not hint and isinstance(error, PermissionError):
        hint = " - an antivirus or another program may be protecting the file: allow it there"
    by_hand = (f" Or open {HOSTS} in Notepad run as administrator and add the line "
               f"\"{ip}  {REDIRECTOR}\"" if ip else
               f" Or open {HOSTS} in Notepad run as administrator and delete the lines with "
               f"{REDIRECTOR}")
    return f"writing hosts failed: {error}{hint}.{by_hand}"


def _hosts_plan(extra: list[str]) -> tuple[list[str], list[str], list[str]] | str:
    """(lines now, lines to write, foreign lines taken out), or the reading error. Every redirect
    of ours and any older line for the same names go; `extra` is appended."""
    try:
        lines = hosts_switch.read_hosts()        # byte for byte (latin-1), a missing file is empty
    except OSError as e:
        return f"reading hosts failed: {e}"
    cleaned, removed = hosts_switch.strip_redirects(lines)
    return lines, cleaned + extra, removed


def _rewrite_hosts(extra: list[str], ip: str = "") -> dict:
    """Writes the plan back - backup first (none when there was no file), restored when the
    write fails half-way."""
    plan = _hosts_plan(extra)
    if isinstance(plan, str):
        return {"ok": False, "error": plan}
    lines, new, removed = plan
    if new == lines:
        return {"ok": True, "removed": [], "backup": None, "changed": False}
    try:
        copy = hosts_switch.backup_hosts()
    except OSError as e:
        return {"ok": False, "error": f"could not back up hosts, so nothing was changed: {e}"}
    try:
        hosts_switch.write_hosts(new)
    except OSError as e:
        restored = hosts_switch.restore(copy)
        return {"ok": False, "error": _hosts_write_error(e, ip)
                + ("" if restored or copy is None else f" (the previous file is in {copy})")}
    return {"ok": True, "removed": removed, "backup": str(copy) if copy else None, "changed": True}


def hosts_on(ip: str) -> dict:
    """Points gosredirector.ea.com at the given address (backup first, then flush DNS).

    Also drops any older line for the same names outside the block (removed) -
    left in place, it would come first and win (hosts_switch.strip_redirects).
    """
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "no server address given"}
    if not valid_ipv4(ip):
        return {"ok": False, "error": f"\"{ip}\" is not an IPv4 address like 192.168.1.10"}
    if not can_edit_hosts():
        return {"ok": False, "error": "administrator rights required", "needs_admin": True}

    result = _rewrite_hosts([BEGIN, f"{ip}\t{REDIRECTOR}", END], ip)
    if result["ok"]:
        flush_dns()
        result["ip"] = ip
    return result


def hosts_off() -> dict:
    """Removes the redirect - the launcher's block and any older line for the same
    names. A leftover entry breaks the EA App and other EA games.

    Nothing to remove is a success without administrator rights: the uninstaller runs unelevated
    (--cleanup) and would otherwise warn on every uninstall."""
    plan = _hosts_plan([])
    if isinstance(plan, str):
        return {"ok": False, "error": plan}
    if plan[0] == plan[1]:
        return {"ok": True, "removed": [], "backup": None, "changed": False}
    if not can_edit_hosts():
        return {"ok": False, "error": "administrator rights required", "needs_admin": True}
    result = _rewrite_hosts([])
    if result["ok"]:
        flush_dns()
    return result


def resolved_redirector() -> list[str]:
    """The addresses Windows gives the game for gosredirector.ea.com, in the order
    it gives them - the game takes the first. Reading the file tells what should
    happen; this is what does. Empty when the name does not resolve."""
    flush_dns()
    try:
        infos = socket.getaddrinfo(REDIRECTOR, 42127, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


# =======================================================================================
#                               FIREWALL
# =======================================================================================

PORT_LIST_RE = re.compile(r"(?<![\w.,-])(\d+(?:[-,]\d+)*)(?![\w.,-])")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def firewall_scope(mode: str, local_ip: str = "", own: list[str] | None = None) -> str:
    """The address a host's rules are limited to (localip), or "" for every address. A host that
    picked its address gets rules for that address only: the server is then reachable on the
    VPN or LAN the players share, not on every network the PC is on, such as public Wi-Fi. An
    address this PC does not have is ignored, since a rule for it would block everything. `own`
    is this PC's addresses, from local_addresses() by default."""
    if mode != "host" or not local_ip:
        return ""
    if own is None:
        own = [a["ip"] for a in local_addresses()]
    return local_ip if local_ip in own else ""


def firewall_commands(mode: str, local_ip: str = "",
                      own: list[str] | None = None) -> list[tuple[str, str, list[str]]]:
    """(rule name, label for the UI, netsh add command) for each inbound rule of the mode."""
    scope = firewall_scope(mode, local_ip, own)
    return [(name, f"{name} ({proto} {ports})" + (f" on {scope}" if scope else ""),
             ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
              "dir=in", "action=allow", f"protocol={proto}", f"localport={ports}"]
             + ([f"localip={scope}"] if scope else []))
            for name, proto, ports in FIREWALL_RULES.get(mode, [])]


def _scoped_to(output: str) -> set[str]:
    """The addresses a rule is limited to, from netsh's output: its IPv4 literals, masks left
    out. netsh translates its labels, never the values - and "Any" carries no address."""
    return {ip for ip in IPV4_RE.findall(output) if not ip.startswith("255.")}


def rule_state(output: str | None, name: str, proto: str, ports: str, scope: str = "") -> str:
    """ok / outdated / missing / unknown, from `netsh advfirewall firewall show rule`.

    netsh translates its labels ("Rule Name" is "Regelname" on a German Windows) but not the
    values, so this looks for the values: the rule's name, its protocol and its port list -
    the whole list, so "42127,14219" does not pass for "42127,14219,17502".
    """
    if output is None:
        return "unknown"
    if name.lower() not in output.lower():
        return "missing"
    if not (ports in PORT_LIST_RE.findall(output) and re.search(rf"\b{proto}\b", output, re.I)):
        return "outdated"
    # a rule for another address (the host moved to another VPN), or for every address when
    # this one was picked, is just as wrong as a wrong port
    return "ok" if _scoped_to(output) == ({scope} if scope else set()) else "outdated"


def _show_rule(name: str) -> str | None:
    result = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
    return None if result is None else _console_text(result.stdout)


def firewall_status(mode: str, local_ip: str = "") -> dict:
    """Which of the mode's inbound rules exist, scoped as firewall_rules would scope them.
    Reading rules needs no administrator rights."""
    rules = FIREWALL_RULES.get(mode, [])
    if not IS_WINDOWS:
        return {"supported": False, "ok": False, "rules": [
            {"name": n, "proto": p, "ports": ports, "state": "unknown"} for n, p, ports in rules]}
    scope = firewall_scope(mode, local_ip)
    with ThreadPoolExecutor(max_workers=max(1, len(rules))) as pool:
        outputs = list(pool.map(_show_rule, [name for name, _, _ in rules]))
    states = [{"name": name, "proto": proto, "ports": ports,
               "state": rule_state(output, name, proto, ports, scope)}
              for (name, proto, ports), output in zip(rules, outputs)]
    return {"supported": True, "ok": bool(states) and all(s["state"] == "ok" for s in states),
            "rules": states, "scope": scope}


def firewall_rules(mode: str, local_ip: str = "") -> dict:
    """Adds the inbound rules for 'host' or 'client' mode that are missing or outdated -
    a host's limited to its address (firewall_commands). Idempotent: a rule that is already
    right is left alone; a wrong one goes first, so switching address or mode never leaves a
    wider rule behind."""
    if mode not in FIREWALL_RULES:
        return {"ok": False, "error": f"unknown mode {mode!r}"}
    if not IS_WINDOWS:
        return {"ok": False, "error": "firewall rules are a Windows feature"}
    if not is_admin():
        return {"ok": False, "error": "administrator rights required", "needs_admin": True}

    before = {r["name"]: r["state"] for r in firewall_status(mode, local_ip)["rules"]}
    added = []
    for name, label, command in firewall_commands(mode, local_ip):
        if before.get(name) == "ok":
            continue
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        result = _run(command)
        if result is None or result.returncode != 0:
            detail = _console_text(result.stdout).strip() if result is not None else "netsh missing"
            return {"ok": False, "error": f"rule {name}: {detail}"}
        added.append(label)
    status = firewall_status(mode, local_ip)
    return {"ok": True, "rules": added, "status": status}


def _rule_names() -> list[str]:
    return sorted({name for rules in FIREWALL_RULES.values() for name, _proto, _ports in rules})


def firewall_off() -> dict:
    """Removes every rule the launcher adds, in either mode - for the uninstaller (--cleanup)
    and the Remove button. Like hosts_off, no rules to remove is a success without
    administrator rights."""
    if not IS_WINDOWS:
        return {"ok": True, "removed": []}
    present = [name for name in _rule_names() if rule_state(_show_rule(name), name, "", "") != "missing"]
    if not present:
        return {"ok": True, "removed": []}
    if not is_admin():
        return {"ok": False, "error": "administrator rights required", "needs_admin": True}
    for name in present:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    return {"ok": True, "removed": present}


# =======================================================================================
#                               PORTS
# =======================================================================================

def port_free(proto: str, port: int) -> bool:
    """Would the server's bind succeed? The same bind it makes (tls_terminator._bind_exclusive):
    SO_EXCLUSIVEADDRUSE on Windows, so a port another program merely shares counts as taken."""
    kind = socket.SOCK_STREAM if proto == "TCP" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, kind)
    try:
        excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if excl is not None:
            s.setsockopt(socket.SOL_SOCKET, excl, 1)
        elif kind == socket.SOCK_STREAM:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def parse_netstat(text: str) -> tuple[dict[tuple[str, int], int], set[int]]:
    """`netstat -ano` -> ({(proto, port): pid} of the sockets that hold a port, {TCP ports with
    connections still closing}). TCP holds a port when listening, told by the remote side being
    0.0.0.0:0 / [::]:0; a connection with PID 0 is in TIME_WAIT. The state column is translated,
    the addresses and numbers are not."""
    owners: dict[tuple[str, int], int] = {}
    closing: set[int] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto, local, remote, pid = parts[0].upper(), parts[1], parts[2], parts[-1]
        port = local.rsplit(":", 1)[-1]
        if not (port.isdigit() and pid.isdigit()):
            continue
        if proto == "TCP" and remote not in ("0.0.0.0:0", "[::]:0"):
            if pid == "0":
                closing.add(int(port))
            continue
        owners.setdefault((proto, int(port)), int(pid))
    return owners, closing


def port_status(own_pid: int | None = None) -> dict:
    """The server's ports: free, or held - by whom. A port held by our own running server is fine.

    "closing": nobody listens, but connections of the last session are still in TIME_WAIT -
    the server's own exclusive bind can be refused until they time out."""
    ports = [{"proto": proto, "port": port, "purpose": purpose, "free": port_free(proto, port)}
             for proto, port, purpose in SERVER_PORTS]
    if all(p["free"] for p in ports):
        return {"ok": True, "ports": ports}
    owners: dict[tuple[str, int], int] = {}
    closing: set[int] = set()
    names: dict[int, str] = {}
    if IS_WINDOWS:
        result = _run(["netstat", "-ano"], timeout=15)
        if result is not None:
            owners, closing = parse_netstat(_console_text(result.stdout))
        names = running_processes() or {}
    for p in ports:
        pid = owners.get((p["proto"], p["port"]))
        p["pid"] = pid
        p["process"] = names.get(pid) if pid else None
        p["own"] = bool(own_pid) and pid == own_pid
        p["closing"] = not pid and p["proto"] == "TCP" and p["port"] in closing
    blocked = [p for p in ports if not p["free"] and not p["own"]]
    return {"ok": not blocked, "ports": ports}


def describe_blocked(ports: list[dict]) -> str:
    """One sentence for the ports the server cannot have."""
    held, closing = [], []
    for p in ports:
        if p["free"] or p.get("own"):
            continue
        if p.get("closing"):
            closing.append(f"{p['proto']} {p['port']}")
            continue
        who = (f"{p['process']} (PID {p['pid']})" if p.get("process")
               else f"PID {p['pid']}" if p.get("pid") else "another program")
        held.append(f"{p['proto']} {p['port']} by {who}")
    parts = []
    if held:
        parts.append(("port " if len(held) == 1 else "ports ") + ", ".join(held)
                     + " - close that program (or an older TurboRivals server) and try again")
    if closing:
        parts.append(", ".join(closing) + " still being released after the last session - "
                     "try again in a minute or two")
    return "; ".join(parts)


# =======================================================================================
#                               ADDRESSES
# =======================================================================================

# Adapter names, not address ranges. ipconfig reports them in English even on
# a localised Windows ("Ethernet adapter Radmin VPN"), and an address range
# says nothing useful: 192.168.x.x is the right answer on a shared LAN and the
# wrong one only when it belongs to a virtual adapter.
VPN_ADAPTERS = re.compile(
    r"radmin|hamachi|zerotier|tailscale|wireguard|openvpn|softether|\bvpn\b", re.I)
VIRTUAL_ADAPTERS = re.compile(
    r"vethernet|\bwsl\b|hyper-v|virtualbox|vmware|loopback|docker|bluetooth", re.I)
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _classify_adapter(adapter: str) -> str:
    """vpn / virtual / lan - only 'virtual' is ever a mistake to pick."""
    if VPN_ADAPTERS.search(adapter):
        return "vpn"
    if VIRTUAL_ADAPTERS.search(adapter):
        return "virtual"
    return "lan"


def parse_ipconfig(text: str) -> list[dict]:
    """`ipconfig` -> [{ip, adapter, kind}]. Loopback and link-local (169.254.x.x, what an adapter
    gets when its VPN or DHCP is down) are left out: no other machine reaches those."""
    found, adapter = [], ""
    for line in text.splitlines():
        if line.strip() and not line[0].isspace():
            # "Ethernet adapter Radmin VPN:" -> "Radmin VPN"
            adapter = re.sub(r"^.*?adapter\s+", "", line.strip().rstrip(":").strip(), flags=re.I)
        elif "IPv4" in line:
            match = IPV4_RE.search(line)
            if match and not match.group(1).startswith(("127.", "169.254.")):
                found.append({"ip": match.group(1),
                              "adapter": adapter or "unknown adapter",
                              "kind": _classify_adapter(adapter)})
    return found


def _addresses_via_socket() -> list[dict]:
    """Fallback when ipconfig is unavailable - no adapter names, so no guessing."""
    found: dict[str, dict] = {}

    def add(ip: str) -> None:
        if ip and not ip.startswith(("127.", "169.254.")):
            found.setdefault(ip, {"ip": ip, "adapter": "unknown adapter", "kind": "lan"})

    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            add(ip)
    except OSError:
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))          # no packet is sent: this only picks a route
        add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    return list(found.values())


def local_addresses() -> list[dict]:
    """Every IPv4 address of this machine, each with the adapter that owns it.

    --public-ip must name the adapter the other players actually reach us on.
    Which one that is depends on how they connect - a VPN over the internet, a
    plain network card on a shared LAN - so the launcher lists them and lets
    the user choose instead of assuming.
    """
    result = _run(["ipconfig"]) if IS_WINDOWS else None
    found = parse_ipconfig(_console_text(result.stdout)) if result is not None else []
    if not found:
        found = _addresses_via_socket()

    # Virtual adapters last: they are the only kind nobody else can reach.
    order = {"vpn": 0, "lan": 1, "virtual": 2}
    unique = list({a["ip"]: a for a in found}.values())
    return sorted(unique, key=lambda a: (order.get(a["kind"], 3), a["ip"]))


def suggested_public_ip(addresses: list[dict] | None = None) -> str:
    """A starting point only - the user picks the adapter in the UI."""
    for addr in local_addresses() if addresses is None else addresses:
        if addr["kind"] != "virtual":
            return addr["ip"]
    return ""


# =======================================================================================
#                               PLAYERS
# =======================================================================================

NAME_FOLD = str.maketrans("ŁłØøĐđßÆæŒœ", "LlOoDdsAaOo")   # letters NFKD does not decompose


def clean_name(name: str) -> str:
    """A nickname as the other players will see it - the server's own rule
    (tls_terminator._clean_name): printable ASCII like every EA nickname, accents folded
    (Ł -> L, é -> e), anything else dropped, at most NAME_MAX characters."""
    folded = unicodedata.normalize("NFKD", (name or "").translate(NAME_FOLD))
    return "".join(ch for ch in folded if " " <= ch <= "~").strip()[:NAME_MAX].strip()


class Game:
    """The session's player list. The server cannot learn EA names (the client
    sends nothing but an opaque Origin token), so they are supplied by hand:
    address -> name. Only needed for players without the launcher - with it,
    a player names itself (identify)."""

    def __init__(self, players: list | None = None):
        self.list_players: list[tuple[str, str]] = []
        for entry in players or []:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                ip, nick = (str(v).strip() for v in entry)
                if valid_ipv4(ip) and clean_name(nick) and len(self.list_players) < MAX_GUESTS:
                    self.list_players.append((ip, nick))

    @property
    def player_count(self) -> int:
        return len(self.list_players)

    def get_list_players(self) -> list[tuple[str, str]]:
        return list(self.list_players)

    def check(self, nick: str, ip: str) -> str:
        """Why this entry cannot be added, "" when it can."""
        nick, ip = (nick or "").strip(), (ip or "").strip()
        if not nick or not ip:
            return "enter both the player's name and their address"
        if not clean_name(nick):
            return "that name has no letters the game can show"
        if not valid_ipv4(ip):
            return f"\"{ip}\" is not an IPv4 address like 26.48.21.54"
        if self.player_count >= MAX_GUESTS:
            return f"limit is {MAX_GUESTS} players + host"
        for listed_ip, listed_nick in self.list_players:
            if listed_ip == ip:
                return f"{ip} is already listed as {listed_nick}"
            if listed_nick.lower() == nick.lower():
                return f"{listed_nick} is already listed"
        return ""

    def add_player(self, nick: str, ip: str) -> bool:
        if self.check(nick, ip):
            return False
        self.list_players.append((ip.strip(), nick.strip()))
        return True

    def remove_player(self, nick: str) -> bool:
        for player in self.list_players:
            if player[1] == nick:
                self.list_players.remove(player)
                return True
        return False


# =======================================================================================
#                               BLAZE SERVER
# =======================================================================================

SERVER_FLAG = "--run-server"     # app.py dispatches on this when frozen


def build_command(local_name: str, players: list[tuple[str, str]], public_ip: str,
                  entitlements: str = "online",
                  extra: list[str] | None = None, capture: bool = False) -> list[str]:
    """The server command line. players are (ip, name) tuples. capture keeps a file per Blaze
    frame in CAPTURE_DIR - hundreds per session, for protocol work only.

    Frozen, sys.executable IS this launcher, so running the server means
    re-invoking ourselves behind SERVER_FLAG rather than starting a Python that
    is not installed on the machine.
    """
    if len(players) > MAX_GUESTS:
        raise ValueError(f"too many players: {len(players)} (limit is {MAX_GUESTS} + host)")
    if public_ip and not valid_ipv4(public_ip):
        raise ValueError(f"\"{public_ip}\" is not an IPv4 address the other players can reach")
    if entitlements not in ("online", "none"):
        raise ValueError(f"unknown entitlements mode {entitlements!r}")

    if FROZEN:
        command = [sys.executable, SERVER_FLAG]
    else:
        command = [sys.executable, "-u", str(ROOT / "proto-lab" / "tls_terminator.py")]

    command += ["--entitlements", entitlements,
                "--cert", str(PKI_DIR / "server.der"),
                "--key", str(PKI_DIR / "server.key"),
                "--out", str(CAPTURE_DIR)]
    if not capture:
        command += ["--no-capture"]
    if os.environ.get("TURBORIVALS_HOME"):
        command += ["--data-dir", str(DATA_DIR / "data")]
    if public_ip:
        command += ["--public-ip", public_ip]
    if local_name:
        command += ["--local-persona", local_name]
    for ip, nick in players:
        command += ["--player", f"{ip}={nick}"]
    if extra:
        command += extra
    # server_args from config.json, last so they can override anything above (A/B tests
    # without a new build - readme, "Other server flags")
    command += [str(a) for a in load_config().get("server_args", [])]
    return command


def purge_captures() -> int:
    """Deletes the raw frames an installed launcher before 1.0.7 left behind (it never passed
    --no-capture) - they hold the EA auth code of every login. Only frozen: run from source,
    CAPTURE_DIR is the developer's own docs/recon/capture. Returns how many files went."""
    if not FROZEN:
        return 0
    removed = 0
    for path in CAPTURE_DIR.glob("blaze-*.bin"):
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def cert_exists() -> bool:
    return (PKI_DIR / "server.der").exists() and (PKI_DIR / "server.key").exists()


def make_cert() -> dict:
    """Generates the stand-in certificate (once per machine).

    Done in-process: make_stub_cert is plain Python, so there is no interpreter
    to spawn and nothing to find on PATH. The two RSA keys take a fraction of a
    second, on the API thread, so the UI stays live.
    """
    try:
        make_stub_cert = _load_sibling("make_stub_cert", "proto-lab")
        make_stub_cert.generate(PKI_DIR)
    except Exception as e:                       # keygen, disk, import - all one story
        return {"ok": False, "error": f"certificate generation failed: {e}"}
    return {"ok": True, "output": _redact(str(PKI_DIR))}


LOG_FLUSH_INTERVAL = 0.1     # seconds between batches handed to the UI
LOG_QUEUE_LIMIT = 2000       # lines held back before the oldest start dropping
LOG_DIR = USER_DIR / "logs"
LOGS_KEPT = 20               # server-<date>.log files, newest first (as since 1.0.9)


def _open_server_log(pid: int, command: list[str] | None = None) -> tuple[io.TextIOBase | None, Path | None]:
    """A fresh log file for this server run, so a session can be read - and attached to a bug
    report - after the fact. It starts with the version and the command line (flags from
    server_args included), paths redacted."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        now = dt.datetime.now()
        path = LOG_DIR / f"server-{now:%Y%m%d-%H%M%S}-{pid}.log"
        handle = path.open("w", encoding="utf-8", errors="replace", buffering=1)
        handle.write(f"# TurboRivals {APP_VERSION}, server started {now:%Y-%m-%d %H:%M:%S}\n")
        if command:
            handle.write(f"# {_redact(subprocess.list2cmdline(command))}\n")
        for old in sorted(LOG_DIR.glob("server-*.log"))[:-LOGS_KEPT]:
            try:
                old.unlink()
            except OSError:
                pass
        return handle, path
    except OSError:
        return None, None


def _kill_with_launcher(proc: subprocess.Popen):
    """Ties the server to the launcher: a Windows job object that ends the server when the last
    handle to it closes - which happens when the launcher exits for ANY reason, a crash or Task
    Manager included. Without it a stray server kept the ports, and the next one was refused
    (or, before SO_EXCLUSIVEADDRUSE, silently shadowed). Best effort: None when unavailable."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits),
                        ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                     ctypes.c_void_p, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000     # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
                and kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle)))):
            return job
        kernel32.CloseHandle(job)
    except Exception:                            # noqa: BLE001 - the server runs either way
        pass
    return None


def _close_handle(handle) -> None:
    if handle and IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        except Exception:                        # noqa: BLE001
            pass


class ServerProcess:
    """The Blaze server as a child process, with its log streamed to the UI.

    Two threads, for two different reasons:

    * Popen.communicate() would block until the session ends, so a reader
      thread drains stdout and parks each line in a queue.
    * The UI is only reachable through Window.evaluate_js, which hops onto the
      WebView2 UI thread and blocks the caller on a semaphore. One call per
      line would flood that thread - a player joining alone produces a few
      hundred lines in about a second. So a flusher thread wakes ten times a
      second and hands over whatever accumulated as ONE batch.

    Every line also goes to LOG_DIR/server-<date>.log.
    """

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.reader: threading.Thread | None = None
        self.flusher: threading.Thread | None = None
        self.command: list[str] = []
        self.started_at: float | None = None
        self.log_path: Path | None = None
        self.exit_code: int | None = None
        # Set by stop(): a server ended from the launcher exits non-zero too (TerminateProcess
        # leaves 1, SIGTERM -15), and that is not a crash.
        self.stop_requested = False

        self._lines: deque[str] = deque()
        self._lock = threading.Lock()
        self._dropped = 0
        self._finished = threading.Event()
        self._job = None

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.is_running() else None

    def status(self) -> dict:
        running = self.is_running()
        return {"running": running,
                "pid": self.proc.pid if running else None,
                "started_at": self.started_at if running else None,
                "uptime": round(time.time() - self.started_at) if running and self.started_at else 0,
                "exit_code": None if running else self.exit_code,
                "stop_requested": self.stop_requested,
                "log_path": _redact(str(self.log_path)) if self.log_path else None}

    def start(self, command: list[str], on_lines, on_exit=None) -> dict:
        if self.is_running():
            return {"ok": False, "error": "the server is already running"}
        if not cert_exists():
            return {"ok": False, "error": "no certificate - generate one first"}

        # The same encoding on both ends of the pipe - for a server run from source; the
        # frozen one sets it itself (app.py --run-server).
        env = {**os.environ, "PYTHONIOENCODING": "utf-8:replace"}
        try:
            proc = subprocess.Popen(
                command, cwd=str(ROOT), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", bufsize=1, creationflags=NO_WINDOW, env=env)
        except OSError as e:
            return {"ok": False, "error": f"could not start the server: {e}"}

        self.proc = proc
        self._job = _kill_with_launcher(proc)
        self.command = command
        self.started_at = time.time()
        self.exit_code = None
        self.stop_requested = False
        log_file, self.log_path = _open_server_log(proc.pid, command)

        with self._lock:
            self._lines.clear()
            self._dropped = 0
        self._finished.clear()

        def pump():
            try:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if log_file:
                        try:
                            log_file.write(line + "\n")
                        except (OSError, ValueError):
                            pass
                    with self._lock:
                        self._lines.append(line)
                        # A burst must never turn into unbounded memory. Losing the
                        # oldest lines beats freezing the window.
                        while len(self._lines) > LOG_QUEUE_LIMIT:
                            self._lines.popleft()
                            self._dropped += 1
            finally:
                self.exit_code = proc.wait()
                try:
                    proc.stdout.close()
                except OSError:
                    pass
                if log_file:
                    how = ", stopped from the launcher" if self.stop_requested else ""
                    try:
                        log_file.write(f"--- server exited (code {self.exit_code}{how}) ---\n")
                        log_file.close()
                    except (OSError, ValueError):
                        pass
                self._finished.set()

        def flush_once():
            with self._lock:
                if not self._lines and not self._dropped:
                    return
                batch = list(self._lines)
                dropped = self._dropped
                self._lines.clear()
                self._dropped = 0
            if dropped:
                batch.insert(0, f"... {dropped} lines skipped (burst)")
            on_lines(batch)

        def flush_loop():
            while not self._finished.wait(LOG_FLUSH_INTERVAL):
                flush_once()
            flush_once()        # the tail, before anyone hears about the exit
            _close_handle(self._job)
            self._job = None
            if on_exit:
                on_exit(self.exit_code)

        self.reader = threading.Thread(target=pump, daemon=True)
        self.reader.start()
        self.flusher = threading.Thread(target=flush_loop, daemon=True)
        self.flusher.start()
        return {"ok": True, "pid": proc.pid, "command": command,
                "log_path": _redact(str(self.log_path)) if self.log_path else None}

    def stop(self, timeout: float = 5) -> dict:
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return {"ok": True, "note": "the server was not running"}
        self.stop_requested = True
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return {"ok": False, "error": f"the server (PID {proc.pid}) does not stop"}
        self._finished.wait(timeout)
        return {"ok": True, "exit_code": proc.returncode}


# =======================================================================================
#                               GAME
# =======================================================================================

_GAME_KEYS = (
    r"SOFTWARE\WOW6432Node\EA Games\Need for Speed(TM) Rivals",
    r"SOFTWARE\EA Games\Need for Speed(TM) Rivals",
)


def find_game_dir() -> Path | None:
    """The game directory, from the registry key the Steam installer writes.

    Same keys as proto-lab/launch_direct.py, but this returns None instead of
    exiting - the launcher has somewhere else to go.
    """
    try:
        import winreg
    except ImportError:
        return None

    for key in _GAME_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
                value, _ = winreg.QueryValueEx(handle, "Install Dir")
                game = Path(value)
                if (game / "NFS14.exe").exists():
                    return game
        except OSError:
            continue
    return None


def ea_offer_ids(game: Path | None = None) -> list[str]:
    """EA App offer ids, read from the game's own installer data.

    <game>\\__Installer\\installerdata.xml lists them as <contentID>; the first
    is the base game (1004776 here, which matches the MultiplayerId the EA App
    reports over LSX). Reading them beats hardcoding an id that would be wrong
    on a different edition.
    """
    game = game or find_game_dir()
    if game is None:
        return []
    try:
        text = (game / "__Installer" / "installerdata.xml").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return []
    return re.findall(r"<contentID>\s*([^<\s]+)\s*</contentID>", text)


def game_info() -> dict:
    game = find_game_dir()
    return {"found": game is not None, "dir": _redact(str(game)) if game else None,
            "offers": ea_offer_ids(game) if game else []}


def _start_uri(uri: str) -> None:
    if not hasattr(os, "startfile"):
        raise OSError("launching the game needs Windows")
    os.startfile(uri)


def launch_game() -> dict:
    """Starts Rivals through the EA App.

    Not through Steam. For a Steam-owned copy of this title the Steam route
    brings the game up but Origin then reports it cannot reach its servers -
    it has never worked here. The EA App is what the game expects, and
    `origin2://` is registered by EA Desktop's EALauncher.

    Steam stays as a fallback for a machine with no EA App, where the URI
    would not resolve at all.
    """
    if process_status()["game"]:
        return {"ok": True, "via": "already running", "running": True}
    offers = ea_offer_ids()
    if offers:
        try:
            _start_uri(f"origin2://game/launch?offerIds={offers[0]}")
            return {"ok": True, "via": f"EA App (offer {offers[0]})"}
        except OSError:
            pass                                 # no EA App - try Steam below

    try:
        _start_uri(f"steam://rungameid/{STEAM_APP_ID}")
    except OSError as e:
        return {"ok": False, "error": f"could not launch the game: {e}"}
    return {"ok": True, "via": "Steam - no EA App found, online may not work"}


# =======================================================================================
#                               CAREER SAVE
# =======================================================================================

# The game logs in under whatever uid the server hands it and names its save file after it, but
# loads the account's own EA-era save. So the server has to know that save's id, and for a guest
# only the guest's machine does (proto-lab/ea_identity.py).

IDENTIFY_PORT = 17502           # the host's QoS HTTP port (tls_terminator --qos-port), already open
SAVE_BACKUP_DIR = USER_DIR / "save-backups"
SAVE_BACKUPS_KEPT = 5

_identity_lock = threading.Lock()
_identity_cache: dict = {"signature": None, "value": None}


def _identity_signature() -> tuple:
    """Size and time of every file ea_identity.resolve reads: the answer only changes with them."""
    files = [ea_identity.saves_dir(), ea_identity.EA_DESKTOP_DIR]
    files += [ea_identity.EA_LOGS_DIR / name for name in ea_identity.LOG_FILES]
    try:
        files += sorted(ea_identity.EA_DESKTOP_DIR.glob("user_*.ini"))
    except OSError:
        pass
    signature = []
    for path in files:
        try:
            st = path.stat()
            signature.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            signature.append((str(path), None, None))
    return tuple(signature)


def save_identity() -> dict:
    """This machine's EA App user, its career saves, the one the game loads and how we know it
    (source), and the EA nickname (persona) when the EA App's log has it.

    Cached until one of its files changes: resolve() reads the EA App's verbose log, which grows
    to tens of megabytes, and the launcher asks on start, on every refresh and on connect."""
    signature = _identity_signature()
    with _identity_lock:
        if _identity_cache["signature"] == signature and _identity_cache["value"] is not None:
            return dict(_identity_cache["value"])
    value = ea_identity.resolve()
    with _identity_lock:
        _identity_cache.update(signature=signature, value=value)
    return dict(value)


def backup_saves() -> dict:
    """Copies the game's settings folder (career saves + profile) once a day, before the
    first session - a wrong uid means the game writes a save, so a copy should exist before
    anything here changes which one. Keeps the last SAVE_BACKUPS_KEPT."""
    source = ea_identity.saves_dir()
    if not source.is_dir():
        return {"ok": False, "error": f"no save folder at {_redact(str(source))}"}
    today = f"{dt.datetime.now():%Y%m%d}"
    try:
        SAVE_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        done = sorted(p for p in SAVE_BACKUP_DIR.iterdir() if p.is_dir())
        if any(p.name.startswith(today) for p in done):
            return {"ok": True, "note": "already backed up today"}
        target = SAVE_BACKUP_DIR / f"{dt.datetime.now():%Y%m%d-%H%M%S}"
        shutil.copytree(source, target)
        for old in (done + [target])[:-SAVE_BACKUPS_KEPT]:
            shutil.rmtree(old, ignore_errors=True)
    except OSError as e:
        return {"ok": False, "error": f"save backup failed: {e}"}
    return {"ok": True, "path": _redact(str(target))}


def _failure_kind(error: Exception) -> str:
    reason = getattr(error, "reason", error)
    if isinstance(reason, ConnectionRefusedError):
        return "refused"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(reason, OSError) and reason.errno in (
            errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051):
        return "unreachable"
    return "other"


def _unreachable(server_ip: str, error: Exception) -> str:
    """Why the host did not answer, in terms of what to check. A refusal means the
    machine is there and only the server is not; silence means the machines do not
    see each other at all."""
    kind = _failure_kind(error)
    if kind == "refused":
        return f"{server_ip} is reachable, but no TurboRivals server runs there"
    if kind == "timeout":
        return (f"no answer from {server_ip} - wrong address, the machines do not see each "
                f"other (VPN not connected, different network) or the host's firewall")
    if kind == "unreachable":
        return f"no route to {server_ip} - is the VPN connected, or the network cable in?"
    return f"the host's server did not answer ({getattr(error, 'reason', error)})"


def _opener():
    # No proxy: a system-wide one would receive a request meant for a LAN or VPN address.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def identify_to_host(server_ip: str, name: str = "") -> dict:
    """Tells the host's server which save this machine's game loads and the name this player
    goes by, before the game starts (tls_terminator._identify). Not fatal when it fails: the game
    still runs, only its progress will not stick and the host's list names the player."""
    ident = save_identity()
    if not valid_ipv4(server_ip or ""):
        return {"ok": False, **ident, "error": f"\"{server_ip}\" is not an IPv4 address"}
    if not ident["id"]:
        return {"ok": False, **ident,
                "error": "no EA App account found - the host cannot save your progress"}
    query = urllib.parse.urlencode({"id": ident["id"], "user": ident["user"] or "",
                                    "saves": ",".join(map(str, ident["saves"])),
                                    "src": ident["source"], "name": clean_name(name)})
    url = f"http://{server_ip}:{IDENTIFY_PORT}/turborivals/identify?{query}"
    try:
        with _opener().open(url, timeout=3) as reply:
            body = reply.read(64)
    except urllib.error.HTTPError as e:
        return {"ok": False, **ident, "error": f"the host refused the save id: {e.read().decode(errors='replace')}"}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, **ident, "error": _unreachable(server_ip, e),
                "reason": _failure_kind(e)}
    if body.strip() != b"ok":
        # A server from before 30.09 answers every path on this port with QoS XML
        return {"ok": False, **ident, "error": "the host's server is too old to take a save id"}
    return {"ok": True, **ident}


def test_host(server_ip: str) -> dict:
    """Is there a TurboRivals server at this address, and how far away: the same request the
    ONLINE NOW list makes, timed. Harmless for the host - its log stays quiet. The redirector
    and Blaze ports share the host's firewall rule with this one."""
    server_ip = (server_ip or "").strip()
    if not valid_ipv4(server_ip):
        return {"ok": False, "reason": "invalid",
                "error": f"\"{server_ip}\" is not an IPv4 address like 26.48.21.54"}
    started = time.perf_counter()
    try:
        with _opener().open(f"http://{server_ip}:{IDENTIFY_PORT}/turborivals/players",
                            timeout=3) as reply:
            players = json.loads(reply.read(256 * 1024))
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "reason": _failure_kind(e), "error": _unreachable(server_ip, e)}
    except ValueError:
        return {"ok": False, "reason": "old", "error": "the host's server is too old for this launcher"}
    ms = round((time.perf_counter() - started) * 1000)
    return {"ok": True, "ms": ms, "players": len(players) if isinstance(players, list) else 0}


# =======================================================================================
#                               PICTURE AND ONLINE NOW
# =======================================================================================

# Each player's picture lives on its own machine (AVATAR_PATH) and goes to the host's server,
# which keeps one per player and hands them to every launcher in the session
# (tls_terminator._launcher_request). The UI scales and crops it before it ever gets here, into
# two files: a small PNG for the launchers and a JPEG for the game, which asks the server for
# profile pictures through ByteVault and links libjpeg (tls_terminator._bytevault_record).

# Next to the save backups, not DATA_DIR: run from the repo, that is the repository itself.
AVATAR_PATH = USER_DIR / "avatar.png"
AVATAR_JPG_PATH = AVATAR_PATH.with_suffix(".jpg")
AVATAR_MAX = 64 * 1024              # same limit as the server
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
AVATAR_CACHE_MAX = 64               # pictures kept in memory, least recently shown dropped first
_avatar_cache: OrderedDict[tuple[str, int, int], str] = OrderedDict()   # (server, uid, version)
_avatar_lock = threading.Lock()


def _data_url(png: bytes) -> str:
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def _decode_data_url(data_url: str, magic: bytes) -> bytes | None:
    try:
        blob = base64.b64decode(data_url.split(",", 1)[1], validate=True)
    except (IndexError, ValueError, AttributeError):
        return None
    return blob if blob.startswith(magic) and len(blob) <= AVATAR_MAX else None


def _write_atomic(path: Path, data: bytes) -> None:
    """Never half a file: write next to it, then swap it in."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:          # antivirus/indexing holds the file - wait and retry
            time.sleep(0.05 * (attempt + 1))
    os.replace(tmp, path)


def save_avatar(png_url: str, jpg_url: str = "") -> dict:
    """Stores this player's picture - PNG and JPEG data URLs from the UI, at most 64 KB each."""
    png = _decode_data_url(png_url, PNG_MAGIC)
    jpg = _decode_data_url(jpg_url, JPEG_MAGIC) if jpg_url else b""
    if png is None or jpg is None:
        return {"ok": False, "error": "the picture must fit in 64 KB - try a simpler one"}
    try:
        _write_atomic(AVATAR_PATH, png)
        if jpg:
            _write_atomic(AVATAR_JPG_PATH, jpg)
        else:
            AVATAR_JPG_PATH.unlink(missing_ok=True)     # never an old JPEG next to a new PNG
    except OSError as e:
        return {"ok": False, "error": f"could not save the picture: {e}"}
    return {"ok": True, "avatar": _data_url(png)}


def load_avatar() -> str:
    """This player's picture as a data URL, "" when none is set."""
    try:
        return _data_url(AVATAR_PATH.read_bytes())
    except OSError:
        return ""


def upload_avatar(server_ip: str) -> dict:
    """Sends this player's picture to the server at server_ip. The server files it under whoever
    it knows at this machine's address, so a guest sends it after identify, and the host once its
    own server runs. Both files: the PNG for the launchers, the JPEG (when there is one) for the
    game."""
    files = [(p, t) for p, t in ((AVATAR_PATH, "image/png"), (AVATAR_JPG_PATH, "image/jpeg"))
             if p.exists()]
    if not files:
        return {"ok": True, "note": "no picture set"}
    for path, ctype in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        request = urllib.request.Request(
            f"http://{server_ip}:{IDENTIFY_PORT}/turborivals/avatar", data=data, method="POST",
            headers={"Content-Type": ctype})
        try:
            with _opener().open(request, timeout=5) as reply:
                reply.read(64)
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": f"the host refused the picture: {e.read().decode(errors='replace')}"}
        except (urllib.error.URLError, OSError) as e:
            return {"ok": False, "error": _unreachable(server_ip, e)}
    return {"ok": True}


def clear_avatar(server_ip: str | None = "") -> dict:
    """Removes this player's picture: both local files, so it is not sent again, and - when
    connected - the copies on the host's server (DELETE /turborivals/avatar, whose picture
    follows from this machine's address). The other launchers drop it on their next poll."""
    for path in (AVATAR_PATH, AVATAR_JPG_PATH):
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            return {"ok": False, "local": False, "error": f"could not remove {path.name}: {e}"}
    if not server_ip:
        return {"ok": True, "local": True}
    request = urllib.request.Request(
        f"http://{server_ip}:{IDENTIFY_PORT}/turborivals/avatar", method="DELETE")
    try:
        with _opener().open(request, timeout=5) as reply:
            reply.read(64)
    except urllib.error.HTTPError as e:
        return {"ok": False, "local": True, "error": f"removed here, but the host kept it: "
                                                     f"{e.read().decode(errors='replace')}"}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "local": True,
                "error": f"removed here, but {_unreachable(server_ip, e)}"}
    return {"ok": True, "local": True}


def _cached_avatar(base: str, server_ip: str, uid: int, version: int) -> str:
    key = (server_ip, uid, version)
    with _avatar_lock:
        if key in _avatar_cache:
            _avatar_cache.move_to_end(key)
            return _avatar_cache[key]
    try:
        with _opener().open(f"{base}/avatar/{uid}", timeout=3) as reply:
            png = reply.read(AVATAR_MAX + 1)
        picture = _data_url(png) if png.startswith(PNG_MAGIC) and len(png) <= AVATAR_MAX else ""
    except (urllib.error.URLError, OSError):
        return ""                        # not cached: the next poll tries again
    with _avatar_lock:
        _avatar_cache[key] = picture
        while len(_avatar_cache) > AVATAR_CACHE_MAX:
            _avatar_cache.popitem(last=False)
    return picture


def fetch_players(server_ip: str) -> dict:
    """Who is logged in to the server at server_ip, each with its picture as a data URL (or "").
    Pictures are cached by the version the server reports, so a poll every few seconds only
    downloads one when it changed."""
    if not valid_ipv4(server_ip or ""):
        return {"ok": False, "players": [], "error": "no server address"}
    base = f"http://{server_ip}:{IDENTIFY_PORT}/turborivals"
    try:
        with _opener().open(f"{base}/players", timeout=3) as reply:
            players = json.loads(reply.read(256 * 1024))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"ok": False, "players": [], "error": _unreachable(server_ip, e)}
    out = []
    for p in players if isinstance(players, list) else []:
        if not isinstance(p, dict):
            continue
        try:
            uid, version = int(p.get("uid", 0)), int(p.get("avatar", 0))
        except (TypeError, ValueError):
            continue
        picture = _cached_avatar(base, server_ip, uid, version) if version else ""
        out.append({"uid": uid, "name": str(p.get("name", "")), "local": bool(p.get("local")),
                    "avatar": picture})
    return {"ok": True, "players": out}


# =======================================================================================
#                               CONFIGURATION
# =======================================================================================

RECENT_SERVERS_KEPT = 6

DEFAULT_CONFIG = {
    "mode": "host",
    "local_persona": "",
    "public_ip": "",
    "server_ip": "",
    "entitlements": "online",
    "players": [],
    "recent_servers": [],        # host addresses this launcher connected to, newest first
    "restore_hosts_on_exit": "ask",          # ask / always / never
    "onboarded": False,          # the first-start welcome was answered
    "log_view": "key",           # the log filter: key / standard / raw / problems
    # the server keeps every Blaze frame - protocol work, so on when run from source and off in
    # the packaged launcher (the frames hold the EA auth code of every login)
    "keep_captures": not FROZEN,
    "server_args": [],           # extra server flags, appended last (A/B tests, readme)
}


def _sanitize(config: dict) -> dict:
    """A config.json edited by hand, or written by an older version, must not break the
    launcher: wrong types fall back to the defaults, entries that make no sense are dropped."""
    out = dict(DEFAULT_CONFIG)
    for key, default in DEFAULT_CONFIG.items():
        value = config.get(key, default)
        out[key] = value if isinstance(value, type(default)) else default
    if out["mode"] not in ("host", "client"):
        out["mode"] = "host"
    if out["entitlements"] not in ("online", "none"):
        out["entitlements"] = "online"
    if out["restore_hosts_on_exit"] not in ("ask", "always", "never"):
        out["restore_hosts_on_exit"] = "ask"
    if out["log_view"] not in ("key", "standard", "raw", "problems"):
        out["log_view"] = "key"
    out["players"] = [list(p) for p in Game(out["players"]).get_list_players()]
    out["recent_servers"] = [ip for ip in out["recent_servers"]
                             if isinstance(ip, str) and valid_ipv4(ip)][:RECENT_SERVERS_KEPT]
    for key in ("local_persona", "public_ip", "server_ip"):
        out[key] = out[key].strip()
    out["server_args"] = [str(a) for a in out["server_args"] if isinstance(a, (str, int, float))]
    return out


def config_exists() -> bool:
    return CONFIG_PATH.exists()


def load_config() -> dict:
    try:
        stored = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stored = {}
    return _sanitize(stored if isinstance(stored, dict) else {})


def save_config(config: dict) -> dict:
    merged = _sanitize({**load_config(), **{k: v for k, v in config.items() if k in DEFAULT_CONFIG}})
    try:
        _write_atomic(CONFIG_PATH, json.dumps(merged, indent=2, ensure_ascii=False).encode("utf-8"))
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "config": merged}


def remember_server(config: dict, server_ip: str) -> list[str]:
    """The recent-servers list with server_ip moved to the front."""
    recent = [server_ip] + [ip for ip in config.get("recent_servers", []) if ip != server_ip]
    return recent[:RECENT_SERVERS_KEPT]


# =======================================================================================
#                               DIAGNOSTICS
# =======================================================================================

def diagnostics(config: dict, server: dict) -> dict:
    """Everything a bug report asks for (.github/ISSUE_TEMPLATE/bug_report.yml), gathered in
    one go. Paths are redacted: the report is meant to be pasted into a public issue."""
    mode = config.get("mode", "host")
    with ThreadPoolExecutor(max_workers=6) as pool:
        procs = pool.submit(running_processes)
        addresses = pool.submit(local_addresses)
        firewall = pool.submit(firewall_status, mode,
                               config.get("public_ip", "") if mode == "host" else "")
        ident = pool.submit(save_identity)
        game = pool.submit(game_info)
        ports = None if server.get("running") else pool.submit(port_status)
    return {
        "version": APP_VERSION,
        "frozen": bool(FROZEN),
        "windows": windows_version(),
        "admin": is_admin(),
        "mode": mode,
        "processes": process_status(procs.result()),
        "hosts": hosts_status(),
        "firewall": firewall.result(),
        "ports": ports.result() if ports else {"ok": True, "ports": [], "server": True},
        "addresses": addresses.result(),
        "public_ip": config.get("public_ip", ""),
        "server_args": config.get("server_args", []),
        "server_ip": config.get("server_ip", ""),
        "save": ident.result(),
        "game": game.result(),
        "cert": cert_exists(),
        "server": server,
        "data_dir": _redact(str(DATA_DIR)),
        "log_dir": _redact(str(LOG_DIR)),
    }
