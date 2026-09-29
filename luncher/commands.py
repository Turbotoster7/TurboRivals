"""TurboRivals - launcher logic.

The UI (web/) never touches the system directly. Everything that needs
privileges, processes or files lives here; app.py only exposes it to
JavaScript.

Scope (phase 3 in the readme): hosts, firewall rules and player names
without a console.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from collections import deque
from pathlib import Path

LAUNCHER_DIR = Path(__file__).resolve().parent

# Frozen (PyInstaller) vs running from the repo. The two differ in one way that
# matters: PyInstaller unpacks the bundle into a temp directory it wipes on
# exit, so ROOT is readable but NOT a place to keep anything.
FROZEN = getattr(sys, "frozen", False)

if FROZEN:
    ROOT = Path(sys._MEIPASS)                    # bundled, read-only, temporary
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "TurboRivals"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH = DATA_DIR / "config.json"
    PKI_DIR = DATA_DIR / "pki"
    CAPTURE_DIR = DATA_DIR / "capture"
else:
    ROOT = LAUNCHER_DIR.parent                   # repository root
    DATA_DIR = ROOT
    CONFIG_PATH = LAUNCHER_DIR / "config.json"
    PKI_DIR = ROOT / "proto-lab" / "pki"
    CAPTURE_DIR = ROOT / "docs" / "recon" / "capture"


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

HOSTS = hosts_switch.HOSTS
BEGIN, END = hosts_switch.BEGIN, hosts_switch.END
REDIRECTOR = hosts_switch.PRIMARY[0]             # gosredirector.ea.com

MAX_GUESTS = 5          # host + 5 guests = 6 slots (MaxClientCount in NFS14.exe)
STEAM_APP_ID = "1262600"

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

NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


def is_admin() -> bool:
    return hosts_switch.is_admin()


def relaunch_as_admin() -> bool:
    """Starts this same launcher elevated (UAC prompt).

    Frozen, sys.executable is the launcher itself and takes no script argument.
    """
    import ctypes

    params = "" if FROZEN else f'"{LAUNCHER_DIR / "app.py"}"'
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(LAUNCHER_DIR), 1)
    return rc > 32


# =======================================================================================
#                               HOSTS / DNS
# =======================================================================================

def flush_dns() -> bool:
    result = subprocess.run(["ipconfig", "/flushdns"],
                            capture_output=True, creationflags=NO_WINDOW)
    return result.returncode == 0


def hosts_status() -> dict:
    """What the launcher wrote into hosts: whether the block is on, and where it points."""
    entries, inside = [], False
    try:
        lines = hosts_switch.read_hosts()
    except OSError as e:
        return {"active": False, "ip": None, "entries": [], "error": str(e)}

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
    return {"active": bool(entries), "ip": ip, "entries": entries, "error": None}


def hosts_on(ip: str) -> dict:
    """Points gosredirector.ea.com at the given address (backup first, then flush DNS)."""
    if not is_admin():
        return {"ok": False, "error": "administrator rights required"}
    if not ip:
        return {"ok": False, "error": "no server address given"}

    try:
        lines = hosts_switch.strip_block(hosts_switch.read_hosts())
        backup = HOSTS.with_suffix(f".turborivals-{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
        shutil.copy2(HOSTS, backup)
        block = [BEGIN, f"{ip}\t{REDIRECTOR}", END]
        HOSTS.write_text("\n".join(lines + block) + "\n", encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"writing hosts failed: {e}"}

    flush_dns()
    return {"ok": True, "backup": str(backup), "ip": ip}


def hosts_off() -> dict:
    """Removes the launcher's block. A leftover entry breaks the EA App and other EA games."""
    if not is_admin():
        return {"ok": False, "error": "administrator rights required"}
    try:
        lines = hosts_switch.read_hosts()
        cleaned = hosts_switch.strip_block(lines)
        if len(cleaned) != len(lines):
            HOSTS.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"writing hosts failed: {e}"}

    flush_dns()
    return {"ok": True}


# =======================================================================================
#                               FIREWALL
# =======================================================================================

def firewall_rules(mode: str) -> dict:
    """Adds the inbound rules for 'host' or 'client' mode (idempotent)."""
    if not is_admin():
        return {"ok": False, "error": "administrator rights required"}

    added = []
    for name, proto, ports in FIREWALL_RULES.get(mode, []):
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={name}"],
                       capture_output=True, creationflags=NO_WINDOW)
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
             "dir=in", "action=allow", f"protocol={proto}", f"localport={ports}"],
            capture_output=True, text=True, creationflags=NO_WINDOW)
        if result.returncode != 0:
            return {"ok": False, "error": f"rule {name}: {(result.stdout or '').strip()}"}
        added.append(f"{name} ({proto} {ports})")
    return {"ok": True, "rules": added}


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


def _addresses_via_socket() -> list[dict]:
    """Fallback when ipconfig is unavailable - no adapter names, so no guessing."""
    found: dict[str, dict] = {}

    def add(ip: str) -> None:
        if ip and not ip.startswith("127."):
            found.setdefault(ip, {"ip": ip, "adapter": "unknown adapter", "kind": "lan"})

    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            add(ip)
    except OSError:
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
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
    found: list[dict] = []
    text = ""
    try:
        raw = subprocess.run(["ipconfig"], capture_output=True,
                             creationflags=NO_WINDOW).stdout
        # 'oem' is the console codepage; only the Polish prose needs it, the
        # adapter names and addresses are ASCII either way.
        text = raw.decode("oem", errors="replace")
    except (OSError, LookupError, ValueError):
        pass

    adapter = ""
    for line in text.splitlines():
        if line.strip() and not line[0].isspace():
            # "Ethernet adapter Radmin VPN:" -> "Radmin VPN"
            adapter = re.sub(r"^.*?adapter\s+", "", line.strip().rstrip(":"), flags=re.I)
        elif "IPv4" in line:
            match = IPV4_RE.search(line)
            if match and not match.group(1).startswith("127."):
                found.append({"ip": match.group(1),
                              "adapter": adapter or "unknown adapter",
                              "kind": _classify_adapter(adapter)})

    if not found:
        found = _addresses_via_socket()

    # Virtual adapters last: they are the only kind nobody else can reach.
    order = {"vpn": 0, "lan": 1, "virtual": 2}
    return sorted(found, key=lambda a: (order.get(a["kind"], 3), a["ip"]))


def suggested_public_ip() -> str:
    """A starting point only - the user picks the adapter in the UI."""
    for addr in local_addresses():
        if addr["kind"] != "virtual":
            return addr["ip"]
    return ""


# =======================================================================================
#                               PLAYERS
# =======================================================================================

class Game:
    """The session's player list. The server cannot learn EA names (the client
    sends nothing but an opaque Origin token), so they are supplied by hand:
    address -> name."""

    def __init__(self, players: list[tuple[str, str]] | None = None):
        self.list_players: list[tuple[str, str]] = list(players or [])

    @property
    def player_count(self) -> int:
        return len(self.list_players)

    def get_player_count(self) -> int:
        return self.player_count

    def get_list_players(self) -> list[tuple[str, str]]:
        return self.list_players

    def addPlayer(self, nick_add: str, ip_add: str) -> bool:
        nick_add, ip_add = nick_add.strip(), ip_add.strip()
        if not nick_add or not ip_add:
            return False
        for ip, nick in self.list_players:
            if ip == ip_add or nick.lower() == nick_add.lower():
                return False
        self.list_players.append((ip_add, nick_add))
        return True

    def removePlayer(self, nick_remove: str) -> bool:
        for player in self.list_players:
            _, nick = player
            if nick == nick_remove:
                self.list_players.remove(player)
                return True
        return False


# =======================================================================================
#                               BLAZE SERVER
# =======================================================================================

SERVER_FLAG = "--run-server"     # app.py dispatches on this when frozen


def build_command(local_name: str, players: list[tuple[str, str]], public_ip: str,
                  entitlements: str = "online",
                  extra: list[str] | None = None) -> list[str]:
    """The server command line. players are (ip, name) tuples.

    Frozen, sys.executable IS this launcher, so running the server means
    re-invoking ourselves behind SERVER_FLAG rather than starting a Python that
    is not installed on the machine.
    """
    if len(players) > MAX_GUESTS:
        raise ValueError(f"too many players: {len(players)} (limit is {MAX_GUESTS} + host)")

    if FROZEN:
        command = [sys.executable, SERVER_FLAG]
    else:
        command = [sys.executable, "-u", str(ROOT / "proto-lab" / "tls_terminator.py")]

    command += ["--entitlements", entitlements,
                "--cert", str(PKI_DIR / "server.der"),
                "--key", str(PKI_DIR / "server.key"),
                "--out", str(CAPTURE_DIR)]
    if public_ip:
        command += ["--public-ip", public_ip]
    if local_name:
        command += ["--local-persona", local_name]
    for ip, nick in players:
        command += ["--player", f"{ip}={nick}"]
    if extra:
        command += extra
    return command


def cert_exists() -> bool:
    return (PKI_DIR / "server.der").exists()


def make_cert() -> dict:
    """Generates the stand-in certificate (once per machine).

    Done in-process: make_stub_cert needs only `cryptography`, which ships with
    the launcher, so there is no interpreter to spawn and nothing to find on
    PATH. It takes about a second (RSA keygen) and runs on the API thread, so
    the UI stays live.
    """
    try:
        make_stub_cert = _load_sibling("make_stub_cert", "proto-lab")
        make_stub_cert.generate(PKI_DIR)
    except Exception as e:                       # keygen, disk, import - all one story
        return {"ok": False, "error": f"certificate generation failed: {e}"}
    return {"ok": True, "output": str(PKI_DIR)}


LOG_FLUSH_INTERVAL = 0.1     # seconds between batches handed to the UI
LOG_QUEUE_LIMIT = 2000       # lines held back before the oldest start dropping


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
    """

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.reader: threading.Thread | None = None
        self.flusher: threading.Thread | None = None
        self.command: list[str] = []
        self.started_at: float | None = None

        self._lines: deque[str] = deque()
        self._lock = threading.Lock()
        self._dropped = 0
        self._finished = threading.Event()
        self._exit_code: int | None = None

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, command: list[str], on_lines, on_exit=None) -> dict:
        if self.is_running():
            return {"ok": False, "error": "the server is already running"}
        if not cert_exists():
            return {"ok": False, "error": "no certificate - generate one first"}

        try:
            self.proc = subprocess.Popen(
                command, cwd=str(ROOT), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", bufsize=1, creationflags=NO_WINDOW)
        except OSError as e:
            self.proc = None
            return {"ok": False, "error": f"could not start the server: {e}"}

        self.command = command
        self.started_at = dt.datetime.now().timestamp()
        proc = self.proc

        self._lines.clear()
        self._dropped = 0
        self._exit_code = None
        self._finished.clear()

        def pump():
            for line in proc.stdout:
                with self._lock:
                    self._lines.append(line.rstrip("\n"))
                    # A burst must never turn into unbounded memory. Losing the
                    # oldest lines beats freezing the window.
                    while len(self._lines) > LOG_QUEUE_LIMIT:
                        self._lines.popleft()
                        self._dropped += 1
            self._exit_code = proc.wait()
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
            if on_exit:
                on_exit(self._exit_code)

        self.reader = threading.Thread(target=pump, daemon=True)
        self.reader.start()
        self.flusher = threading.Thread(target=flush_loop, daemon=True)
        self.flusher.start()
        return {"ok": True, "pid": proc.pid, "command": command}

    def stop(self) -> dict:
        if not self.is_running():
            return {"ok": True, "note": "the server was not running"}
        proc = self.proc
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        return {"ok": True}


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


def ea_offer_ids() -> list[str]:
    """EA App offer ids, read from the game's own installer data.

    <game>\\__Installer\\installerdata.xml lists them as <contentID>; the first
    is the base game (1004776 here, which matches the MultiplayerId the EA App
    reports over LSX). Reading them beats hardcoding an id that would be wrong
    on a different edition.
    """
    game = find_game_dir()
    if game is None:
        return []
    try:
        text = (game / "__Installer" / "installerdata.xml").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return []
    return re.findall(r"<contentID>\s*([^<\s]+)\s*</contentID>", text)


def launch_game() -> dict:
    """Starts Rivals through the EA App.

    Not through Steam. For a Steam-owned copy of this title the Steam route
    brings the game up but Origin then reports it cannot reach its servers -
    it has never worked here. The EA App is what the game expects, and
    `origin2://` is registered by EA Desktop's EALauncher.

    Steam stays as a fallback for a machine with no EA App, where the URI
    would not resolve at all.
    """
    offers = ea_offer_ids()
    if offers:
        try:
            os.startfile(f"origin2://game/launch?offerIds={offers[0]}")
            return {"ok": True, "via": f"EA App (offer {offers[0]})"}
        except OSError:
            pass                                 # no EA App - try Steam below

    try:
        os.startfile(f"steam://rungameid/{STEAM_APP_ID}")
    except OSError as e:
        return {"ok": False, "error": f"could not launch the game: {e}"}
    return {"ok": True, "via": "Steam - no EA App found, online may not work"}


# =======================================================================================
#                               CONFIGURATION
# =======================================================================================

DEFAULT_CONFIG = {
    "mode": "host",
    "local_persona": "",
    "public_ip": "",
    "server_ip": "",
    "entitlements": "online",
    "players": [],
}


def load_config() -> dict:
    config = dict(DEFAULT_CONFIG)
    try:
        config.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return config


def save_config(config: dict) -> dict:
    merged = dict(DEFAULT_CONFIG)
    merged.update({k: v for k, v in config.items() if k in DEFAULT_CONFIG})
    try:
        CONFIG_PATH.write_text(json.dumps(merged, indent=2, ensure_ascii=False),
                               encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}
