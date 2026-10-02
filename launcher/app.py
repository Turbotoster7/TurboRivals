"""TurboRivals Launcher - a pywebview window with an HTML interface.

The UI lives in web/ (HTML/CSS/JS), all the logic in commands.py. This Api
class is the only bridge between them: every public method is called from
JavaScript as `pywebview.api.<name>()`, and Python pushes events back with
`window.TR.on(event, payload)`.

Run it with:
    python launcher/app.py
The hosts file and the firewall rules need administrator rights - without
them the launcher still runs, but those actions report an error and offer to
restart elevated.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# --- server mode -------------------------------------------------------------
# Packaged as one exe, sys.executable is THIS program, so the launcher starts
# the Blaze server by re-invoking itself behind --run-server (see
# commands.build_command). Handled before webview is imported: the server has
# no use for a GUI toolkit, and this path also runs when no display exists.
if "--run-server" in sys.argv:
    def _serve() -> int:
        # Line buffering, or the log panel stays empty. Writing to a pipe is
        # block-buffered by default, and a frozen exe cannot be handed -u, so
        # the server's output would sit in a few-kilobyte buffer while the
        # session is in progress - exactly when it needs reading.
        # UTF-8 because that is how ServerProcess reads the pipe; left at the console
        # codepage, one character outside it (a player's name) raised in print().
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass                             # windowed build with no stdio

        try:
            import tls_terminator
        except ImportError:                      # running from the repo
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "proto-lab"))
            import tls_terminator
        cut = sys.argv.index("--run-server")
        sys.argv = ["tls_terminator.py"] + sys.argv[cut + 1:]
        return tls_terminator.main()

    raise SystemExit(_serve())

# Same idea for the certificate: usable without opening the window, which is
# what makes the packaged build testable without driving the UI.
if "--make-cert" in sys.argv:
    import commands as _commands

    _result = _commands.make_cert()
    print(_result.get("output") or _result.get("error"))
    raise SystemExit(0 if _result["ok"] else 1)

# Used by the uninstaller. Removing the launcher while the redirect is still on
# would leave a hosts entry that breaks the EA App and every other EA game -
# with the tool for undoing it just deleted.
if "--hosts-off" in sys.argv:
    import commands as _commands

    _result = _commands.hosts_off()
    print("hosts restored" if _result["ok"] else _result["error"])
    raise SystemExit(0 if _result["ok"] else 1)

import webview  # noqa: E402
import commands  # noqa: E402

WEB_DIR = Path(__file__).resolve().parent / "web"
EMIT_TIMEOUT = 5            # seconds an event may take to reach the page

# --self-test opens the window and reads this from the page until it holds: drawn past
# "booting" (get_snapshot answered), the version from Python on screen, no check left pending
# (the probes Python pushed arrived) - and the script errors app.js caught on the way. The
# performance marks app.js sets say when each of those happened, in ms after `origin` (epoch ms).
SELF_TEST_TIMEOUT = 60
SELF_TEST_JS = """(() => {
    const marks = {};
    for (const mark of performance.getEntriesByType('mark')) {
        if (!(mark.name in marks)) marks[mark.name] = Math.round(mark.startTime);
    }
    const page = performance.getEntriesByType('navigation')[0];
    return {
        booted: !document.body.classList.contains('booting'),
        version: document.getElementById('appVersion').textContent,
        pending: [...document.querySelectorAll('#checkList .check:not([hidden])')]
            .filter((row) => !row.dataset.status || row.dataset.status === 'pending').length,
        errors: state.activity.filter((entry) => entry.level === 'error').map((entry) => entry.text),
        size: [window.innerWidth, window.innerHeight],
        screen: [screen.availWidth, screen.availHeight],
        origin: performance.timeOrigin,
        marks: { ...marks, loaded: Math.round(page ? page.domContentLoadedEventEnd : 0) },
    };
})()"""

# The slow questions, each answered on its own thread and pushed to the page as it lands
# (event "probe"), so the window is usable at once instead of after the slowest of them.
PROBES = ("processes", "addresses", "save", "firewall", "ports")
FOLDERS = {
    "logs": lambda: commands.LOG_DIR,
    "data": lambda: commands.USER_DIR,
    "save-backups": lambda: commands.SAVE_BACKUP_DIR,
    "saves": lambda: commands.ea_identity.saves_dir(),
}


class Api:
    """Only the public methods below reach JavaScript.

    Every attribute matters: pywebview walks this object with dir() to build
    the JS bridge (util.py get_functions) and recurses into anything public
    that is not callable. A plain `self.window` sends it into the WinForms
    control - `window.native.AccessibilityObject.Bounds.Empty...` until the
    recursion limit - and that walk runs BEFORE pywebviewready fires, so it
    delays startup. Names starting with an underscore are skipped, which is
    why the state below is private.

    pywebview runs every call on a thread of its own, so two calls can overlap:
    the config file and the player list are only touched under _lock.
    """

    def __init__(self):
        self._server = commands.ServerProcess()
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._first_run = not commands.config_exists()
        self._game = commands.Game(commands.load_config()["players"])
        self._window: webview.Window | None = None

    # --- bridge to the UI -------------------------------------------------

    def _emit(self, event: str, payload) -> None:
        """Pushes an event to the page. Also called from worker and log threads.

        evaluate_js waits for the page to answer, and once the window is gone nothing ever
        does: a probe still in flight at closing time blocked forever, and since pywebview and
        the probe pool join their threads at exit, the launcher process never ended. So nothing
        is sent after closing, and the call runs on a daemon thread with a time limit."""
        if not self._window or self._closed.is_set():
            return
        script = f"window.TR && window.TR.on({json.dumps(event)}, {json.dumps(payload)})"
        sender = threading.Thread(target=self._evaluate, args=(script,), daemon=True)
        sender.start()
        sender.join(EMIT_TIMEOUT)

    def _evaluate(self, script: str) -> None:
        try:
            self._window.evaluate_js(script)
        except Exception:
            pass  # window closed mid-flight - the event has nowhere left to go

    def _mark_closed(self, *_args) -> None:
        self._closed.set()

    def _window_hidden(self, hidden: bool) -> None:
        """Minimized or restored: the page stops polling and drawing while nobody looks. Window
        events arrive on the GUI thread, which evaluate_js needs itself - so not from here."""
        threading.Thread(target=self._emit, args=("window", {"hidden": hidden}), daemon=True).start()

    def _update_config(self, **changes) -> dict:
        with self._lock:
            result = commands.save_config(changes)
        return result.get("config") or commands.load_config()

    # --- state ------------------------------------------------------------

    def get_snapshot(self) -> dict:
        """Everything that is quick to know - no child process, no network. The rest
        follows through refresh()."""
        config = commands.load_config()
        return {
            "version": commands.APP_VERSION,
            "windows": commands.IS_WINDOWS,
            "frozen": bool(commands.FROZEN),
            "first_run": self._first_run and not config["onboarded"],
            "config": config,
            "players": self._game.get_list_players(),
            "max_guests": commands.MAX_GUESTS,
            "admin": commands.is_admin(),
            "can_edit_hosts": commands.can_edit_hosts(),
            "hosts": commands.hosts_status(),
            "cert": commands.cert_exists(),
            "server": self._server.status(),
            "avatar": commands.load_avatar(),
            "firewall_rules": commands.FIREWALL_RULES,
            "server_ports": [{"proto": p, "port": n, "purpose": what}
                             for p, n, what in commands.SERVER_PORTS],
            "redirector": commands.REDIRECTOR,
            "project_url": commands.PROJECT_URL,
        }

    def refresh(self, names: list | None = None) -> dict:
        """Runs the slow probes in parallel. Each result goes to the page the moment it is in
        (event "probe"); the full set is also the return value."""
        wanted = [n for n in (names or PROBES) if n in PROBES]
        mode = commands.load_config()["mode"]

        def addresses():
            found = commands.local_addresses()
            return {"list": found, "suggested": commands.suggested_public_ip(found)}

        jobs = {
            "processes": commands.process_status,
            "addresses": addresses,
            "save": commands.save_identity,
            "firewall": lambda: commands.firewall_status(mode),
            "ports": self._ports,
        }
        results = {"hosts": commands.hosts_status(), "admin": commands.is_admin()}
        if not wanted:
            return results
        with ThreadPoolExecutor(max_workers=len(wanted)) as pool:
            futures = {pool.submit(jobs[name]): name for name in wanted}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    value = future.result()
                except Exception as e:               # noqa: BLE001 - one probe, not the window
                    value = {"error": str(e)}
                results[name] = value
                self._emit("probe", {"name": name, "value": value})
        return results

    def _ports(self) -> dict:
        if self._server.is_running():
            return {"ok": True, "server": True, "ports": []}
        return commands.port_status()

    def save_config(self, changes: dict) -> dict:
        """Partial update: only the keys given change."""
        if not isinstance(changes, dict):
            return {"ok": False, "error": "expected an object"}
        changes = {k: v for k, v in changes.items() if k != "players"}
        return {"ok": True, "config": self._update_config(**changes)}

    def relaunch_as_admin(self) -> dict:
        if commands.relaunch_as_admin():
            self.close()
            return {"ok": True}
        return {"ok": False, "error": "UAC declined" if commands.IS_WINDOWS
                else "restarting elevated is a Windows feature"}

    # --- system -----------------------------------------------------------

    def hosts_status(self) -> dict:
        return commands.hosts_status()

    def hosts_on(self, ip: str) -> dict:
        result = commands.hosts_on(ip)
        result["status"] = commands.hosts_status()
        return result

    def hosts_off(self) -> dict:
        result = commands.hosts_off()
        result["status"] = commands.hosts_status()
        return result

    def resolved_redirector(self) -> list:
        return commands.resolved_redirector()

    def firewall_status(self, mode: str) -> dict:
        return commands.firewall_status(mode)

    def firewall_rules(self, mode: str) -> dict:
        return commands.firewall_rules(mode)

    def check_ports(self) -> dict:
        return self._ports()

    def make_cert(self) -> dict:
        return commands.make_cert()

    def launch_game(self) -> dict:
        return commands.launch_game()

    def identify(self, server_ip: str, name: str = "") -> dict:
        """Before a guest's game starts: back its saves up, then tell the host which one the
        game loads and the player's name - see commands.identify_to_host."""
        backup = commands.backup_saves()
        result = commands.identify_to_host(server_ip, name)
        result["backup"] = backup
        if result.get("ok"):
            config = commands.load_config()
            self._update_config(server_ip=server_ip.strip(), local_persona=(name or "").strip(),
                                recent_servers=commands.remember_server(config, server_ip.strip()))
        return result

    def test_host(self, server_ip: str) -> dict:
        return commands.test_host(server_ip)

    # --- picture and ONLINE NOW -------------------------------------------

    def save_avatar(self, png_url: str, jpg_url: str = "") -> dict:
        return commands.save_avatar(png_url, jpg_url)

    def upload_avatar(self, server_ip: str) -> dict:
        return commands.upload_avatar(server_ip)

    def fetch_players(self, server_ip: str) -> dict:
        return commands.fetch_players(server_ip)

    # --- players ----------------------------------------------------------

    def add_player(self, nick: str, ip: str) -> dict:
        with self._lock:
            problem = self._game.check(nick, ip)
            if problem:
                return {"ok": False, "error": problem, "players": self._game.get_list_players()}
            self._game.add_player(nick, ip)
            players = self._game.get_list_players()
            commands.save_config({"players": players})
        return {"ok": True, "players": players}

    def remove_player(self, nick: str) -> dict:
        with self._lock:
            self._game.remove_player(nick)
            players = self._game.get_list_players()
            commands.save_config({"players": players})
        return {"ok": True, "players": players}

    def get_players(self) -> list:
        return self._game.get_list_players()

    # --- server -----------------------------------------------------------

    def start_server(self, local_name: str, public_ip: str, entitlements: str = "online") -> dict:
        name = commands.clean_name(local_name)
        if not name:
            return {"ok": False, "error": "enter your name - the server stores progress under it"}
        public_ip = (public_ip or "").strip()
        if public_ip and not commands.valid_ipv4(public_ip):
            return {"ok": False, "error": f"\"{public_ip}\" is not an IPv4 address"}
        if self._server.is_running():
            return {"ok": False, "error": "the server is already running"}
        if not commands.cert_exists():
            return {"ok": False, "error": "no certificate - generate one first", "needs_cert": True}
        # Checked here, not left to the server: it would refuse too, but only after the window
        # had already said "server up", and without naming the program in the way.
        ports = commands.port_status()
        if not ports["ok"]:
            return {"ok": False, "ports": ports,
                    "error": "the server cannot start: " + commands.describe_blocked(ports["ports"])}

        # The server picks the host's save id by itself (ea_identity) - back the saves up first.
        commands.backup_saves()
        try:
            command = commands.build_command(
                name, self._game.get_list_players(), public_ip, entitlements,
                capture=commands.load_config()["keep_captures"])
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        self._update_config(local_persona=(local_name or "").strip(), public_ip=public_ip)

        # One evaluate_js per batch of lines, not per line - see ServerProcess.
        return self._server.start(
            command,
            on_lines=lambda lines: self._emit("log", lines),
            on_exit=lambda code: self._emit(
                "server-exit", {"code": code, "requested": self._server.stop_requested}),
        )

    def stop_server(self) -> dict:
        return self._server.stop()

    def server_status(self) -> dict:
        return self._server.status()

    # --- help -------------------------------------------------------------

    def diagnostics(self) -> dict:
        return commands.diagnostics(commands.load_config(), self._server.status())

    def open_folder(self, kind: str) -> dict:
        if kind not in FOLDERS:
            return {"ok": False, "error": f"unknown folder {kind!r}"}
        return commands.open_folder(FOLDERS[kind](), create=kind != "saves")

    def open_url(self, url: str) -> dict:
        return commands.open_url(url)

    # --- window -----------------------------------------------------------

    def minimize(self) -> None:
        if self._window:
            self._window.minimize()

    def quit(self, restore_hosts: bool = False) -> dict:
        """Closes the launcher; with restore_hosts, takes the redirect down first. A failed
        restore keeps the window open, so the player still has the button to retry."""
        if restore_hosts:
            result = commands.hosts_off()
            if not result["ok"]:
                return result
        self.close()
        return {"ok": True}

    def close(self) -> None:
        self._closed.set()
        self._server.stop()
        if self._window:
            self._window.destroy()


def _self_test(window: webview.Window, outcome: dict) -> None:
    """--self-test, on pywebview's worker thread: waits for the page to be ready, prints what it
    found as one JSON line and closes the window. How CI knows the packaged build works -
    WebView2, the bundled page and pythonnet included - and how long it took to get there."""
    started = time.monotonic()
    report: dict = {}
    while time.monotonic() - started < SELF_TEST_TIMEOUT:
        try:
            report = window.evaluate_js(SELF_TEST_JS) or {}
        except Exception as error:               # the page is not there yet
            report = {"error": str(error)}
        marks = report.get("marks") or {}
        if (report.get("booted") and report.get("pending") == 0
                and all(f"probe {name}" in marks for name in PROBES)):
            break
        time.sleep(0.2)
    report["ready_at"] = time.time()
    report["ok"] = bool(report.get("booted") and report.get("pending") == 0
                        and not report.get("errors")
                        and report.get("version") == f"v{commands.APP_VERSION}")
    outcome.update(report)
    print("self-test: " + json.dumps(report), flush=True)
    window.destroy()


def _fit_frameless(window: webview.Window) -> None:
    """pywebview sizes a frameless window while it still has its frame, then drops the frame and
    keeps the client area: on Windows the window came out 16x39 px short (1084x641 for 1100x680).
    Runs on before_show - on the GUI thread, before the window is placed - so it opens at the
    size asked for, centred."""
    form = window.native
    try:
        import ctypes
        from System.Drawing import Size          # pythonnet, there with pywebview's WinForms

        scale = ctypes.windll.user32.GetDpiForWindow(form.Handle.ToInt32()) / 96
        form.Size = Size(int(window.initial_width * scale), int(window.initial_height * scale))
    except Exception:
        pass                                     # keeps pywebview's own size


def _webview_storage() -> dict:
    """A WebView2 profile that stays. In private mode pywebview makes a new one in %TEMP% on every
    start, and on closing hides the window, waits for the browser process to end and deletes the
    profile - so TurboRivals.exe lingered after its window was gone. The page keeps nothing there;
    the launcher's state is config.json. Should the folder not be creatable, private mode it is."""
    folder = commands.USER_DIR / "webview"
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        return {}
    return {"private_mode": False, "storage_path": str(folder)}


def main() -> int:
    self_test = "--self-test" in sys.argv
    outcome: dict = {}
    api = Api()
    window = webview.create_window(
        "TurboRivals Launcher",
        # A file URL: given a path, pywebview serves web/ through an HTTP server of its own - on
        # a random port in private mode, on the fixed 42001 otherwise, which another program
        # (or another pywebview app) may already hold.
        (WEB_DIR / "index.html").as_uri(),
        js_api=api,
        # Sized for a 14" laptop: at 150% scaling its working area is about
        # 1280x680 logical pixels, so the height may not exceed 680.
        width=1100,
        height=680,
        min_size=(900, 580),
        background_color="#111214",   # --bg in style.css, so the first frame matches the page
        frameless=True,
        easy_drag=False,
    )
    api._window = window
    if commands.IS_WINDOWS:
        window.events.before_show += _fit_frameless
    window.events.closed += api._mark_closed     # also when closed by Alt+F4 or the taskbar
    window.events.minimized += lambda *_: api._window_hidden(True)
    window.events.restored += lambda *_: api._window_hidden(False)
    try:
        if self_test:
            webview.start(_self_test, (window, outcome), **_webview_storage())
        else:
            webview.start(debug="--debug" in sys.argv, **_webview_storage())
    except Exception as error:
        # The window IS WebView2, so there is nothing left to draw an error in.
        # Without this the launcher would just fail to appear, which is a bad
        # thing to hand to someone else.
        #
        # Name the actual cause rather than guessing. An earlier version blamed
        # WebView2 for every startup failure and sent us hunting in the wrong
        # place for half an hour, while the real message underneath said
        # Python.Runtime.
        text = str(error)
        if any(hint in text for hint in ("Python.Runtime", "clr_loader", "pythonnet")):
            # .NET refuses to load an assembly carrying Mark-of-the-Web, which
            # every file extracted from a downloaded archive inherits. Installing
            # through the setup avoids it: Inno writes the files fresh.
            advice = (
                "Its files are blocked because they came out of a downloaded "
                "archive, so Windows will not let .NET load them.\n\n"
                "Either install with TurboRivalsSetup.exe, or unblock the folder "
                "in PowerShell:\n"
                "    Get-ChildItem -Recurse <folder> | Unblock-File")
        else:
            advice = (
                "It needs the Microsoft Edge WebView2 Runtime. Windows 11 has it "
                "built in, but an older Windows 10 may not - it is a free download "
                "from Microsoft (\"Evergreen WebView2 Runtime\").")

        message = f"TurboRivals could not open its window.\n\n{advice}\n\nDetails: {error}"
        if commands.IS_WINDOWS and not self_test:    # a message box would hold CI until it times out
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, "TurboRivals", 0x10)
        else:
            print(message, file=sys.stderr)
        api._server.stop()
        return 1

    api._server.stop()          # never leave the server behind once the window is gone
    if self_test:
        print("self-test closed: " + json.dumps({"at": time.time()}), flush=True)
        return 0 if outcome.get("ok") else 1
    return 0


def _leave(code: int) -> None:
    """Ends the process without waiting for other threads. pywebview answers every JS call on
    a non-daemon thread of its own, and one finishing while the window is torn down can wait
    forever for a page that is gone (seen on GTK: the process outlived its window). A stray
    launcher would keep TurboRivals.exe locked for the uninstaller. By now the server is
    stopped and everything worth keeping is written (config and pictures atomically)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream:
                stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(code)


if __name__ == "__main__":
    _leave(main())
