"""TurboRivals Launcher - a pywebview window with a HUD interface.

The UI lives in web/ (HTML/CSS/JS in the turbotoster.dev style), all the
logic in commands.py. This Api class is the only bridge between them: every
public method is called from JavaScript as `pywebview.api.<name>()`.

Run it with:
    python launcher/app.py
The hosts file and the firewall rules need administrator rights - without
them the launcher still runs, but those actions report an error and offer to
restart elevated.
"""

from __future__ import annotations

import json
import sys
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
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(line_buffering=True)
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


class Api:
    """Only the public methods below reach JavaScript.

    Every attribute matters: pywebview walks this object with dir() to build
    the JS bridge (util.py get_functions) and recurses into anything public
    that is not callable. A plain `self.window` sends it into the WinForms
    control - `window.native.AccessibilityObject.Bounds.Empty...` until the
    recursion limit - and that walk runs BEFORE pywebviewready fires, so it
    delays startup. Names starting with an underscore are skipped, which is
    why the state below is private.
    """

    def __init__(self):
        self._server = commands.ServerProcess()
        self._game = commands.Game()
        self._window: webview.Window | None = None

    # --- bridge to the UI -------------------------------------------------

    def _emit(self, event: str, payload) -> None:
        """Pushes an event to the page. Also called from the log reader thread."""
        if not self._window:
            return
        try:
            self._window.evaluate_js(
                f"window.TR && window.TR.on({json.dumps(event)}, {json.dumps(payload)})")
        except Exception:
            pass  # window closed mid-flight - the log has nowhere left to go

    # --- state ------------------------------------------------------------

    def get_state(self) -> dict:
        config = commands.load_config()
        self._game = commands.Game([tuple(p) for p in config.get("players", [])])
        return {
            "version": commands.APP_VERSION,
            "admin": commands.is_admin(),
            "ea_app": commands.ea_app_running(),
            "hosts": commands.hosts_status(),
            "cert": commands.cert_exists(),
            "server_running": self._server.is_running(),
            "addresses": commands.local_addresses(),
            "suggested_ip": commands.suggested_public_ip(),
            "max_guests": commands.MAX_GUESTS,
            "config": config,
        }

    def save_config(self, config: dict) -> dict:
        return commands.save_config(config)

    def relaunch_as_admin(self) -> dict:
        if commands.relaunch_as_admin():
            if self._window:
                self._window.destroy()
            return {"ok": True}
        return {"ok": False, "error": "UAC declined"}

    # --- system -----------------------------------------------------------

    def hosts_status(self) -> dict:
        return commands.hosts_status()

    def hosts_on(self, ip: str) -> dict:
        return commands.hosts_on(ip)

    def hosts_off(self) -> dict:
        return commands.hosts_off()

    def firewall_rules(self, mode: str) -> dict:
        return commands.firewall_rules(mode)

    def make_cert(self) -> dict:
        return commands.make_cert()

    def launch_game(self) -> dict:
        return commands.launch_game()

    # --- players ----------------------------------------------------------

    def add_player(self, nick: str, ip: str) -> dict:
        if self._game.player_count >= commands.MAX_GUESTS:
            return {"ok": False, "error": f"limit is {commands.MAX_GUESTS} players + host"}
        if not self._game.addPlayer(nick, ip):
            return {"ok": False, "error": "empty entry, or that name/address is already listed"}
        return {"ok": True, "players": self._game.get_list_players()}

    def remove_player(self, nick: str) -> dict:
        self._game.removePlayer(nick)
        return {"ok": True, "players": self._game.get_list_players()}

    def get_players(self) -> list:
        return self._game.get_list_players()

    # --- server -----------------------------------------------------------

    def start_server(self, local_name: str, public_ip: str, entitlements: str) -> dict:
        try:
            command = commands.build_command(
                local_name, self._game.get_list_players(), public_ip, entitlements)
        except ValueError as e:
            return {"ok": False, "error": str(e)}

        # One evaluate_js per batch of lines, not per line - see ServerProcess.
        return self._server.start(
            command,
            on_lines=lambda lines: self._emit("log", lines),
            on_exit=lambda code: self._emit("server-exit", code),
        )

    def stop_server(self) -> dict:
        return self._server.stop()

    # --- window -----------------------------------------------------------

    def minimize(self) -> None:
        if self._window:
            self._window.minimize()

    def close(self) -> None:
        self._server.stop()
        if self._window:
            self._window.destroy()


def main() -> int:
    api = Api()
    window = webview.create_window(
        "TurboRivals Launcher",
        str(WEB_DIR / "index.html"),
        js_api=api,
        # Sized for a 14" laptop: at 150% scaling its working area is about
        # 1280x680 logical pixels, so the old 780 height could never fit.
        width=1000,
        height=620,
        min_size=(880, 560),
        background_color="#0b1026",
        frameless=True,
        easy_drag=False,
    )
    api._window = window
    try:
        webview.start(debug="--debug" in sys.argv)
    except Exception as error:
        # The window IS WebView2, so there is nothing left to draw an error in.
        # Without this the launcher would just fail to appear, which is a bad
        # thing to hand to someone else.
        #
        # Name the actual cause rather than guessing. An earlier version blamed
        # WebView2 for every startup failure and sent us hunting in the wrong
        # place for half an hour, while the real message underneath said
        # Python.Runtime.
        import ctypes

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

        ctypes.windll.user32.MessageBoxW(
            None,
            f"TurboRivals could not open its window.\n\n{advice}\n\nDetails: {error}",
            "TurboRivals", 0x10)
        api._server.stop()
        return 1

    api._server.stop()          # never leave the server behind once the window is gone
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
