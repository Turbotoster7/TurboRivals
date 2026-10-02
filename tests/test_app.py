"""The Api object behind the window (launcher/app.py), without a window. Needs pywebview."""
import support  # noqa: F401

import threading
import time
import unittest
from unittest import mock

try:
    import app
except ImportError as e:                         # no pywebview on this machine
    app = None
    REASON = str(e)


class BlockingWindow:
    """evaluate_js the way a destroyed window behaves: the answer never comes."""

    def __init__(self):
        self.calls = 0
        self.forever = threading.Event()

    def evaluate_js(self, script):
        self.calls += 1
        self.forever.wait()


@unittest.skipIf(app is None, "pywebview is not installed")
class Emit(unittest.TestCase):
    def test_a_dead_window_cannot_hang_the_caller(self):
        api = app.Api()
        api._window = BlockingWindow()
        started = time.monotonic()
        with mock.patch.object(app, "EMIT_TIMEOUT", 0.3):
            api._emit("probe", {"name": "processes", "value": {}})
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(api._window.calls, 1)

    def test_nothing_is_sent_after_closing(self):
        api = app.Api()
        api._window = BlockingWindow()
        api._mark_closed()
        api._emit("log", ["line"])
        self.assertEqual(api._window.calls, 0)


@unittest.skipIf(app is None, "pywebview is not installed")
class Players(unittest.TestCase):
    def setUp(self):
        app.commands.CONFIG_PATH.unlink(missing_ok=True)

    def test_list_is_kept_in_python_and_saved(self):
        api = app.Api()
        self.assertTrue(api.add_player("Kowal_PL", "26.11.40.7")["ok"])
        refused = api.add_player("Kowal_PL", "26.11.40.8")
        self.assertFalse(refused["ok"])
        self.assertIn("already listed", refused["error"])
        self.assertEqual(app.commands.load_config()["players"], [["26.11.40.7", "Kowal_PL"]])
        # the page cannot overwrite it through save_config
        api.save_config({"players": [], "mode": "client"})
        self.assertEqual(app.commands.load_config()["players"], [["26.11.40.7", "Kowal_PL"]])
        self.assertEqual(app.Api().get_players(), [("26.11.40.7", "Kowal_PL")])

    def test_the_games_save_folder_is_never_created(self):
        api = app.Api()
        saves = app.commands.ea_identity.saves_dir()
        if saves.exists():
            self.skipTest("this machine has a real save folder")
        result = api.open_folder("saves")
        self.assertFalse(result["ok"])
        self.assertFalse(saves.exists())
        self.assertFalse(api.open_folder("nonsense")["ok"])

    def test_start_server_refuses_bad_input_before_anything_runs(self):
        api = app.Api()
        self.assertIn("name", api.start_server("名前", "26.48.21.54")["error"])
        self.assertIn("IPv4", api.start_server("Host", "26.48.21")["error"])


if __name__ == "__main__":
    unittest.main()
