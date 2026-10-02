"""The server command line the launcher builds, its config, the cleanup of old frames and the
per-run log file - installed (frozen) versus run from source. Only a tiny Python child is started
(the log test), never the server or the game."""
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "launcher"))

import commands  # noqa: E402


class ServerCommandTests(unittest.TestCase):
    def setUp(self):
        # The developer's own launcher/config.json must not leak into the command.
        patch = mock.patch.object(commands, "load_config", lambda: dict(commands.DEFAULT_CONFIG))
        patch.start()
        self.addCleanup(patch.stop)

    def test_installed_launcher_saves_no_frames(self):
        with mock.patch.object(commands, "FROZEN", True):
            self.assertIn("--no-capture", commands.build_command("Host", [], "26.1.2.3"))

    def test_source_run_keeps_capturing(self):
        # the setting starts on when run from source, off in the packaged launcher (the frames
        # hold the EA auth code); the launcher passes it as `capture`
        self.assertEqual(commands.DEFAULT_CONFIG["keep_captures"], not commands.FROZEN)
        self.assertNotIn("--no-capture", commands.build_command("Host", [], "26.1.2.3", capture=True))

    def test_server_args_from_config_come_last(self):
        config = dict(commands.DEFAULT_CONFIG, server_args=["--session-bps", 100000])
        with mock.patch.object(commands, "load_config", lambda: config):
            command = commands.build_command("Host", [], "26.1.2.3")
        self.assertEqual(command[-2:], ["--session-bps", "100000"])

    def test_old_frames_go_only_when_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp)
            (capture / "blaze-120000-001-01.bin").write_bytes(b"frame")
            (capture / "notes.txt").write_text("keep")
            with mock.patch.object(commands, "CAPTURE_DIR", capture):
                with mock.patch.object(commands, "FROZEN", False):
                    self.assertEqual(commands.purge_captures(), 0)
                with mock.patch.object(commands, "FROZEN", True):
                    self.assertEqual(commands.purge_captures(), 1)
            self.assertEqual([p.name for p in capture.iterdir()], ["notes.txt"])


class ConfigTests(unittest.TestCase):
    def test_saving_from_the_ui_keeps_hand_written_server_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"mode": "host", "server_args": ["--session-bps", "100000"]}))
            with mock.patch.object(commands, "CONFIG_PATH", path):
                self.assertTrue(commands.save_config({"mode": "client", "public_ip": "26.1.2.3"})["ok"])
                saved = json.loads(path.read_text())
        self.assertEqual(saved["mode"], "client")
        self.assertEqual(saved["server_args"], ["--session-bps", "100000"])


class LogFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.logs = Path(tmp.name) / "logs"
        patch = mock.patch.object(commands, "LOG_DIR", self.logs)
        patch.start()
        self.addCleanup(patch.stop)

    def test_every_line_of_a_run_goes_to_its_file(self):
        server = commands.ServerProcess()
        shown, done = [], threading.Event()
        with mock.patch.object(commands, "cert_exists", lambda: True):
            result = server.start([sys.executable, "-u", "-c", "print('hello'); print('world')"],
                                  on_lines=shown.extend, on_exit=lambda code: done.set())
        self.assertTrue(result["ok"], result)
        self.assertTrue(done.wait(10), "the child did not finish")
        text = server.log_path.read_text(encoding="utf-8")
        # the version and the command line first: a log attached to a bug report says which
        # build ran and with which flags (server_args)
        self.assertTrue(text.startswith(f"# TurboRivals {commands.APP_VERSION}"), text[:200])
        self.assertIn(" -c ", text.splitlines()[1])
        self.assertIn("hello\nworld\n", text)
        self.assertEqual(shown, ["hello", "world"])                 # the window still gets them

    def test_twenty_runs_are_kept(self):
        self.assertEqual(commands.LOGS_KEPT, 20)                    # readme, since 1.0.9


if __name__ == "__main__":
    unittest.main()
