"""The real server (proto-lab/tls_terminator.py) started the way the launcher starts it, then
driven by the launcher's own functions and by a fake game client (fake_game.py).

Needs the server's ports free (TCP 42127, 14219, 17502, UDP 17502-17503); skipped otherwise."""
import support

import base64
import json
import socket
import threading
import time
import unittest
from unittest import mock

import commands
from test_commands import tiny_png

PORTS = [(proto, port) for proto, port, _ in commands.SERVER_PORTS]
FAKE_IDENTITY = {"id": 1006400012345, "source": "EA App profile", "user": 1012900012345,
                 "persona": "Tester", "saves": [1006400012345]}


def loopback_alias_works(ip: str) -> bool:
    """Linux routes all of 127/8 to lo; Windows and macOS need it configured."""
    s = socket.socket()
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


@unittest.skipUnless(support.ports_free(*PORTS), "the server's ports are in use on this machine")
class LiveServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import fake_game  # noqa: F401  (needs the server modules importable)
        except ImportError as e:                # pragma: no cover
            raise unittest.SkipTest(f"server modules not importable: {e}")
        if not commands.cert_exists():
            result = commands.make_cert()
            if not result["ok"]:
                raise unittest.SkipTest(result["error"])
        cls.lines: list[str] = []
        cls.lock = threading.Lock()
        cls.server = commands.ServerProcess()

        def collect(batch):
            with cls.lock:
                cls.lines.extend(batch)

        # --local-id: what the server's own ea_identity lookup finds on a host with the EA App;
        # without it the host's picture has no uid to be filed under.
        command = commands.build_command("HostPlayer", [], "127.0.0.1",
                                         extra=["--local-id", str(FAKE_IDENTITY["id"])])
        started = cls.server.start(command, on_lines=collect)
        assert started["ok"], started
        if not cls.wait_for("(redirector)", timeout=20):
            cls.server.stop()
            raise AssertionError("server did not come up:\n" + "\n".join(cls.lines))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    @classmethod
    def wait_for(cls, text: str, timeout: float = 10, after: int = 0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with cls.lock:
                if any(text in line for line in cls.lines[after:]):
                    return True
            time.sleep(0.05)
        return False

    def mark(self) -> int:
        with self.lock:
            return len(self.lines)

    def test_startup_lines_are_whole(self):
        with self.lock:
            lines = list(self.lines)
        listening = [line for line in lines if "listening on" in line]
        self.assertEqual(len(listening), 5, listening)       # 42127, 14219, UDP 17502/17503, TCP 17502
        self.assertTrue(all(line.rstrip().endswith(")") for line in listening), listening)
        self.assertTrue(any(line.startswith("handing the game this Blaze address") for line in lines))

    def test_a_silent_client_does_not_hold_up_the_others(self):
        # Before: QoS HTTP answered one connection after the other, so this one held up every
        # launcher request (and the game's QoS) for its 5 s timeout.
        silent = socket.create_connection(("127.0.0.1", 17502))
        try:
            time.sleep(0.2)
            started = time.perf_counter()
            result = commands.test_host("127.0.0.1")
            took = time.perf_counter() - started
        finally:
            silent.close()
        self.assertTrue(result["ok"], result)
        self.assertLess(took, 1.5)

    def test_qos_udp_keeps_answering_after_a_probe_socket_closed(self):
        # On Windows the reply to a closed socket comes back as ICMP port unreachable and the
        # next recvfrom raises WSAECONNRESET - which used to end the QoS responder for everyone.
        # A burst, then gone: the server is still replying when the socket closes, so replies
        # really do hit a closed port (one probe alone was usually answered before the close).
        first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(50):
            first.sendto(bytes(20), ("127.0.0.1", 17502))
        first.close()
        time.sleep(0.6)
        second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        second.settimeout(3)
        try:
            for _ in range(3):                         # UDP: give a lost datagram another go
                second.sendto(bytes(20), ("127.0.0.1", 17502))
                try:
                    reply, _ = second.recvfrom(4096)
                    break
                except (socket.timeout, ConnectionResetError):   # reset: port 17502 is closed
                    reply = b""
        finally:
            second.close()
        self.assertEqual(len(reply), 30, "the QoS UDP responder stopped answering")

    def test_speed_walls_survive_a_corrupt_stats_file(self):
        import blaze
        import fake_game

        data = support.HOME / "data"
        (data / "stats").mkdir(parents=True, exist_ok=True)
        (data / "reports").mkdir(parents=True, exist_ok=True)
        (data / "reports" / "424242.jsonl").write_text(json.dumps(
            {"t": 1, "category": "SpeedCameras", "entity": 777, "int": {}, "float": {"Speed": 251.0},
             "str": {}}) + "\n", encoding="utf-8")
        (data / "stats" / "424242.json").write_text("", encoding="utf-8")   # cut short
        start = self.mark()
        game = fake_game.FakeGame("127.0.0.1", 14219, commands.PKI_DIR / "server.key", "127.0.0.5")
        try:
            game.rpc(9, 7)
            game.rpc(1, 152)
            walls = game.rpc(2050, 20, blaze.encode_tdf([blaze.f_list_int("SWIS", [777])]))
            self.assertEqual(walls.error, 0)
            self.assertEqual(game.rpc(9, 2).error, 0)                    # still connected
        finally:
            game.close()
        self.assertTrue(self.wait_for("[speed wall] 777: 1 row(s)", after=start),
                        "\n".join(self.lines[start:]))
        self.assertTrue(self.wait_for("stats/424242.json was unreadable", after=start))

    def test_no_capture_files_by_default(self):
        self.assertFalse(list((support.HOME / "capture").glob("*")) if (support.HOME / "capture").exists() else [])

    def test_test_host_reports_a_live_server(self):
        result = commands.test_host("127.0.0.1")
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(result["ms"], 0)

    def test_identify_and_picture(self):
        start = self.mark()
        with mock.patch.object(commands, "save_identity", return_value=dict(FAKE_IDENTITY)):
            result = commands.identify_to_host("127.0.0.1", "Łukasz")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.wait_for("launcher: name Lukasz, save id 1006400012345", after=start))

        png = "data:image/png;base64," + base64.b64encode(tiny_png()).decode()
        self.assertTrue(commands.save_avatar(png)["ok"])
        uploaded = commands.upload_avatar("127.0.0.1")
        self.assertTrue(uploaded["ok"], uploaded)
        self.assertTrue(self.wait_for("[avatar] 127.0.0.1: picture of uid", after=start))

    def test_ports_are_reported_taken_while_it_runs(self):
        status = commands.port_status()
        self.assertFalse(status["ok"])
        self.assertTrue(all(not p["free"] for p in status["ports"]))

    def test_game_that_never_logs_in_gets_a_hint(self):
        import fake_game

        source = "127.0.0.2"
        if not loopback_alias_works(source):
            self.skipTest("no 127.0.0.2 on this system")
        start = self.mark()
        game = fake_game.FakeGame("127.0.0.1", 14219, commands.PKI_DIR / "server.key", source)
        reply = game.rpc(9, 7)                              # Util.preAuth
        self.assertEqual(reply.error, 0)
        game.rpc(9, 2)                                      # Util.ping
        game.close()                                        # ...and gone, like a game without a token
        self.assertTrue(self.wait_for(f"[hint] {source}: the game connected but never logged in",
                                      after=start), "\n".join(self.lines[start:]))

    def test_logged_in_game_shows_in_online_now_and_gets_no_hint(self):
        import fake_game

        source = "127.0.0.3"
        if not loopback_alias_works(source):
            self.skipTest("no 127.0.0.3 on this system")
        start = self.mark()
        game = fake_game.FakeGame("127.0.0.1", 14219, commands.PKI_DIR / "server.key", source)
        game.rpc(9, 7)
        login = game.rpc(1, 152)                            # Authentication.originLogin
        self.assertEqual(login.error, 0)
        try:
            deadline, names = time.time() + 5, []
            while time.time() < deadline:
                online = commands.fetch_players("127.0.0.1")
                self.assertTrue(online["ok"], online)
                names = [p["name"] for p in online["players"]]
                if names:
                    break
                time.sleep(0.2)
            self.assertTrue(names, "nobody in ONLINE NOW after a login")
        finally:
            game.close()
        self.assertTrue(self.wait_for("client closed the connection", after=start))
        time.sleep(0.3)
        with self.lock:
            hints = [line for line in self.lines[start:] if f"[hint] {source}" in line]
        self.assertEqual(hints, [])


if __name__ == "__main__":
    unittest.main()
