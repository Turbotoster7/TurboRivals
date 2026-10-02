"""Server parts without a running server: the listener loops, progress storage, players.json."""
import support

import errno
import json
import unittest
from pathlib import Path

import lobby
import player_store
import tls_terminator


class FakeSocket:
    """Plays back a script of results for accept()/recvfrom(): a value is returned, an
    exception raised."""

    def __init__(self, *script):
        self.script = list(script)
        self.sent = []

    def _next(self, *_args):
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    accept = recvfrom = _next

    def sendto(self, data, peer):
        self.sent.append((data, peer))


class Args:
    public_ip = "26.48.21.54"
    qos_upstream_bps = 100_000_000


class Listeners(unittest.TestCase):
    def test_accept_keeps_listening_after_a_dead_connection(self):
        conn = object()
        s = FakeSocket(ConnectionAbortedError(), ConnectionResetError(), (conn, ("1.2.3.4", 5)),
                       OSError(errno.EBADF, "closed"))
        seen = []
        tls_terminator._accept_forever(s, lambda c, p: seen.append((c, p)), "test")
        self.assertEqual(seen, [(conn, ("1.2.3.4", 5))])

    def test_qos_udp_survives_windows_connection_resets_and_failed_replies(self):
        probe = bytes(20)
        s = FakeSocket(ConnectionResetError(10054, "WSAECONNRESET"), (probe, ("26.11.40.7", 50000)),
                       (probe, ("26.11.40.7", 50001)), (probe, ("26.11.40.7", 50002)),
                       OSError(errno.EBADF, "closed"))
        replies = {"n": 0}
        record = s.sendto

        def second_reply_fails(data, peer):
            replies["n"] += 1
            if replies["n"] == 2:
                raise OSError(errno.ENETUNREACH, "network unreachable")
            record(data, peer)

        s.sendto = second_reply_fails
        tls_terminator._serve_qos_udp(s, 17502, Args())
        self.assertEqual([peer[1] for _data, peer in s.sent], [50000, 50002])
        self.assertTrue(all(len(data) == 30 for data, _peer in s.sent))

    def test_a_bad_public_address_costs_one_reply_not_the_responder(self):
        class BadArgs(Args):
            public_ip = "my-pc.local"                # a name, not an address
        s = FakeSocket((bytes(20), ("127.0.0.1", 50000)), (bytes(24), ("26.1.1.1", 50001)),
                       OSError(errno.EBADF, "closed"))
        tls_terminator._serve_qos_udp(s, 17502, BadArgs())
        self.assertEqual([peer[1] for _data, peer in s.sent], [50001])


class Store(unittest.TestCase):
    def setUp(self):
        self.root = support.HOME / "store-test"
        for sub in ("stats", "reports"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
            for f in (self.root / sub).iterdir():
                f.unlink()

    def journal(self, pid, *entries):
        (self.root / "reports" / f"{pid}.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in entries) + '{"cut short', encoding="utf-8")

    def test_a_corrupt_state_is_rebuilt_from_the_journal(self):
        self.journal(77,
                     {"t": 1, "category": "SpeedCameras", "entity": 900, "int": {}, "float": {"Speed": 201.5}, "str": {}},
                     {"t": 2, "category": "SpeedCameras", "entity": 900, "int": {}, "float": {"Speed": 233.0}, "str": {}},
                     {"t": 3, "category": "PlayerStats", "entity": 0, "int": {"RacerCredits": 1500}, "float": {}, "str": {}})
        (self.root / "stats" / "77.json").write_text("", encoding="utf-8")        # cut short
        store = player_store.PlayerStore(self.root)
        rows = store.rows_for_entity(900)
        self.assertEqual([{k: v for k, v in r.items() if k != "updated"} for r in rows],
                         [{"blaze_id": 77, "int": {}, "float": {"Speed": 233.0}, "str": {}}])
        self.assertEqual(store.state(77)["PlayerStats"]["0"]["int"], {"RacerCredits": 1500})
        kept = list((self.root / "stats").glob("77.json.corrupt-*"))
        self.assertEqual(len(kept), 1)
        self.assertEqual(json.loads((self.root / "stats" / "77.json").read_text())["SpeedCameras"]["900"]["reports"], 2)

    def test_a_state_that_is_not_an_object_counts_as_corrupt(self):
        (self.root / "stats" / "78.json").write_text("[1, 2]", encoding="utf-8")
        store = player_store.PlayerStore(self.root)
        self.assertEqual(store.state(78), {})        # no journal: an empty state, the file kept
        self.assertTrue(list((self.root / "stats").glob("78.json.corrupt-*")))


class Players(unittest.TestCase):
    def test_a_corrupt_players_json_is_kept_not_overwritten(self):
        folder = support.HOME / "lobby-test"
        folder.mkdir(exist_ok=True)
        for f in folder.iterdir():
            f.unlink()
        players = folder / "players.json"
        players.write_text('{"ea:1006400012345": {"uid": 1006400012345, "persona": "Night', encoding="utf-8")
        lb = lobby.Lobby(players)
        self.assertEqual(lb.players, {})
        kept = list(folder.glob("players.json.corrupt-*"))
        self.assertEqual(len(kept), 1)
        self.assertIn("Night", kept[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
