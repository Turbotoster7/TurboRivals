"""Matchmaking decisions, offline: the real lobby and _resolve_matchmaking, no sockets.

The two-thread race comes from RivalsNET's fixture (tests/turborivals/test_matchmaking.py in
49Ssr/RivalsNET): before 1.0.7 two decisions firing together both took the last free slot.
"""
import contextlib
import io
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402
import tls_terminator  # noqa: E402

ARGS = SimpleNamespace(notify_comp=0x7802, gm_player_state=4)
REQUEST = {"PMAX": 2, "ATTR": {"gameMembershipRequirements": "Public"}}


class PausedSelectionLobby(lobby.Lobby):
    """Holds the first search right after it picked a game, while a second one tries for the
    same slot."""

    def __init__(self):
        super().__init__(local_id=10001)
        self.selected = threading.Event()
        self.release = threading.Event()
        self.second_selected = threading.Event()

    def find_public_game(self, sess, avoid, strict=False):
        game = super().find_public_game(sess, avoid, strict)
        if threading.current_thread().name == "first":
            self.selected.set()
            if not self.release.wait(5):
                raise TimeoutError("the first search was never released")
        elif threading.current_thread().name == "second":
            self.second_selected.set()
        return game


class MatchmakingTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def session(self, lb, ip):
        sess = lobby.Session(ip, lambda _frame: None)
        lb.login(sess)
        return sess

    def running_game(self, lb):
        host = self.session(lb, "127.0.0.1")
        game = lb.create_game(host, tls_terminator._mm_game_params(REQUEST), 4)
        lb.set_state(game.gid, blaze.GAME_STATE["IN_GAME"])
        return host, game

    def test_last_slot_is_not_taken_twice(self):
        lb = PausedSelectionLobby()
        _host, game = self.running_game(lb)
        first = self.session(lb, "192.0.2.2")
        second = self.session(lb, "192.0.2.3")
        errors = []

        def search(sess, msid):
            try:
                tls_terminator._resolve_matchmaking(lb, ARGS, sess, msid, REQUEST)
            except BaseException as e:      # noqa: BLE001 - reported below
                errors.append(e)

        threads = [threading.Thread(target=search, args=(first, 1), name="first"),
                   threading.Thread(target=search, args=(second, 2), name="second")]
        threads[0].start()
        try:
            self.assertTrue(lb.selected.wait(5), "the first search did not pick a game")
            threads[1].start()
            # Without the lock around the whole decision the second search picks the same
            # last slot right here; with it, it waits for the first to finish.
            lb.second_selected.wait(1)
        finally:
            lb.release.set()
            for t in threads:
                if t.ident is not None:
                    t.join(5)
        self.assertFalse(any(t.is_alive() for t in threads), "a search did not finish")
        self.assertEqual(errors, [])
        self.assertLessEqual(len(game.players), 2)
        self.assertEqual(len(lb.games), 2)
        self.assertNotEqual(first.games, second.games)

    def test_joiner_learns_the_players_before_the_game(self):
        lb = lobby.Lobby(local_id=10001)
        host, game = self.running_game(lb)
        guest = self.session(lb, "192.0.2.2")
        frames = tls_terminator._resolve_matchmaking(lb, ARGS, guest, 1, REQUEST)
        to_guest = [(blaze.Fire2.decode(raw).component, blaze.Fire2.decode(raw).command)
                    for target, raw in frames if target is guest]
        self.assertEqual(to_guest, [(0x7802, 2), (4, 20)])      # UserAdded, then GameSetup
        self.assertEqual(set(game.players), {host.uid, guest.uid})

    def test_full_game_makes_a_new_one(self):
        lb = lobby.Lobby(local_id=10001)
        _host, full = self.running_game(lb)
        first = self.session(lb, "192.0.2.2")
        second = self.session(lb, "192.0.2.3")
        tls_terminator._resolve_matchmaking(lb, ARGS, first, 1, REQUEST)
        tls_terminator._resolve_matchmaking(lb, ARGS, second, 2, REQUEST)
        self.assertEqual(len(full.players), 2)
        self.assertEqual(len(lb.games), 2)

    @staticmethod
    def avoiding(game):
        return dict(REQUEST, CRIT=[("AGAM", 3, [("GIDL", 4, [game.gid])])])

    def test_an_avoided_game_loses_to_another_one(self):
        lb = lobby.Lobby(local_id=10001)
        _host, avoided = self.running_game(lb)
        other_host = self.session(lb, "192.0.2.9")
        other = lb.create_game(other_host, tls_terminator._mm_game_params(REQUEST), 4)
        lb.set_state(other.gid, blaze.GAME_STATE["IN_GAME"])
        guest = self.session(lb, "192.0.2.2")
        tls_terminator._resolve_matchmaking(lb, ARGS, guest, 1, self.avoiding(avoided))
        self.assertNotIn(guest.uid, avoided.players)
        self.assertIn(guest.uid, other.players)

    def test_the_only_game_is_joined_even_when_avoided(self):
        # 01.10: a laptop woke from sleep, its game asked to avoid the host's game it had dropped
        # out of (GIDL), and a strict avoid left it alone in a new game.
        lb = lobby.Lobby(local_id=10001)
        _host, game = self.running_game(lb)
        guest = self.session(lb, "192.0.2.2")
        tls_terminator._resolve_matchmaking(lb, ARGS, guest, 1, self.avoiding(game))
        self.assertIn(guest.uid, game.players)
        self.assertEqual(len(lb.games), 1)

    def test_strict_avoid_keeps_the_old_behaviour(self):
        lb = lobby.Lobby(local_id=10001)
        _host, game = self.running_game(lb)
        guest = self.session(lb, "192.0.2.2")
        strict = SimpleNamespace(**vars(ARGS), strict_avoid=True)
        tls_terminator._resolve_matchmaking(lb, strict, guest, 1, self.avoiding(game))
        self.assertNotIn(guest.uid, game.players)
        self.assertEqual(len(lb.games), 2)


if __name__ == "__main__":
    unittest.main()
