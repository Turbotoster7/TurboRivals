"""UserSessions.resumeSession: a game coming back on a new connection with its session key -
after the host's server restarted or the PC slept. Until 1.0.11 it got an empty acknowledgement,
pinged once and gave up (01.10, server-20261001-203209). Offline, no sockets."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402
import tls_terminator  # noqa: E402

GUEST = 1802434674
HOST = 1006431274704
ARGS = SimpleNamespace(reply_msgtype=0x10, no_resume=False, notify_probe=False,
                       plain_session_data=False, legacy_user_added=False, notify_comp=0x7802,
                       empty_user_auth=False)


def resume_request(key: str) -> "blaze.Fire2":
    return blaze.Fire2(component=0x7802, command=0x23, seq=426,
                       payload=blaze.encode_tdf([blaze.f_str("SKEY", key)]))


class ResumeSessionTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # players.json as the host's disk has it after a restart: the registrations of the
        # launchers are gone with the old process, the stored players are not.
        players = Path(tmp.name) / "players.json"
        players.write_text(json.dumps({
            "local": {"uid": HOST, "persona": "Turbotoster"},
            f"ea:{GUEST}": {"uid": GUEST, "persona": "CustomNickname2", "user": 1004043460810}}))
        self.lb = lobby.Lobby(players, local_id=HOST, local_persona="Turbotoster")
        patch = mock.patch.dict(tls_terminator._LOBBY, {"lobby": self.lb})
        patch.start()
        self.addCleanup(patch.stop)

    def session(self, ip):
        return lobby.Session(ip, lambda _frame: None)

    def test_the_guest_takes_its_session_back(self):
        guest = self.session("26.48.21.54")
        reply = blaze.Fire2.decode(tls_terminator._resume_session(
            resume_request(f"1_{GUEST}_sess"), ARGS, guest))
        self.assertEqual((reply.command, reply.error, reply.seq), (0x23, 0, 426))
        self.assertEqual((guest.uid, guest.persona), (GUEST, "CustomNickname2"))
        self.assertIs(self.lb.sessions[GUEST], guest)
        # ...followed by what a login brings: UserAdded, ExtendedDataUpdate, UserAuthenticated
        notes = tls_terminator._after_reply(resume_request(""), ARGS, guest)
        self.assertEqual([blaze.Fire2.decode(n).command for _t, n in notes], [2, 1, 8])
        self.assertFalse(guest.resumed)

    def test_the_host_resumes_from_its_own_machine(self):
        host = self.session("127.0.0.1")
        self.assertEqual(self.lb.resume(host, HOST), [])
        self.assertEqual(host.persona, "Turbotoster")

    def test_an_unknown_key_gets_an_error_so_the_game_logs_in_again(self):
        for key in ("1_4242_sess", "garbage", ""):
            with self.subTest(key=key):
                sess = self.session("26.48.21.54")
                reply = blaze.Fire2.decode(tls_terminator._resume_session(
                    resume_request(key), ARGS, sess))
                self.assertEqual(reply.error, tls_terminator.RESUME_REFUSED)
                self.assertEqual(sess.uid, 0)

    def test_nobody_takes_over_a_player_logged_in_elsewhere(self):
        elsewhere = self.session("26.48.21.54")
        self.lb.resume(elsewhere, GUEST)
        self.assertIsNone(self.lb.resume(self.session("26.99.0.1"), GUEST))
        self.assertIs(self.lb.sessions[GUEST], elsewhere)

    def test_a_half_open_old_connection_leaves_its_game(self):
        # The PC slept: the server still holds the old connection when the game comes back.
        host = self.session("127.0.0.1")
        self.lb.login(host)
        old = self.session("26.48.21.54")
        self.lb.resume(old, GUEST)
        game = self.lb.create_game(host, {"max_players": 6}, 4)
        self.lb.join(old, game)
        new = self.session("26.48.21.54")
        notes = self.lb.resume(new, GUEST)
        self.assertFalse(old.alive)
        self.assertNotIn(GUEST, game.players)
        self.assertEqual([(t, blaze.Fire2.decode(n).command) for t, n in notes],
                         [(host, blaze.GM_NOTIFY_PLAYER_REMOVED)])


if __name__ == "__main__":
    unittest.main()
