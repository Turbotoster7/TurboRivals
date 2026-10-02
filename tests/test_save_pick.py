"""The server's side of a career save picked by hand (launcher: Career save > Pick your save).

A pick is the player's word, not the EA App's. A wrong one is a uid the other games cannot tie to
the car - the kind of rival Autolog crashed on (02.10, Player_15) - so it counts as unconfirmed,
like a guess. The game's listUserEntitlements2 BUID can refute an id but not confirm one: it never
differed from the uid on 02.10, not even for a synthetic one. Offline, no sockets."""
import support  # noqa: F401  (throw-away folders, proto-lab on the path)

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import ea_identity
import lobby
import tls_terminator

USER = 1003772287105
PICKED = 1803135130
GUEST_IP = "100.96.255.48"


def identify(src: str, uid: int = PICKED) -> bytes:
    query = f"id={uid}&user={USER}&saves={uid}&src={src.replace(' ', '+')}&name=DrTrolls"
    return f"GET {tls_terminator.IDENTIFY_PATH}?{query} HTTP/1.1\r\n\r\n".encode()


class SavePickTests(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        quiet = contextlib.redirect_stdout(self.out)
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def use(self, lb):
        patch = mock.patch.dict(tls_terminator._LOBBY, {"lobby": lb})
        patch.start()
        self.addCleanup(patch.stop)
        return lb

    def guest(self, lb, ip=GUEST_IP):
        sess = lobby.Session(ip, lambda _frame: None)
        lb.login(sess)
        return sess

    def test_a_guest_pick_is_used_but_unconfirmed(self):
        lb = self.use(lobby.Lobby(self.dir / "players.json"))
        status, _body = tls_terminator._identify(identify(ea_identity.SOURCE_CHOSEN), None, (GUEST_IP, 0))
        self.assertEqual(status, b"200 OK")
        sess = self.guest(lb)
        self.assertEqual(sess.uid, PICKED)                  # progress goes to the picked save
        self.assertIn(PICKED, lb.unconfirmed_uids())        # but no rival row for the others yet

    def test_a_save_found_by_the_launcher_stays_confirmed(self):
        lb = self.use(lobby.Lobby(self.dir / "players.json"))
        tls_terminator._identify(identify(ea_identity.SOURCE_ONLY_SAVE), None, (GUEST_IP, 0))
        self.assertNotIn(self.guest(lb).uid, lb.unconfirmed_uids())

    def test_a_matching_buid_confirms_nothing(self):
        # 1.1.1 let it confirm, and a picked save came back into the others' Autolog (02.10)
        lb = self.use(lobby.Lobby(self.dir / "players.json"))
        tls_terminator._identify(identify(ea_identity.SOURCE_CHOSEN), None, (GUEST_IP, 0))
        sess = self.guest(lb)
        tls_terminator._note_persona_id(sess, PICKED)
        self.assertIn(PICKED, lb.unconfirmed_uids())
        self.assertIn(f"BUID {PICKED} (= its uid)", self.out.getvalue())
        self.assertNotIn("[hint]", self.out.getvalue())

    def test_a_different_buid_refutes_even_a_found_save(self):
        lb = self.use(lobby.Lobby(self.dir / "players.json"))
        tls_terminator._identify(identify(ea_identity.SOURCE_ONLY_SAVE), None, (GUEST_IP, 0))
        sess = self.guest(lb)
        self.assertNotIn(PICKED, lb.unconfirmed_uids())
        tls_terminator._note_persona_id(sess, PICKED + 1)
        self.assertIn(PICKED, lb.unconfirmed_uids())

    def test_a_wrong_uid_gets_a_hint_naming_the_save_once(self):
        lb = self.use(lobby.Lobby(self.dir / "players.json"))
        sess = self.guest(lb)                               # synthetic uid, no launcher
        tls_terminator._note_persona_id(sess, PICKED)
        tls_terminator._note_persona_id(sess, PICKED)
        hints = [line for line in self.out.getvalue().splitlines() if "[hint]" in line]
        self.assertEqual(len(hints), 1)
        self.assertIn(f"the game goes by {PICKED} but is logged in as {sess.uid}", hints[0])
        self.assertIn(f"pick {PICKED} under Career save", hints[0])

    def test_the_host_s_pick_is_unconfirmed_too(self):
        lb = self.use(lobby.Lobby(self.dir / "players.json", local_id=PICKED,
                                  local_id_source="--local-id, chosen in the launcher",
                                  local_id_confirmed=False))
        host = self.guest(lb, "127.0.0.1")
        self.assertEqual(host.uid, PICKED)
        self.assertIn(PICKED, lb.unconfirmed_uids())
        tls_terminator._note_persona_id(host, PICKED)
        self.assertIn(PICKED, lb.unconfirmed_uids())                 # still: a BUID only refutes

    def _local_lobby(self, local_id=0, chosen=False):
        args = SimpleNamespace(data_dir=str(self.dir), local_id=local_id, local_id_chosen=chosen)
        with mock.patch.dict(tls_terminator._LOBBY, {}, clear=True):
            return tls_terminator._lobby(args)

    def test_local_id_chosen_marks_the_host_s_id(self):
        with mock.patch.object(ea_identity, "resolve", side_effect=AssertionError("not asked")):
            lb = self._local_lobby(PICKED, chosen=True)      # the launcher's pick
            self.assertEqual((lb.local_id, lb.local_id_confirmed), (PICKED, False))
            self.assertIn(ea_identity.SOURCE_CHOSEN, lb.local_id_source)
            lb = self._local_lobby(PICKED)                   # the operator's own --local-id
            self.assertEqual((lb.local_id, lb.local_id_confirmed), (PICKED, True))

    def test_a_guessed_host_id_is_unconfirmed(self):
        guess = {"id": USER, "source": ea_identity.SOURCE_GUESS, "user": USER, "persona": "",
                 "saves": [], "files": [], "auto": {}}
        with mock.patch.object(ea_identity, "resolve", return_value=guess):
            lb = self._local_lobby()
        self.assertEqual((lb.local_id, lb.local_id_confirmed), (USER, False))
        found = dict(guess, id=PICKED, source=ea_identity.SOURCE_ONLY_SAVE)
        with mock.patch.object(ea_identity, "resolve", return_value=found):
            lb = self._local_lobby()
        self.assertEqual((lb.local_id, lb.local_id_confirmed), (PICKED, True))


if __name__ == "__main__":
    unittest.main()
