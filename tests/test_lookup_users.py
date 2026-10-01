"""UserSessions.lookupUsers: who owns a car whose id no Blaze user has. Offline, no sockets.

A game names each car by its owner's PersonaId and asks the server when no Blaze user carries
that id (log-40: the guest asked about the host's PersonaId while the host was logged in under
its EA App user id). Left unanswered, the car stays an ordinary racer - name only up close.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402
import tls_terminator  # noqa: E402

HOST_PERSONA = 1006431274704           # the host's PersonaId (the save its game loads)
HOST_EA_USER = 1012917074704           # its EA App user id - the uid before 1.0.4
GUEST_PERSONA = 1802434674             # the guest's PersonaId
ARGS = SimpleNamespace(reply_msgtype=0x10, no_lookup_users=False)


def lookup_request(*ids: int) -> "blaze.Fire2":
    """The request as the game sends it: LTYP 0 (BLAZE_ID) and a list of UserIdentification."""
    payload = blaze.encode_tdf([
        blaze.f_int("LTYP", 0),
        blaze.f_list_struct("ULST", [[blaze.f_int("ID", i), blaze.f_str("NAME", "")] for i in ids]),
    ])
    return blaze.Fire2(component=0x7802, command=13, payload=payload, seq=42)


def answered(reply: bytes) -> list[dict]:
    """(ID, NAME) of every user in a lookupUsers reply."""
    fr = blaze.Fire2.decode(reply)
    assert (fr.component, fr.command, fr.seq) == (0x7802, 13, 42)
    fields = {t.strip(): v for t, _w, v in blaze.decode_tdf(fr.payload)}
    out = []
    for user_data in fields.get("ULST") or []:
        data = {t.strip(): v for t, _w, v in user_data}
        user = {t.strip(): v for t, _w, v in data["USER"]}
        out.append({"id": user["ID"], "name": user["NAME"], "flags": data["FLGS"]})
    return out


class LookupUsersTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def lobby_with(self, host_uid: int):
        """A host on this machine (confirmed id) in a running game, plus the lobby."""
        lb = lobby.Lobby(local_id=host_uid, local_persona="Host")
        patch = mock.patch.dict(tls_terminator._LOBBY, {"lobby": lb})
        patch.start()
        self.addCleanup(patch.stop)
        host = lobby.Session("127.0.0.1", lambda _frame: None)
        lb.login(host)
        game = lb.create_game(host, {"max_players": 6}, 4)
        return lb, host, game

    def guest(self, lb, game, ip: str, name: str):
        sess = lobby.Session(ip, lambda _frame: None)
        lb.login(sess)                                  # no launcher: synthetic uid
        lb.names[ip] = sess.persona = name
        lb.join(sess, game)
        return sess

    def ask(self, asker, *ids):
        return answered(tls_terminator._lookup_users(lookup_request(*ids), ARGS, asker))

    def test_a_logged_in_uid_is_answered(self):
        lb, host, game = self.lobby_with(HOST_PERSONA)
        guest = self.guest(lb, game, "192.0.2.2", "Guest")
        self.assertEqual(self.ask(guest, HOST_PERSONA),
                         [{"id": HOST_PERSONA, "name": "Host", "flags": 3}])

    def test_persona_from_entitlements_is_an_alias(self):
        # log-40 exactly: the host logged in under its EA App user id, its game sent its
        # PersonaId as the BUID of listUserEntitlements2, and the guest asks about that one.
        lb, host, game = self.lobby_with(HOST_EA_USER)
        host.persona_id = HOST_PERSONA
        guest = self.guest(lb, game, "192.0.2.2", "Guest")
        self.assertEqual(self.ask(guest, HOST_PERSONA)[0]["name"], "Host")
        self.assertEqual(lb.aliases[HOST_PERSONA], HOST_EA_USER)

    def test_the_only_unconfirmed_player_in_the_game_owns_the_unknown_id(self):
        lb, host, game = self.lobby_with(HOST_PERSONA)
        guest = self.guest(lb, game, "192.0.2.2", "Guest")      # synthetic uid
        self.assertEqual(self.ask(host, GUEST_PERSONA),
                         [{"id": GUEST_PERSONA, "name": "Guest", "flags": 3}])
        self.assertEqual(lb.aliases[GUEST_PERSONA], guest.uid)
        self.assertEqual(self.ask(host, GUEST_PERSONA)[0]["name"], "Guest")   # by the alias now

    def test_two_unconfirmed_players_are_not_guessed_between(self):
        lb, host, game = self.lobby_with(HOST_PERSONA)
        self.guest(lb, game, "192.0.2.2", "Guest")
        self.guest(lb, game, "192.0.2.3", "Other")
        self.assertEqual(self.ask(host, GUEST_PERSONA), [])

    def test_the_asker_does_not_lend_its_name(self):
        # An unconfirmed guest asking about a car nobody owns gets no answer - not its own name.
        lb, host, game = self.lobby_with(HOST_PERSONA)
        guest = self.guest(lb, game, "192.0.2.2", "Guest")
        self.assertEqual(self.ask(guest, 4242424242), [])

    def test_a_guessed_launcher_id_counts_as_unconfirmed(self):
        lb, host, game = self.lobby_with(HOST_PERSONA)
        lb.register("192.0.2.2", HOST_EA_USER + 1, name="Guest", guess=True)
        guest = self.guest(lb, game, "192.0.2.2", "Guest")
        self.assertEqual(guest.uid, HOST_EA_USER + 1)
        self.assertEqual(self.ask(host, GUEST_PERSONA)[0]["name"], "Guest")

    def test_a_player_owns_one_unknown_id_only(self):
        lb, host, game = self.lobby_with(HOST_PERSONA)
        self.guest(lb, game, "192.0.2.2", "Guest")
        self.ask(host, GUEST_PERSONA)                              # the guest's PersonaId learned
        names = [(u["id"], u["name"]) for u in self.ask(host, HOST_PERSONA, 999, GUEST_PERSONA)]
        self.assertEqual(names, [(HOST_PERSONA, "Host"), (GUEST_PERSONA, "Guest")])


if __name__ == "__main__":
    unittest.main()
