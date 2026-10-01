"""The bandwidth every player is shown to the others with (--session-bps): the QDAT of the
session data and the NQOS of the game. Up to 1.0.8 both were 100 kbit/s. Offline."""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402
import tls_terminator  # noqa: E402


def fields(raw) -> dict:
    return {t.strip(): v for t, _w, v in raw}


class SessionBandwidthTests(unittest.TestCase):
    def qdat(self) -> dict:
        data = blaze.f_extended_data("DATA")
        return fields(fields(fields(blaze.decode_tdf(blaze.encode_tdf([data])))["DATA"])["QDAT"])

    def game_nqos(self) -> dict:
        with contextlib.redirect_stdout(io.StringIO()):
            lb = lobby.Lobby(local_id=10001)
            host = lobby.Session("127.0.0.1", lambda _frame: None)
            lb.login(host)
            game = lb.create_game(host, tls_terminator._mm_game_params({"PMAX": 2}), 4)
        setup = blaze.Fire2.decode(tls_terminator._game_setup(lb, game, None))
        return fields(fields(fields(blaze.decode_tdf(setup.payload))["GAME"])["NQOS"])

    def test_default_is_no_longer_100_kbit(self):
        self.assertEqual(blaze.SESSION_BPS, 10_000_000)
        self.assertEqual((self.qdat()["DBPS"], self.qdat()["UBPS"]), (10_000_000, 10_000_000))

    def test_session_bps_reaches_player_and_game(self):
        with mock.patch.object(blaze, "SESSION_BPS", 100_000):          # --session-bps 100000
            self.assertEqual((self.qdat()["DBPS"], self.qdat()["UBPS"]), (100_000, 100_000))
            nqos = self.game_nqos()
        self.assertEqual((nqos["DBPS"], nqos["UBPS"], nqos["NATT"]), (100_000, 100_000, 0))


if __name__ == "__main__":
    unittest.main()
