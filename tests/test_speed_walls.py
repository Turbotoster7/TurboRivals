"""Speed wall rows: who is "you" and who is a rival (BlazeUser.URTY), and whose results count.
Up to 1.0.11 every row was NOT_SET and the walls showed no one to beat. Offline."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import blaze  # noqa: E402
import lobby  # noqa: E402


def fields(raw) -> dict:
    return {t.strip(): v for t, _w, v in raw}


class SpeedWallTests(unittest.TestCase):
    def relations(self, local_id, rival_relation=blaze.RELATION_FRIEND) -> dict:
        rows = [{"blaze_id": 1, "persona": "Me", "float": {"speed": 61.0}},
                {"blaze_id": 2, "persona": "Rival", "float": {"speed": 58.3}}]
        reply = blaze.Fire2.decode(blaze.build_in_game_speed_walls_response(
            7, [(2329405573, rows)], local_id=local_id, rival_relation=rival_relation))
        wall = fields(fields(blaze.decode_tdf(reply.payload))["ROWS"][0])
        self.assertEqual(wall["SWID"], 2329405573)
        return {fields(fields(r)["BLUS"])["PENA"]: fields(fields(r)["BLUS"])["URTY"]
                for r in wall["ROWS"]}

    def test_the_asker_is_the_local_player_and_the_others_are_rivals(self):
        self.assertEqual(self.relations(local_id=1),
                         {"Me": blaze.RELATION_LOCAL_PLAYER, "Rival": blaze.RELATION_FRIEND})

    def test_the_rival_relation_is_switchable(self):            # --speedwall-relation 3
        self.assertEqual(self.relations(1, blaze.RELATION_RECENTLY_PLAYED)["Rival"], 3)

    def test_only_known_players_and_those_online_are_ranked(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            players = Path(tmp) / "players.json"
            players.write_text(json.dumps({
                "local": {"uid": 1006431274704, "persona": "Turbotoster"},
                "ea:1802434674": {"uid": 1802434674, "persona": "CustomNickname2"},
                "192.168.231.179": {"uid": 1100327745405, "persona": "Gracz_179"}}))
            lb = lobby.Lobby(players, local_id=1006431274704)
            ranked = lb.ranked_uids()
            # An old address entry (the laptop before 1.0.4) is the same person as ea:1802434674.
            self.assertEqual(ranked, {1006431274704, 1802434674})
            guest = lobby.Session("26.1.2.3", lambda _frame: None)
            lb.login(guest)                                       # synthetic, but online
            self.assertIn(guest.uid, lb.ranked_uids())


if __name__ == "__main__":
    unittest.main()
