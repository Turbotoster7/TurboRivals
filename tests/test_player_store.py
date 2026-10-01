"""PlayerStore speed wall rows when one object sits in several report categories. On 1.0.12.3
a race (Sunset Tunnel) stored in DirectedRaces7c5c0574 and DirectedRaces7c5c8955 had the older,
worse time overwrite the better one, mixed with the other attempt's fields. Offline, temporary data."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proto-lab"))

import player_store  # noqa: E402

PID, RACE, CAMERA, OTHER = 1473685610, 1836156012, 2329405506, 777


def slot(updated, attempts, **floats):
    return {"float": floats, "int": {"attempts": attempts}, "str": {}, "updated": updated}


class RowsForEntityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "stats").mkdir()
        state = {
            # the better time is the older report here, so "newest wins" would fail
            "DirectedRaces7c5c0574": {str(RACE): slot(100, 1, eventTime=152.04)},
            "DirectedRaces7c5c8955": {str(RACE): slot(200, 8, eventTime=289.67)},
            "SpeedCameras00596c35": {str(CAMERA): slot(300, 2, speed=79.9)},
            "SpeedCameras00596c96": {str(CAMERA): slot(100, 5, speed=68.9)},
            "Collectables00596a25": {str(OTHER): slot(100, 1)},
            "Collectables00596a26": {str(OTHER): slot(400, 2)},
        }
        (root / "stats" / f"{PID}.json").write_text(json.dumps(state))
        self.store = player_store.PlayerStore(root)

    def row(self, entity) -> dict:
        rows = self.store.rows_for_entity(entity)
        self.assertEqual([r["blaze_id"] for r in rows], [PID])
        return rows[0]

    def test_the_best_time_with_its_own_fields(self):
        row = self.row(RACE)
        self.assertEqual((row["float"], row["int"], row["updated"]),
                         ({"eventTime": 152.04}, {"attempts": 1}, 100))

    def test_the_highest_speed(self):
        row = self.row(CAMERA)
        self.assertEqual((row["float"], row["int"]), ({"speed": 79.9}, {"attempts": 2}))

    def test_without_a_main_result_the_newest(self):
        self.assertEqual(self.row(OTHER)["int"], {"attempts": 2})

    def test_world_walls_leave_the_events_out(self):
        self.assertEqual(self.store.speedwall_ids(PID), {RACE, CAMERA})
        self.assertEqual(self.store.speedwall_ids(PID, world_only=True), {CAMERA})


if __name__ == "__main__":
    unittest.main()
