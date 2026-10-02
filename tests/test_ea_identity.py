"""ea_identity: which career save the game loads, the save files on the PC, and a save picked by
hand in the launcher (Career save > Pick your save). Offline, on throw-away folders.

The case behind the pick, a friend's PC on 02.10: two EA-era saves (1803135129 from 2013 and
1803135130), our synthetic 1100944155289, and 1003772287105.sav - the EA App user id the
launcher had guessed. The rules could only guess again."""
import support  # noqa: F401  (throw-away folders, proto-lab on the path)

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import ea_identity

USER = 1003772287105                 # the EA App user id
OLD, NEW = 1803135129, 1803135130    # the two EA-era saves
SERVER = 1100944155289               # lobby.REMOTE_UID_BASE pool
ALL = [OLD, NEW, SERVER, USER]       # oldest first, as save_ids()


class Resolve(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.logs = Path(tmp.name)                       # no EA App log: nothing unmasked

    def resolve(self, saves, user=USER, users=None, **kw):
        return ea_identity.resolve(saves, user, log_dir=self.logs, users=users or [user], **kw)

    def test_two_ea_era_saves_are_only_a_guess(self):
        found = self.resolve(ALL)
        self.assertEqual((found["id"], found["source"]), (USER, ea_identity.SOURCE_GUESS))
        self.assertEqual(found["auto"], {"id": USER, "source": ea_identity.SOURCE_GUESS})
        self.assertEqual({f["id"]: f["kind"] for f in found["files"]},
                         {OLD: "career", NEW: "career", SERVER: "server", USER: "account"})

    def test_a_picked_career_save_wins(self):
        found = self.resolve(ALL, chosen=NEW)
        self.assertEqual((found["id"], found["source"]), (NEW, ea_identity.SOURCE_CHOSEN))
        self.assertEqual(found["auto"]["source"], ea_identity.SOURCE_GUESS)   # the rules alone
        self.assertNotIn("chosen_missing", found)

    def test_only_a_career_save_can_be_picked(self):
        # 1100944155289 is what the player took for his save on 02.10 - the game never loads it
        for wrong in (SERVER, USER, 4242):
            with self.subTest(wrong=wrong):
                found = self.resolve(ALL, chosen=wrong)
                self.assertEqual(found["source"], ea_identity.SOURCE_GUESS)
                self.assertEqual(found["chosen_missing"], wrong)

    def test_a_pick_gone_from_the_folder_falls_back_to_the_rules(self):
        found = self.resolve([NEW, SERVER], chosen=OLD)
        self.assertEqual((found["id"], found["source"]), (NEW, ea_identity.SOURCE_ONLY_SAVE))
        self.assertEqual(found["chosen_missing"], OLD)

    def test_without_an_ea_app_account_nothing_is_picked(self):
        found = self.resolve([NEW], user=0, chosen=NEW)
        self.assertIsNone(found["id"])

    def test_the_flags_say_why_a_save_may_be_the_one(self):
        user, other = 1012917074704, 1004043434674          # another account here: ...34674
        found = self.resolve([1006431274704, 1802434674], user=user, users=[user, other])
        files = {f["id"]: f for f in found["files"]}
        self.assertTrue(files[1006431274704]["suffix"])      # ...74704, the account's own
        self.assertTrue(files[1802434674]["other"])          # ...34674, the other account's
        self.assertTrue(files[1802434674]["newest"])         # last in save_ids() order
        self.assertFalse(files[1006431274704]["newest"])

    def test_the_ea_app_profile_marks_its_save(self):
        (self.logs / "EADesktopVerbose.log").write_text(
            f'<GetProfileResponse UserId="{USER}" PersonaId="{NEW}" Persona="DrTrolls"/>\n')
        found = self.resolve(ALL)
        self.assertEqual((found["id"], found["source"]), (NEW, ea_identity.SOURCE_PROFILE))
        self.assertEqual([f["id"] for f in found["files"] if f["profile"]], [NEW])


class SaveFiles(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        now = time.time()
        for age, name in enumerate([f"{USER}.sav", f"{SERVER}.sav", f"{NEW}.sav", f"{OLD}.sav"]):
            path = self.folder / name
            path.write_bytes(b"\0" * 16)
            os.utime(path, (now - age * 3600, now - age * 3600))
        for name in ("RNET_current.sav", "2669023.sav11", "GAMESETTINGS"):
            (self.folder / name).write_bytes(b"x")

    def test_kinds_newest_first(self):
        files = ea_identity.save_files(self.folder, users=[USER])
        self.assertEqual([(f["id"], f["kind"]) for f in files],
                         [(USER, "account"), (SERVER, "server"), (NEW, "career"), (OLD, "career")])
        self.assertTrue(all(f["written"] > 0 for f in files))

    def test_resolve_reads_the_folder(self):
        with mock.patch.object(ea_identity, "saves_dir", return_value=self.folder):
            found = ea_identity.resolve(user=USER, log_dir=self.folder, users=[USER], chosen=NEW)
        self.assertEqual((found["id"], found["source"]), (NEW, ea_identity.SOURCE_CHOSEN))
        self.assertEqual(found["saves"], [OLD, NEW, SERVER, USER])
        self.assertEqual([f["id"] for f in found["files"] if f["newest"]], [NEW])


if __name__ == "__main__":
    unittest.main()
