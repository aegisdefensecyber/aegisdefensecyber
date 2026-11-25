"""Tests for scripts/slot_gate.py (the cheap 'is an update due?' check)."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_brief  # noqa: E402
import slot_gate  # noqa: E402

ET = slot_gate.ET


def at(s):  # ET wall-clock time
    return datetime.fromisoformat(s).replace(tzinfo=ET)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "threatwatch/data").mkdir(parents=True)
        (self.root / "global-intelligence/data").mkdir(parents=True)
        self.p = mock.patch.object(slot_gate, "ROOT", self.root)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def status(self, last):
        (self.root / "threatwatch/data/status.json").write_text(json.dumps({"lastSlot": last}))

    def gi(self, ts):
        (self.root / "global-intelligence/data/last-updated.json").write_text(json.dumps({"collected_at": ts}))

    def test_slots_match_publisher(self):
        self.assertEqual(slot_gate.SLOTS, build_brief.SLOTS_ET)

    def test_threatwatch(self):
        self.status("2026-11-24 22:00")
        self.assertFalse(slot_gate.threatwatch_due(at("2026-11-25T06:30"))[0])   # before first slot
        self.assertTrue(slot_gate.threatwatch_due(at("2026-11-25T06:52"))[0])
        self.assertTrue(slot_gate.threatwatch_due(at("2026-11-25T10:37"))[0])    # missed 07:00 still due
        self.status("2026-11-25 07:00")
        self.assertFalse(slot_gate.threatwatch_due(at("2026-11-25T10:37"))[0])
        self.assertTrue(slot_gate.threatwatch_due(at("2026-11-25T11:52"))[0])
        self.assertTrue(slot_gate.threatwatch_due(at("2026-11-25T23:59"))[0])
        (self.root / "threatwatch/data/status.json").unlink()
        self.assertTrue(slot_gate.threatwatch_due(at("2026-11-25T07:07"))[0])

    def test_global(self):
        self.gi("2026-11-25T12:10:00Z")   # 07:10 EST
        self.assertFalse(slot_gate.global_due(at("2026-11-25T10:00"))[0])
        self.assertTrue(slot_gate.global_due(at("2026-11-25T11:50"))[0])
        self.gi("2026-11-25T03:00:00Z")   # 22:00 EST on the 24th
        self.assertFalse(slot_gate.global_due(at("2026-11-25T05:00"))[0])    # still the 22:00 slot
        self.gi("2026-11-25T02:00:00Z")   # 21:00 EST on the 24th, before that slot
        self.assertTrue(slot_gate.global_due(at("2026-11-25T05:00"))[0])
        (self.root / "global-intelligence/data/last-updated.json").unlink()
        self.assertTrue(slot_gate.global_due(at("2026-11-25T08:00"))[0])

    def test_cli_writes_output(self):
        self.status("x")
        out = self.root / "out.txt"
        with mock.patch.dict("os.environ", {"GITHUB_OUTPUT": str(out)}):
            slot_gate.main(["threatwatch", "--now", "2026-11-25T12:00:00Z"])
        self.assertEqual(out.read_text(), "due=true\n")


if __name__ == "__main__":
    unittest.main()
