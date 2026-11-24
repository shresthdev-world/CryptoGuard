"""Offline checks; the Windows-only move case operates on a temporary text fixture."""
import csv
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detector
import evidence as ev
import portable


def finding(markers=(), peers=(), load="", gap=False):
    return {"markers": list(markers), "pool_matches": list(peers), "load": load, "coverage_gap": gap}


class Findings(unittest.TestCase):
    def test_workload_only(self):
        self.assertEqual(ev.classify(finding(load="CPU >=80% for 10 consecutive samples")), ev.UNUSUAL)

    def test_sustained_gpu(self):
        self.assertEqual(ev.classify(finding(load="GPU >=80% for 3 distinct GPU samples")), ev.UNUSUAL)

    def test_single_clue(self):
        self.assertEqual(ev.classify(finding(["Stratum URL marker"])), ev.POSSIBLE)

    def test_launch_address_is_one_source(self):
        self.assertEqual(ev.classify(finding(["Stratum URL in launch arguments"], ["Pool in launch arguments: demo.invalid"], "High CPU")), ev.POSSIBLE)

    def test_peer_alone(self):
        self.assertEqual(ev.classify(finding(peers=["192.0.2.1:443 | test pool"])), ev.POSSIBLE)

    def test_corroborated_runtime(self):
        self.assertEqual(ev.classify(finding(["Stratum URL in launch arguments"], ["192.0.2.1:443 | test pool"])), ev.LIKELY)

    def test_empty_and_unavailable(self):
        self.assertEqual(ev.classify(finding()), ev.CLEAR)
        self.assertEqual(ev.classify(finding(gap=True)), ev.INCOMPLETE)

    def test_port_only(self):
        self.assertEqual(ev.match_peers([("192.0.2.1", 3333)], {}), [])

    def test_pid_reuse_and_recovery(self):
        a,b=(14,100),(14,120)
        counter=detector.Streaks(3)
        for rows, want in [({a:90},set()),({a:90},set()),({b:90},set()),({b:90},set()),({b:90},{b}),({b:90},set()),({b:0},set())]:
            self.assertEqual(counter.update(rows), want)

    def test_demo_logs_and_quarantine(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(detector, "DATA", Path(folder)):
            events=[]
            detector.demo(lambda k,v: events.append((k,v)), threading.Event())
            items=[v for k,v in events if k=="finding"]
            self.assertEqual([v["verdict"] for v in items], [ev.UNUSUAL,ev.POSSIBLE,ev.LIKELY])
            with (Path(folder)/"demo_alerts.csv").open() as log:
                self.assertEqual(len(list(csv.DictReader(log))), 3)
            self.assertEqual(len((Path(folder)/"demo_alerts.jsonl").read_text().splitlines()),3)
            sample=detector.DemoSample()
            self.assertEqual(sample.move(),sample.isolated)
            self.assertEqual(sample.move(True),sample.original)
            sample.original.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                sample.move()
            detector.log_action(items[-1],"Training action")
            self.assertEqual(json.loads((Path(folder)/'actions.jsonl').read_text())['mode'],'Demo')

    def test_portable_scope(self):
        item=dict(mode="Live", verdict=ev.LIKELY, owned_by_user=True, digest="recorded", path=str(Path.home()/"Downloads"/"xmrig.exe"))
        self.assertTrue(portable.eligible(item))
        for override in [dict(mode="Demo"),dict(verdict=ev.UNUSUAL), dict(owned_by_user=False), dict(digest=""),dict(path=str(Path.home()/"Downloads"/"browser.exe")),dict(path=str(Path.home()/"Downloads"/".."/"xmrig.exe")),dict(path=str(Path.home()/"xmrig.exe"))]:
            self.assertFalse(portable.eligible(dict(item,**override)))

    @unittest.skipUnless(os.name == "nt", "Uses the Windows file API")
    def test_windows_handle_move(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"harmless.txt"
            held=Path(d)/"held.disabled"
            data=b"Temporary classroom test"
            source.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest()
            with self.assertRaises(ValueError):
                portable.move_checked(source,held,"incorrect")
            held.write_bytes(b"keep")
            with self.assertRaises(OSError):
                portable.move_checked(source,held,digest)
            self.assertEqual(held.read_bytes(),b"keep")
            held.unlink()
            portable.move_checked(source,held,digest)
            self.assertFalse(source.exists())
            portable.move_checked(held,source,digest)
            self.assertEqual(source.read_bytes(),data)


if __name__ == "__main__":
    unittest.main()
