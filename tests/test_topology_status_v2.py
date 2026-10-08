"""
Topology v2 — read-only switches + learned hosts.

Controller writes logs/topology_status.json; dashboard serves GET /api/topology.
No OpenFlow mutation, no LLDP, no mitigation wiring.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SOC = ROOT / "dashboard" / "static" / "soc"


class TopologyStatusUnitTests(unittest.TestCase):
    def test_build_snapshot_switches_and_hosts(self):
        from controller.topology_status import build_topology_snapshot

        snap = build_topology_snapshot(
            datapath_ids=[2, 1],
            mac_to_port={
                1: {
                    "02:aa:aa:aa:aa:01": 1,
                    "ff:ff:ff:ff:ff:ff": 2,  # skipped
                    "33:33:00:00:00:01": 3,  # skipped
                },
                2: {"02:bb:bb:bb:bb:02": 4},
            },
            poll_interval_sec=5,
        )
        self.assertEqual(snap["switch_count"], 2)
        self.assertEqual(snap["host_count"], 2)
        # Same MAC learned on two switches → two attachment links, one unique host
        snap2 = build_topology_snapshot(
            datapath_ids=[1, 2],
            mac_to_port={
                1: {"02:aa:aa:aa:aa:01": 1},
                2: {"02:aa:aa:aa:aa:01": 3},
            },
        )
        self.assertEqual(snap2["host_count"], 1)
        self.assertEqual(snap2["link_count"], 2)
        self.assertEqual(len(snap["links"]), 2)
        self.assertEqual(snap["switches"][0]["dpid"], 1)
        macs = {h["mac"] for h in snap["hosts"]}
        self.assertEqual(macs, {"02:aa:aa:aa:aa:01", "02:bb:bb:bb:bb:02"})
        self.assertTrue(any("not discovered" in x.lower() for x in snap["limitations"]))

    def test_atomic_write_and_roundtrip(self):
        from controller.topology_status import (
            build_topology_snapshot,
            write_topology_snapshot,
            publish_topology_status,
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "topology_status.json"
            snap = build_topology_snapshot(
                datapath_ids=[7], mac_to_port={7: {"02:cc:cc:cc:cc:03": 1}}
            )
            self.assertTrue(write_topology_snapshot(str(path), snap))
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["switch_count"], 1)
            self.assertEqual(loaded["hosts"][0]["mac"], "02:cc:cc:cc:cc:03")

            self.assertTrue(
                publish_topology_status(
                    tmp,
                    datapath_ids=[1],
                    mac_to_port={1: {"02:dd:dd:dd:dd:04": 2}},
                )
            )
            again = json.loads((Path(tmp) / "topology_status.json").read_text(encoding="utf-8"))
            self.assertEqual(again["host_count"], 1)

    def test_preserves_last_known_when_switches_drop(self):
        from controller.topology_status import publish_topology_status

        with tempfile.TemporaryDirectory() as tmp:
            publish_topology_status(
                tmp,
                datapath_ids=[1, 2],
                mac_to_port={1: {"02:aa:aa:aa:aa:01": 1}},
            )
            publish_topology_status(tmp, datapath_ids=[], mac_to_port={})
            path = Path(tmp) / "topology_status.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["switch_count"], 0)
            self.assertEqual(data["connection_state"], "NO_SWITCHES")
            self.assertIsInstance(data.get("last_known"), dict)
            self.assertEqual(data["last_known"]["switch_count"], 2)


class TopologyApiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._path = Path(self._tmp.name) / "topology_status.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_api_unavailable_without_file(self):
        from fastapi.testclient import TestClient
        import dashboard.api as api

        with mock.patch.object(api, "TOPOLOGY_STATUS_JSON", self._path):
            client = TestClient(api.app)
            r = client.get("/api/topology")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertFalse(body.get("available"))
            self.assertEqual(body.get("freshness"), "UNAVAILABLE")
            self.assertEqual(body.get("switches"), [])

    def test_api_live_when_fresh(self):
        from fastapi.testclient import TestClient
        import dashboard.api as api
        from controller.topology_status import publish_topology_status

        publish_topology_status(
            self._tmp.name,
            datapath_ids=[1, 2],
            mac_to_port={1: {"02:ee:ee:ee:ee:05": 3}},
            path=str(self._path),
        )
        with mock.patch.object(api, "TOPOLOGY_STATUS_JSON", self._path):
            client = TestClient(api.app)
            r = client.get("/api/topology")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertTrue(body.get("available"))
            self.assertEqual(body.get("freshness"), "LIVE")
            self.assertEqual(body.get("switch_count"), 2)
            self.assertEqual(body.get("host_count"), 1)

    def test_api_is_get_only_readonly(self):
        from fastapi.testclient import TestClient
        import dashboard.api as api

        client = TestClient(api.app)
        self.assertEqual(client.get("/api/topology").status_code, 200)
        # No write surface
        self.assertEqual(client.post("/api/topology").status_code, 405)


class TopologyFrontendTests(unittest.TestCase):
    def test_soc_calls_topology_api(self):
        api_js = (SOC / "js" / "api" / "index.js").read_text(encoding="utf-8")
        pages = (SOC / "js" / "pages" / "index.js").read_text(encoding="utf-8")
        self.assertIn("/api/topology", api_js)
        self.assertIn("fetchTopology", api_js)
        self.assertIn("fetchTopology", pages)
        self.assertNotIn("No topology read API is exposed", pages)
        # Topology page remains GET-only (no control writes)
        topo_fn = pages.split("export async function renderTopology", 1)[-1].split(
            "export async function renderTwin", 1
        )[0]
        self.assertNotIn("method: \"POST\"", topo_fn)
        self.assertNotIn("/api/control/", topo_fn)


if __name__ == "__main__":
    unittest.main()
