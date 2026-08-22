import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from promotion_portal.server import BASE_PATH, make_server
from promotion_portal.setup import create_instance
from promotion_portal.storage import MessageStore


class EvaluationLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.instance = Path(self.tmp.name) / "instance"
        create_instance(self.instance)
        self.server = make_server("127.0.0.1", 0, self.instance)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}{BASE_PATH}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def fetch(self, path, headers=None, method=None):
        req = Request(self.base_url + path, headers=headers or {}, method=method)
        with urlopen(req, timeout=5) as response:
            return response.status, response.read().decode(), response.headers.get("Content-Type", "")

    def test_storage_snapshot_tracks_scores_evidence_and_corrections(self):
        store = MessageStore(self.instance / "messages.sqlite3")
        task_id = store.add_task("captain", "Review uptime evidence", "Verify public surfaces are healthy.", max_score=5)
        store.add_evidence(task_id, "wesley", "Daily smoke", "https://wesley.thesisko.com/status/", "All systems operational.")
        store.score_task(task_id, "captain", 4)
        store.add_timeline_event("captain", "correction_required", "Tighten representation evidence.")
        store.add_timeline_event("wesley", "self_caught", "Found stale copy before Captain review.")

        snapshot = store.evaluation_snapshot()

        self.assertEqual(snapshot["aggregate"]["task_count"], 1)
        self.assertEqual(snapshot["aggregate"]["score"], 4)
        self.assertEqual(snapshot["aggregate"]["max_score"], 5)
        self.assertEqual(snapshot["aggregate"]["evidence_count"], 1)
        self.assertEqual(snapshot["aggregate"]["corrections_required"], 1)
        self.assertEqual(snapshot["aggregate"]["self_caught"], 1)
        self.assertIn(task_id, snapshot["evidence_by_task"])

    def test_status_api_exposes_evaluation_aggregate(self):
        store = self.server.app.store
        task_id = store.add_task("captain", "Review portal", "Evidence ledger visible.")
        store.add_evidence(task_id, "wesley", "Rendered page", "", "Evaluation page has metrics.")

        status, body, content_type = self.fetch("/api/status")
        payload = json.loads(body)

        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        self.assertEqual(payload["status"], "phase1")
        self.assertEqual(payload["evaluation"]["task_count"], 1)
        self.assertEqual(payload["evaluation"]["evidence_count"], 1)

    def test_public_status_matches_phase_one_ledger_state(self):
        store = self.server.app.store
        task_id = store.add_task("captain", "Review portal", "Evidence ledger visible.")
        store.add_evidence(task_id, "wesley", "Rendered page", "", "Evaluation page has metrics.")
        store.add_timeline_event("captain", "correction_required", "Remove stale public phase copy.")

        status, body, content_type = self.fetch("")

        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("Phase 1 / evaluation ledger live", body)
        self.assertIn("Phase 1 evidence collection", body)
        self.assertIn("<dt>Tasks</dt><dd>1</dd>", body)
        self.assertIn("<dt>Evidence items</dt><dd>1</dd>", body)
        self.assertIn("<dt>Corrections required</dt><dd>1</dd>", body)

    def test_head_status_routes_do_not_return_501(self):
        status, _, content_type = self.fetch("/api/status", method="HEAD")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)

        token = self.server.app.security.sign_session("captain")
        status, _, content_type = self.fetch("/evaluation", {"Cookie": f"portal_session={token}"}, method="HEAD")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)

    def test_evaluation_page_renders_ledger_after_login(self):
        store = self.server.app.store
        task_id = store.add_task("captain", "Audit task", "Command-readable evidence.")
        store.add_evidence(task_id, "wesley", "Smoke result", "https://wesley.thesisko.com/status/", "Status page green.")
        token = self.server.app.security.sign_session("captain")

        status, body, _ = self.fetch("/evaluation", {"Cookie": f"portal_session={token}"})

        self.assertEqual(status, 200)
        self.assertIn("Protected Evaluation", body)
        self.assertIn("Audit task", body)
        self.assertIn("Smoke result", body)
        self.assertIn("Corrections required", body)


if __name__ == "__main__":
    unittest.main()
