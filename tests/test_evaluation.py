import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

import promotion_portal.server as server_module
from promotion_portal.server import BASE_PATH, make_server
from promotion_portal.setup import create_instance
from promotion_portal.storage import MessageStore, officer_category_for


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
        store.add_timeline_event("wesley", "useful_shipped", "Added a daily useful shipped ledger.")

        snapshot = store.evaluation_snapshot()

        self.assertEqual(snapshot["aggregate"]["task_count"], 1)
        self.assertEqual(snapshot["aggregate"]["score"], 4)
        self.assertEqual(snapshot["aggregate"]["max_score"], 5)
        self.assertEqual(snapshot["aggregate"]["evidence_count"], 1)
        self.assertEqual(snapshot["aggregate"]["corrections_required"], 1)
        self.assertEqual(snapshot["aggregate"]["self_caught"], 1)
        self.assertEqual(snapshot["aggregate"]["category_count"], 1)
        self.assertEqual(snapshot["aggregate"]["useful_shipped"], 1)
        self.assertEqual(snapshot["aggregate"]["useful_work_days"], 1)
        self.assertEqual(snapshot["readiness"]["useful_shipped_today"], 1)
        self.assertEqual(snapshot["readiness"]["score_percent"], 80.0)
        self.assertIn("readiness", snapshot["aggregate"])
        self.assertEqual(snapshot["correction_trend"][0]["net_corrections"], 0)
        self.assertIn(task_id, snapshot["evidence_by_task"])

    def test_security_category_wins_over_generic_portal_keyword(self):
        task = {
            "title": "Promotion Portal security review",
            "description": "Name trust boundaries, auth controls, token risk, private data protection, and threat paths.",
        }
        evidence = [{"title": "Security judgment page", "body": "Documents risk, auth, token, private data, and overclaim controls."}]

        category = officer_category_for(task, evidence)

        self.assertEqual(category["key"], "judgment_security")

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
        self.assertEqual(payload["evaluation"]["category_count"], 1)
        self.assertIn("correction_trend", payload["evaluation"])
        self.assertIn("readiness", payload["evaluation"])
        self.assertEqual(payload["evaluation"]["readiness"]["useful_shipped_today"], 0)

    def test_public_status_matches_phase_one_ledger_state(self):
        store = self.server.app.store
        task_id = store.add_task("captain", "Review portal", "Evidence ledger visible.")
        store.add_evidence(task_id, "wesley", "Rendered page", "", "Evaluation page has metrics.")
        store.add_timeline_event("captain", "correction_required", "Remove stale public phase copy.")
        store.add_timeline_event("wesley", "useful_shipped", "Published officer-material daily work tracking.")

        status, body, content_type = self.fetch("")

        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("Phase 1 / evaluation ledger live", body)
        self.assertIn("Phase 1 evidence collection", body)
        self.assertIn("<dt>Tasks</dt><dd>1</dd>", body)
        self.assertIn("<dt>Evidence items</dt><dd>1</dd>", body)
        self.assertIn("<dt>Corrections required</dt><dd>1</dd>", body)
        self.assertIn("<dt>Officer-bar categories</dt><dd>1</dd>", body)
        self.assertIn("<dt>Useful shipped</dt><dd>1</dd>", body)

    def test_head_status_routes_do_not_return_501(self):
        status, _, content_type = self.fetch("/api/status", method="HEAD")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)

        token = self.server.app.security.sign_session("captain")
        status, _, content_type = self.fetch("/evaluation", {"Cookie": f"portal_session={token}"}, method="HEAD")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)

    def test_officer_reports_page_renders_recent_daily_logs(self):
        report_dir = self.instance / "reports"
        report_dir.mkdir()
        (report_dir / "2026-08-23.md").write_text("""# Daily log\n\n## Phase 1 work\n- Verified portal tests pass.\n- Captain correction tracked.\n\n## Fleet gate\n- Preflight PASS.\n""")
        old_reports_dir = server_module.REPORTS_DIR
        server_module.REPORTS_DIR = report_dir
        self.addCleanup(setattr, server_module, "REPORTS_DIR", old_reports_dir)
        token = self.server.app.security.sign_session("captain")

        status, body, _ = self.fetch("/reports", {"Cookie": f"portal_session={token}"})

        self.assertEqual(status, 200)
        self.assertIn("Officer Reports", body)
        self.assertIn("Decision synthesis", body)
        self.assertIn("Promotion signal:", body)
        self.assertIn("Concern:", body)
        self.assertIn("Next evidence needed:", body)
        self.assertIn("Recent correction debt", body)
        self.assertIn("Phase 1 work", body)
        self.assertIn("Shipped / useful", body)
        self.assertIn("Verification", body)
        self.assertIn("Corrections", body)
        self.assertIn("Attention / risk", body)
        self.assertIn("Score movement", body)
        self.assertIn("Command brief:", body)
        self.assertIn("Verified portal tests pass.", body)
        self.assertIn("Captain correction tracked.", body)

    def test_security_page_renders_runtime_evidence_without_secret_values(self):
        token = self.server.app.security.sign_session("captain")

        status, body, _ = self.fetch("/security", {"Cookie": f"portal_session={token}"})

        self.assertEqual(status, 200)
        self.assertIn("Runtime evidence checked", body)
        self.assertIn("config.json: mode 600", body)
        self.assertIn("credentials.generated.json: mode 600", body)
        self.assertIn("messages.sqlite3: mode 600", body)
        self.assertIn("nginx deployment marker", body)
        self.assertNotIn("captain_password", body)
        self.assertNotIn("api_token", body)

    def test_evaluation_page_renders_ledger_after_login(self):
        store = self.server.app.store
        task_id = store.add_task("captain", "Audit task", "Command-readable evidence.")
        store.add_evidence(task_id, "wesley", "Smoke result", "https://wesley.thesisko.com/status/", "Status page green.")
        store.add_timeline_event("wesley", "useful_shipped", "Added a Command-auditable daily useful shipped ledger.")
        token = self.server.app.security.sign_session("captain")

        status, body, _ = self.fetch("/evaluation", {"Cookie": f"portal_session={token}"})

        self.assertEqual(status, 200)
        self.assertIn("Protected Evaluation", body)
        self.assertIn("Audit task", body)
        self.assertIn("Smoke result", body)
        self.assertIn("Corrections required", body)
        self.assertIn("Officer-bar categories", body)
        self.assertIn("Operational stewardship", body)
        self.assertIn("Corrections trend", body)
        self.assertIn("Daily useful shipped", body)
        self.assertIn("Command-auditable daily useful shipped ledger", body)
        self.assertIn("Promotion readiness", body)
        self.assertIn("Useful shipped today", body)
        self.assertIn("Score percent", body)


if __name__ == "__main__":
    unittest.main()
