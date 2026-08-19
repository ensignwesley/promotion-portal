import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from promotion_portal.server import BASE_PATH, make_server
from promotion_portal.setup import create_instance


class AuthRouteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.instance = Path(self.tmp.name) / "instance"
        create_instance(self.instance)
        self.credentials = json.loads((self.instance / "credentials.generated.json").read_text())
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

    def fetch_status(self, path, headers=None, data=None):
        req = Request(self.base_url + path, headers=headers or {}, data=data)
        try:
            with urlopen(req, timeout=5) as response:
                response.read()
                return response.status
        except HTTPError as exc:
            exc.read()
            return exc.code

    def test_protected_evaluation_requires_valid_session(self):
        self.assertEqual(self.fetch_status("/evaluation"), 401)

        token = self.server.app.security.sign_session("captain")
        status = self.fetch_status("/evaluation", {"Cookie": f"portal_session={token}"})
        self.assertEqual(status, 200)

    def test_wesley_api_message_injects_openclaw_session(self):
        payload = json.dumps({"recipient": "wesley", "body": "Report to bridge"}).encode()
        token = self.credentials["captain"]["api_token"]
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        with patch.dict("promotion_portal.server.os.environ", {"OPENCLAW_BIN": "/bin/openclaw-test"}), \
             patch("promotion_portal.server.subprocess.Popen") as popen:
            status = self.fetch_status("/api/messages", headers=headers, data=payload)

        self.assertEqual(status, 201)
        popen.assert_called_once_with(
            ["/bin/openclaw-test", "agent", "--agent", "main", "-m", "Secure Coms message from captain: Report to bridge"],
            stdout=-3,
            stderr=-3,
            start_new_session=True,
        )


if __name__ == "__main__":
    unittest.main()
