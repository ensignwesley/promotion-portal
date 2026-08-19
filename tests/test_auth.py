import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from promotion_portal.server import BASE_PATH, make_server
from promotion_portal.setup import create_instance


class AuthRouteTest(unittest.TestCase):
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

    def fetch_status(self, path, headers=None):
        req = Request(self.base_url + path, headers=headers or {})
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


if __name__ == "__main__":
    unittest.main()
