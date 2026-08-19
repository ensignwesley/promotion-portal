import argparse
import html
import json
import os
import subprocess
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .security import PRINCIPALS, SecurityContext
from .storage import MessageStore

BASE_PATH = "/promotion-review"
RECIPIENTS = PRINCIPALS


def load_config(instance: Path) -> dict:
    with (instance / "config.json").open() as fh:
        return json.load(fh)


class PortalApp:
    def __init__(self, instance: Path):
        self.instance = instance
        self.security = SecurityContext(load_config(instance))
        self.store = MessageStore(instance / "messages.sqlite3")

    def encrypt_and_store(self, sender: str, recipient: str, body: str, client_ip: str = "", user_agent: str = "") -> int:
        if sender not in PRINCIPALS or recipient not in RECIPIENTS:
            raise ValueError("unknown principal")
        if not body.strip():
            raise ValueError("message body required")
        nonce, ciphertext = self.security.encrypt_message(body)
        return self.store.add_message(sender, recipient, nonce, ciphertext, client_ip, user_agent)

    def visible_messages(self, principal: str, limit: int = 100) -> list[dict]:
        rows = self.store.list_messages_for(principal, limit)
        out = []
        for row in rows:
            out.append({
                "id": row["id"],
                "created_at": row["created_at"],
                "sender": row["sender"],
                "recipient": row["recipient"],
                "body": self.security.decrypt_message(row["nonce"], row["ciphertext"]),
                "client_ip": row["client_ip"] or "",
                "user_agent": row["user_agent"] or "",
            })
        return out

    def inject_openclaw_message(self, sender: str, recipient: str, body: str) -> bool:
        if recipient != "wesley":
            return False
        subprocess.run(
            ["openclaw", "agent", "--agent", "main", "-m", f"Secure Coms message from {sender}: {body}"],
            timeout=30,
            check=True,
        )
        return True


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "PromotionPortal/0.1"

    @property
    def app(self) -> PortalApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = self.normalized_path()
        if path in ("/", ""):
            return self.redirect(BASE_PATH + "/")
        if path == BASE_PATH or path == BASE_PATH + "/":
            return self.public_status()
        if path == BASE_PATH + "/login":
            return self.login_page()
        if path == BASE_PATH + "/logout":
            return self.logout()
        if path == BASE_PATH + "/evaluation":
            principal = self.require_session()
            if not principal:
                return
            return self.evaluation_page(principal)
        if path == BASE_PATH + "/comms":
            principal = self.require_session()
            if not principal:
                return
            return self.comms_page(principal)
        if path == BASE_PATH + "/api/messages":
            principal = self.require_api()
            if not principal:
                return
            return self.json_response({"messages": self.app.visible_messages(principal)})
        if path == BASE_PATH + "/api/status":
            return self.json_response({"status": "phase0", "service": "promotion-review", "deliverables": ["portal", "secure-coms"]})
        return self.not_found()

    def do_POST(self):
        path = self.normalized_path()
        if path == BASE_PATH + "/login":
            return self.login_submit()
        if path == BASE_PATH + "/comms/send":
            principal = self.require_session()
            if not principal:
                return
            fields = self.read_form()
            try:
                self.app.encrypt_and_store(principal, fields.get("recipient", ""), fields.get("body", ""), self.client_ip(), self.headers.get("User-Agent", ""))
            except ValueError as exc:
                return self.html_response(self.shell("Send failed", f"<p class='error'>{html.escape(str(exc))}</p><p><a href='{BASE_PATH}/comms'>Back</a></p>"), HTTPStatus.BAD_REQUEST)
            return self.redirect(BASE_PATH + "/comms")
        if path == BASE_PATH + "/api/messages":
            principal = self.require_api()
            if not principal:
                return
            data = self.read_json()
            recipient = str(data.get("recipient", ""))
            body = str(data.get("body", ""))
            try:
                mid = self.app.encrypt_and_store(principal, recipient, body, self.client_ip(), self.headers.get("User-Agent", ""))
            except ValueError as exc:
                return self.json_response({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            delivered_to_openclaw = False
            try:
                delivered_to_openclaw = self.app.inject_openclaw_message(principal, recipient, body)
            except (OSError, subprocess.SubprocessError) as exc:
                return self.json_response({"id": mid, "status": "stored_delivery_failed", "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return self.json_response({"id": mid, "status": "stored", "delivered_to_openclaw": delivered_to_openclaw}, HTTPStatus.CREATED)
        return self.not_found()

    def normalized_path(self):
        return urlparse(self.path).path.rstrip("/") if urlparse(self.path).path != BASE_PATH + "/" else BASE_PATH + "/"

    def client_ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(min(length, 1024 * 64))

    def read_form(self):
        return {k: v[-1] for k, v in parse_qs(self.read_body().decode()).items()}

    def read_json(self):
        try:
            return json.loads(self.read_body().decode() or "{}")
        except json.JSONDecodeError:
            return {}

    def session_principal(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("portal_session")
        if not morsel:
            return None
        return self.app.security.verify_session(morsel.value)

    def bearer_principal(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return self.app.security.authenticate_api_token(auth.removeprefix("Bearer ").strip())

    def require_session(self):
        principal = self.session_principal()
        if not principal:
            self.html_response(self.shell("Authentication required", f"<p>Protected content requires login.</p><p><a href='{BASE_PATH}/login'>Log in</a></p>"), HTTPStatus.UNAUTHORIZED)
            return None
        return principal

    def require_api(self):
        principal = self.bearer_principal()
        if not principal:
            self.json_response({"error": "authentication required"}, HTTPStatus.UNAUTHORIZED)
            return None
        return principal

    def public_status(self):
        body = f"""
        <section class='card'>
          <p class='eyebrow'>Phase 0 / Aug 19</p>
          <h1>Promotion Review Portal</h1>
          <p class='score'>Current score: <strong>Phase 0 build in progress</strong></p>
          <p>Public status is intentionally visible. Evaluation details and Secure Coms require authenticated access.</p>
          <ul>
            <li>Deliverable 1: protected promotion evaluation portal.</li>
            <li>Deliverable 2: Secure Coms API and Command audit UI.</li>
          </ul>
          <p><a class='button' href='{BASE_PATH}/login'>Authenticate</a></p>
        </section>
        """
        return self.html_response(self.shell("Promotion Review Portal", body))

    def login_page(self):
        return self.html_response(self.shell("Login", f"""
        <section class='card'><h1>Authenticate</h1>
        <form method='post' action='{BASE_PATH}/login'>
          <label>Principal <select name='principal'><option>captain</option><option>wesley</option><option>command</option></select></label>
          <label>Password <input type='password' name='password' required></label>
          <button type='submit'>Log in</button>
        </form></section>
        """))

    def login_submit(self):
        fields = self.read_form()
        principal = fields.get("principal", "")
        if self.app.security.authenticate_password(principal, fields.get("password", "")):
            token = self.app.security.sign_session(principal)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", BASE_PATH + "/comms")
            self.send_header("Set-Cookie", f"portal_session={token}; HttpOnly; SameSite=Strict; Path={BASE_PATH}")
            self.end_headers()
            return
        return self.html_response(self.shell("Login failed", f"<p class='error'>Invalid credentials.</p><p><a href='{BASE_PATH}/login'>Try again</a></p>"), HTTPStatus.UNAUTHORIZED)

    def logout(self):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", BASE_PATH + "/")
        self.send_header("Set-Cookie", f"portal_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path={BASE_PATH}")
        self.end_headers()

    def evaluation_page(self, principal: str):
        return self.html_response(self.shell("Evaluation", f"""
        <section class='card'><p class='eyebrow'>Authenticated as {html.escape(principal)}</p>
        <h1>Protected Evaluation</h1>
        <p>Phase 0 protected content is reachable only after authentication. Detailed review material will be added during Phase 1.</p>
        <p><a href='{BASE_PATH}/comms'>Secure Coms</a></p></section>
        """))

    def comms_page(self, principal: str):
        messages = self.app.visible_messages(principal)
        rows = "".join(f"<article class='msg'><header>#{m['id']} {html.escape(m['created_at'])} — <b>{html.escape(m['sender'])}</b> to <b>{html.escape(m['recipient'])}</b></header><p>{html.escape(m['body'])}</p></article>" for m in messages)
        role_note = "Command audit view: all messages visible." if principal == "command" else "Principal view: sent and received messages only."
        options = "".join(f"<option>{p}</option>" for p in sorted(RECIPIENTS))
        return self.html_response(self.shell("Secure Coms", f"""
        <section class='card'><p class='eyebrow'>Authenticated as {html.escape(principal)}</p><h1>Secure Coms</h1><p>{role_note}</p>
        <nav><a href='{BASE_PATH}/evaluation'>Evaluation</a> · <a href='{BASE_PATH}/logout'>Logout</a></nav>
        <form method='post' action='{BASE_PATH}/comms/send'>
          <label>Recipient <select name='recipient'>{options}</select></label>
          <label>Message <textarea name='body' rows='4' required></textarea></label>
          <button type='submit'>Send encrypted message</button>
        </form></section>
        <section class='card'><h2>Audit history</h2>{rows or '<p>No messages yet.</p>'}</section>
        """))

    def shell(self, title: str, body: str):
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>
        <style>body{{margin:0;background:#08111f;color:#e9f2ff;font:16px/1.5 system-ui,sans-serif}}main{{max-width:920px;margin:0 auto;padding:2rem}}.card{{background:#111d2d;border:1px solid #2d496b;border-radius:16px;padding:1.5rem;margin:1rem 0;box-shadow:0 12px 40px #0005}}.eyebrow{{color:#5eead4;text-transform:uppercase;letter-spacing:.14em;font-size:.8rem}}a{{color:#7dd3fc}}.button,button{{background:#5eead4;color:#04111f;border:0;border-radius:10px;padding:.7rem 1rem;font-weight:700}}label{{display:block;margin:1rem 0}}input,select,textarea{{width:100%;box-sizing:border-box;background:#07101d;color:#e9f2ff;border:1px solid #38587a;border-radius:10px;padding:.7rem}}.msg{{border-top:1px solid #2d496b;padding:.8rem 0}}.msg header{{color:#b7c8dd}}.error{{color:#fecaca}}</style></head><body><main>{body}</main></body></html>"""

    def html_response(self, body: str, status=HTTPStatus.OK):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def json_response(self, payload: dict, status=HTTPStatus.OK):
        raw = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, location: str):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def not_found(self):
        self.html_response(self.shell("Not found", "<p>Not found.</p>"), HTTPStatus.NOT_FOUND)


def make_server(host: str, port: int, instance: Path):
    app = PortalApp(instance)
    server = ThreadingHTTPServer((host, port), PortalHandler)
    server.app = app  # type: ignore[attr-defined]
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description="Promotion Review Portal Phase 0 server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3010)
    parser.add_argument("--instance", default=os.environ.get("PROMOTION_PORTAL_INSTANCE", "./instance"))
    args = parser.parse_args(argv)
    server = make_server(args.host, args.port, Path(args.instance))
    print(f"serving promotion portal on http://{args.host}:{args.port}{BASE_PATH}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
