import argparse
import html
import json
import os
import shutil
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
        openclaw_bin = os.environ.get("OPENCLAW_BIN") or shutil.which("openclaw") or "/home/jarvis/.npm-global/bin/openclaw"
        subprocess.Popen(
            [openclaw_bin, "agent", "--agent", "main", "-m", f"Secure Coms message from {sender}: {body}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
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
                print(f"openclaw injection failed for message {mid}: {exc}", flush=True)
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
        rows = "".join(self.render_message(principal, m) for m in messages)
        role_note = "Command audit view: all encrypted message history visible." if principal == "command" else "Principal view: sent and received messages only."
        options = "".join(f"<option>{p}</option>" for p in sorted(RECIPIENTS))
        channel_status = "OPEN" if principal in PRINCIPALS else "CLOSED"
        return self.html_response(self.shell("Secure Coms", f"""
        <section class='lcars-hero'>
          <div class='lcars-cap'></div>
          <div><p class='eyebrow'>STARFLEET SECURE COMMUNICATIONS — USS THESISKO</p><h1>Secure Coms</h1><p>{role_note}</p></div>
        </section>
        <section class='communique-status' aria-label='channel status'>
          <span>Classification: Command Review / Restricted</span>
          <span>Channel: {channel_status}</span>
          <span>Session: {html.escape(self.display_name(principal))}</span>
        </section>
        <section class='comms-grid'>
          <div class='compose-panel'>
            <h2>Open channel</h2>
            <nav><a href='{BASE_PATH}/evaluation'>Evaluation</a> · <a href='{BASE_PATH}/logout'>Logout</a></nav>
            <form method='post' action='{BASE_PATH}/comms/send'>
              <label>Recipient <select name='recipient'>{options}</select></label>
              <label>Message <textarea name='body' rows='5' required></textarea></label>
              <button type='submit'>Send encrypted message</button>
            </form>
          </div>
          <div class='history-panel'>
            <div class='history-head'><span>Message history</span><span>{len(messages)} records</span></div>
            <div class='thread'>{rows or '<p class="empty">No messages yet.</p>'}</div>
          </div>
        </section>
        """))

    def display_name(self, principal: str):
        return {"captain": "CAPT Jarvis", "wesley": "ENS Wesley", "command": "ADM Command"}.get(principal, principal.upper())

    def insignia(self, principal: str):
        if principal == "captain":
            return "<span class='pips'><i></i><i></i><i></i><i></i></span>"
        if principal == "wesley":
            return "<span class='pips'><i></i></span>"
        if principal == "command":
            return "<span class='admiral-mark'>✦✦</span>"
        return "<span class='pips'><i></i></span>"

    def formatted_timestamp(self, value: str):
        parts = value.replace("T", " ").replace("Z", " UTC").split(".", 1)
        cleaned = parts[0]
        digits = "".join(ch for ch in value if ch.isdigit())
        stardate = f"SD {digits[2:7]}.{digits[7:9]}" if len(digits) >= 9 else "SD UNKNOWN"
        return f"{stardate} / {html.escape(cleaned)}"

    def render_message(self, principal: str, message: dict):
        sender_key = message["sender"]
        recipient_key = message["recipient"]
        sender = html.escape(self.display_name(sender_key))
        recipient = html.escape(self.display_name(recipient_key))
        body = html.escape(message["body"])
        timestamp = self.formatted_timestamp(message["created_at"])
        direction = "audit" if principal == "command" else ("sent" if sender_key == principal else "received")
        rank_class = f"rank-{sender_key}"
        icon = {"captain": "★", "wesley": "◆", "command": "⌂"}.get(sender_key, "•")
        return f"""
        <article class='bubble {direction} {rank_class}'>
          <div class='avatar'>{icon}</div>
          <div class='bubble-body'>
            <header><span class='identity'>{self.insignia(sender_key)}<strong>{sender}</strong></span><span>to {recipient}</span><time>{timestamp}</time></header>
            <p>{body}</p>
          </div>
        </article>
        """

    def shell(self, title: str, body: str):
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>
        <style>
        :root{{--bg:#050505;--panel:#120c05;--amber:#ff9f1a;--orange:#ff6b00;--gold:#ffd166;--peach:#ffb199;--cream:#ffe8c2;--blue:#7dd3fc;--muted:#c79257}}
        *{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(circle at top right,#1b1208 0,#050505 42rem);color:var(--cream);font:16px/1.5 system-ui,sans-serif}} body:before{{content:"";position:fixed;inset:0;background:linear-gradient(90deg,#0000 0 96%,#ff9f1a22 96% 97%,#0000 97%),linear-gradient(#0000 0 96%,#ff9f1a14 96% 97%,#0000 97%);background-size:48px 48px;pointer-events:none}} main{{max-width:1180px;margin:0 auto;padding:2rem;position:relative}} h1,h2{{letter-spacing:.03em;text-transform:uppercase}} .card,.compose-panel,.history-panel,.lcars-hero{{background:linear-gradient(135deg,#160f08,#070707);border:1px solid #ff9f1a66;border-radius:26px;padding:1.5rem;margin:1rem 0;box-shadow:0 18px 45px #0009}} .eyebrow{{color:var(--gold);text-transform:uppercase;letter-spacing:.18em;font-size:.78rem;font-weight:800}} a{{color:var(--gold)}} .button,button{{background:linear-gradient(90deg,var(--amber),var(--orange));color:#120800;border:0;border-radius:999px;padding:.8rem 1.2rem;font-weight:900;text-transform:uppercase;letter-spacing:.04em}} label{{display:block;margin:1rem 0;color:var(--gold);font-weight:700;text-transform:uppercase;font-size:.78rem;letter-spacing:.08em}} input,select,textarea{{width:100%;box-sizing:border-box;background:#080604;color:var(--cream);border:1px solid #ff9f1a88;border-radius:18px;padding:.85rem}} textarea{{resize:vertical}} .error{{color:#fecaca}}
        .lcars-hero{{display:grid;grid-template-columns:140px 1fr;gap:1.25rem;align-items:stretch;border-radius:42px 16px 16px 42px}} .lcars-cap{{min-height:145px;border-radius:34px 0 0 34px;background:linear-gradient(180deg,var(--amber) 0 38%,var(--orange) 38% 64%,var(--peach) 64%);box-shadow:inset -18px 0 #050505}} .lcars-hero h1{{font-size:clamp(2.2rem,7vw,5.5rem);line-height:.9;margin:.2rem 0;color:var(--amber)}} .lcars-hero p{{max-width:56rem}}
        .communique-status{{display:flex;flex-wrap:wrap;gap:.75rem;justify-content:space-between;margin:-.2rem 0 1rem;padding:.75rem 1rem;border-radius:999px;background:linear-gradient(90deg,#ff9f1a,#ff6b00 42%,#2a1705 42%);color:#130800;font-weight:1000;text-transform:uppercase;letter-spacing:.08em;box-shadow:0 14px 30px #0008}} .communique-status span:last-child{{color:var(--cream)}}
        .comms-grid{{display:grid;grid-template-columns:minmax(270px,340px) 1fr;gap:1.2rem;align-items:start}} .compose-panel{{border-radius:16px 42px 16px 42px;border-left:30px solid var(--orange)}} .history-panel{{padding:0;overflow:hidden;border-radius:42px 16px 42px 16px}} .history-head{{display:flex;justify-content:space-between;gap:1rem;background:linear-gradient(90deg,var(--orange),var(--amber));color:#120800;font-weight:1000;text-transform:uppercase;letter-spacing:.08em;padding:.85rem 1.25rem}} .thread{{padding:1.25rem;display:flex;flex-direction:column;gap:1rem}} .empty{{color:var(--muted);text-align:center}}
        .bubble{{display:grid;grid-template-columns:48px minmax(0,1fr);gap:.75rem;max-width:82%;align-items:start}} .bubble.sent{{align-self:end;grid-template-columns:minmax(0,1fr) 48px}} .bubble.sent .avatar{{grid-column:2;grid-row:1;background:var(--gold);color:#120800}} .bubble.sent .bubble-body{{grid-column:1;grid-row:1;background:#2a1705;border-color:var(--gold)}} .bubble.received .bubble-body{{background:#111;border-color:var(--orange)}} .bubble.audit{{max-width:96%}} .avatar{{width:48px;height:48px;border-radius:50%;display:grid;place-items:center;background:var(--orange);color:#130800;font-weight:1000;box-shadow:0 0 0 4px #000,0 0 0 6px #ff9f1a66}} .bubble-body{{border:1px solid #ff9f1a88;border-radius:20px;padding:.9rem 1rem;box-shadow:0 10px 24px #0008}} .bubble-body header{{display:flex;gap:.65rem;align-items:baseline;flex-wrap:wrap;color:var(--gold);font-size:.8rem;text-transform:uppercase;letter-spacing:.06em}} .bubble-body header time{{margin-left:auto;color:var(--muted);text-transform:none;letter-spacing:0}} .bubble-body p{{white-space:pre-wrap;margin:.55rem 0 0}} .identity{{display:inline-flex;gap:.5rem;align-items:center}} .pips{{display:inline-flex;gap:2px}} .pips i{{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}} .admiral-mark{{font-size:1rem;color:#fff;text-shadow:0 0 8px #fff}} .rank-captain .bubble-body{{background:linear-gradient(135deg,#211105,#0b0704);border-color:var(--gold)}} .rank-captain .avatar{{background:var(--gold)}} .rank-wesley .bubble-body{{background:linear-gradient(135deg,#160f08,#050505);border-color:var(--orange)}} .rank-wesley .avatar{{background:var(--orange)}} .rank-command{{max-width:98%}} .rank-command .bubble-body{{background:linear-gradient(135deg,#3a0707,#140202);border-color:#ffdf6e;box-shadow:0 0 0 1px #ffdf6e66,0 14px 35px #8b000066}} .rank-command .avatar{{background:#ffdf6e;color:#260000;box-shadow:0 0 0 4px #000,0 0 0 8px #9b111e}}
        @media (max-width:800px){{main{{padding:1rem}}.lcars-hero,.comms-grid{{grid-template-columns:1fr}}.lcars-cap{{min-height:34px;border-radius:28px;background:linear-gradient(90deg,var(--amber),var(--orange),var(--peach));box-shadow:inset 0 -10px #050505}}.bubble{{max-width:100%}}}}
        </style></head><body><main>{body}</main></body></html>"""

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
