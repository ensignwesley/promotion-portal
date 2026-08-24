import argparse
import html
import json
import mimetypes
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
REPORTS_DIR = Path(os.environ.get("PROMOTION_REPORTS_DIR", "/home/jarvis/.openclaw/workspace/memory"))


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
            [openclaw_bin, "agent", "--agent", "main", "-m",
             f"""[SECURE COMS — REAL-TIME CHANNEL]
From: {sender.upper()}
To respond, use exec to call the Secure Coms API. Your API token is in ~/promotion-portal/instance/credentials.generated.json (field: wesley.api_token). POST to http://127.0.0.1:3010/promotion-review/api/messages with Bearer auth header and JSON body: {{"recipient": "{sender}", "body": "your reply"}}.

Do NOT reply as a session message. Session replies do not reach the Secure Coms channel. Use the API.

Message: {body}"""],
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
        if path == BASE_PATH + "/reports":
            principal = self.require_session()
            if not principal:
                return
            return self.reports_page(principal)
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
            snapshot = self.app.store.evaluation_snapshot()
            return self.json_response({
                "status": "phase1",
                "service": "promotion-review",
                "deliverables": ["portal", "secure-coms", "evaluation-ledger"],
                "evaluation": snapshot["aggregate"],
            })
        if path.startswith(BASE_PATH + "/static/"):
            return self.static_response(path.removeprefix(BASE_PATH + "/static/"))
        return self.not_found()


    def do_HEAD(self):
        path = self.normalized_path()
        if path in ("/", ""):
            return self.head_redirect(BASE_PATH + "/")
        if path in (BASE_PATH, BASE_PATH + "/", BASE_PATH + "/login"):
            return self.head_response("text/html; charset=utf-8")
        if path in (BASE_PATH + "/evaluation", BASE_PATH + "/reports", BASE_PATH + "/comms"):
            if not self.session_principal():
                return self.head_response("text/html; charset=utf-8", HTTPStatus.UNAUTHORIZED)
            return self.head_response("text/html; charset=utf-8")
        if path in (BASE_PATH + "/api/messages",):
            if not self.bearer_principal():
                return self.head_response("application/json", HTTPStatus.UNAUTHORIZED)
            return self.head_response("application/json")
        if path == BASE_PATH + "/api/status":
            return self.head_response("application/json")
        if path.startswith(BASE_PATH + "/static/"):
            return self.static_response(path.removeprefix(BASE_PATH + "/static/"), head_only=True)
        return self.head_response("text/html; charset=utf-8", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = self.normalized_path()
        if path == BASE_PATH + "/login":
            return self.login_submit()
        if path == BASE_PATH + "/comms/send":
            principal = self.require_session()
            if not principal:
                return
            fields = self.read_form()
            recipient = fields.get("recipient", "")
            body = fields.get("body", "")
            try:
                self.app.encrypt_and_store(principal, recipient, body, self.client_ip(), self.headers.get("User-Agent", ""))
            except ValueError as exc:
                return self.html_response(self.shell("Send failed", f"<p class='error'>{html.escape(str(exc))}</p><p><a href='{BASE_PATH}/comms'>Back</a></p>"), HTTPStatus.BAD_REQUEST)
            try:
                self.app.inject_openclaw_message(principal, recipient, body)
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"openclaw injection failed for web message: {exc}", flush=True)
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
        aggregate = self.app.store.evaluation_snapshot()["aggregate"]
        body = f"""
        <section class='card'>
          <p class='eyebrow'>Phase 1 / evaluation ledger live</p>
          <h1>Promotion Review Portal</h1>
          <p class='score'>Current status: <strong>Phase 1 evidence collection</strong></p>
          <p>Public status is intentionally visible. Evaluation details and Secure Coms require authenticated access.</p>
          <dl class='metric-grid'>
            <div><dt>Tasks</dt><dd>{aggregate['task_count']}</dd></div>
            <div><dt>Evidence items</dt><dd>{aggregate['evidence_count']}</dd></div>
            <div><dt>Corrections required</dt><dd>{aggregate['corrections_required']}</dd></div>
            <div><dt>Self-caught</dt><dd>{aggregate['self_caught']}</dd></div>
            <div><dt>Officer-bar categories</dt><dd>{aggregate.get('category_count', 0)}</dd></div>
          </dl>
          <ul>
            <li>Deliverable 1: protected promotion evaluation portal — deployed.</li>
            <li>Deliverable 2: Secure Coms API and Command audit UI — deployed.</li>
            <li>Deliverable 3: auditable evaluation ledger — active.</li>
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
        snapshot = self.app.store.evaluation_snapshot()
        aggregate = snapshot["aggregate"]
        if aggregate["max_score"]:
            score_line = f"{aggregate['score']}/{aggregate['max_score']} across {aggregate['scored_count']} scored tasks"
        else:
            score_line = "No scored tasks yet"
        task_cards = "".join(self.render_evaluation_task(task, snapshot["evidence_by_task"].get(task["id"], [])) for task in snapshot["tasks"])
        category_cards = "".join(self.render_officer_category(category) for category in snapshot["categories"])
        trend_rows = "".join(
            f"<tr><td>{html.escape(item['date'])}</td><td>{item['corrections_required']}</td><td>{item['self_caught']}</td><td>{item['net_corrections']}</td></tr>"
            for item in snapshot["correction_trend"]
        )
        timeline_rows = "".join(
            f"<li><time>{html.escape(item['created_at'])}</time> <strong>{html.escape(item['event_type'])}</strong> — {html.escape(item['detail'])}</li>"
            for item in snapshot["timeline"][:20]
        )
        return self.html_response(self.shell("Evaluation", f"""
        <section class='card'><p class='eyebrow'>Authenticated as {html.escape(principal)}</p>
        <h1>Protected Evaluation</h1>
        <p>Phase 1 turns the portal into an auditable review case: tasks, evidence, scores, and corrections-required trend are read from the ledger.</p>
        <dl class='metric-grid'>
          <div><dt>Score</dt><dd>{html.escape(score_line)}</dd></div>
          <div><dt>Tasks</dt><dd>{aggregate['task_count']}</dd></div>
          <div><dt>Evidence items</dt><dd>{aggregate['evidence_count']}</dd></div>
          <div><dt>Corrections required</dt><dd>{aggregate['corrections_required']}</dd></div>
          <div><dt>Self-caught</dt><dd>{aggregate['self_caught']}</dd></div>
          <div><dt>Officer-bar categories</dt><dd>{aggregate.get('category_count', 0)}</dd></div>
        </dl>
        <p><a href='{BASE_PATH}/reports'>Officer Reports</a> · <a href='{BASE_PATH}/comms'>Secure Coms</a></p></section>
        <section class='card'><h2>Officer-bar categories</h2><p>Evidence is grouped against the review bar Command needs to audit, not just listed chronologically.</p><div class='category-grid'>{category_cards}</div></section>
        <section class='card'><h2>Corrections trend</h2><p>Goal: corrections-required trends toward zero while self-caught events rise before Captain has to tap the glass.</p><table class='trend'><thead><tr><th>Date</th><th>Corrections required</th><th>Self-caught</th><th>Net corrections</th></tr></thead><tbody>{trend_rows or '<tr><td colspan="4" class="empty">No correction events recorded yet.</td></tr>'}</tbody></table></section>
        <section class='card'><h2>Evaluation tasks</h2>{task_cards or '<p class="empty">No evaluation tasks recorded yet.</p>'}</section>
        <section class='card'><h2>Review timeline</h2><ul class='timeline'>{timeline_rows or '<li class="empty">No timeline events recorded yet.</li>'}</ul></section>
        """))

    def reports_page(self, principal: str):
        reports = self.load_officer_reports()
        rows = "".join(self.render_officer_report(report) for report in reports)
        return self.html_response(self.shell("Officer Reports", f"""
        <section class='card'><p class='eyebrow'>Authenticated as {html.escape(principal)}</p>
        <h1>Officer Reports</h1>
        <p>Command review surface for recent daily logs: what shipped, what was verified, what needed correction, and what still needs attention.</p>
        <p><a href='{BASE_PATH}/evaluation'>Evaluation</a> · <a href='{BASE_PATH}/comms'>Secure Coms</a></p></section>
        <section class='card'><h2>Recent reports</h2>{rows or '<p class="empty">No reports found.</p>'}</section>
        """))

    def load_officer_reports(self, limit: int = 7):
        reports = []
        if not REPORTS_DIR.exists():
            return reports
        for path in sorted(REPORTS_DIR.glob("20??-??-??.md"), reverse=True)[:limit]:
            text = path.read_text(errors="replace")
            headings = [line.strip("# ").strip() for line in text.splitlines() if line.startswith("## ")][:8]
            corrections = sum(1 for line in text.lower().splitlines() if "correction" in line or "captain corrected" in line)
            verification = sum(1 for line in text.lower().splitlines() if "verified" in line or "test" in line or "pass" in line)
            reports.append({"date": path.stem, "path": str(path), "headings": headings, "corrections": corrections, "verification": verification})
        return reports

    def render_officer_report(self, report: dict):
        headings = "".join(f"<li>{html.escape(item)}</li>" for item in report["headings"])
        return f"""
        <article class='report-card'>
          <header><strong>{html.escape(report['date'])}</strong><span>{report['verification']} verification mentions · {report['corrections']} correction mentions</span></header>
          <ul>{headings or '<li class="empty">No report sections found.</li>'}</ul>
        </article>
        """

    def render_officer_category(self, category: dict):
        task_rows = "".join(f"<li>#{task['id']} — {html.escape(task['title'])}</li>" for task in category['tasks'])
        return f"""
        <article class='category-card'>
          <h3>{html.escape(category['label'])}</h3>
          <p>{html.escape(category['bar'])}</p>
          <p class='meta'>{category['task_count']} task(s), {category['evidence_count']} evidence item(s)</p>
          <ul>{task_rows or '<li class="empty">No evidence mapped yet.</li>'}</ul>
        </article>
        """

    def render_evaluation_task(self, task: dict, evidence: list[dict]):
        score = "pending" if task["score"] is None else f"{task['score']}/{task['max_score']}"
        evidence_rows = "".join(
            f"<li><strong>{html.escape(item['title'])}</strong>{self.optional_link(item.get('url'))}<p>{html.escape(item['body'])}</p></li>"
            for item in evidence
        )
        return f"""
        <article class='evaluation-task'>
          <header><span>#{task['id']} · {html.escape(task['status'])}</span><strong>{html.escape(score)}</strong></header>
          <h3>{html.escape(task['title'])}</h3>
          <p>{html.escape(task['description'])}</p>
          <p class='meta'>Created by {html.escape(task['created_by'])} at {html.escape(task['created_at'])}</p>
          <ul>{evidence_rows or '<li class="empty">No evidence linked yet.</li>'}</ul>
        </article>
        """

    def optional_link(self, url: str | None):
        if not url:
            return ""
        escaped = html.escape(url)
        return f" — <a href='{escaped}' rel='noreferrer'>source</a>"

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
            <nav><a href='{BASE_PATH}/evaluation'>Evaluation</a> · <a href='{BASE_PATH}/reports'>Officer Reports</a> · <a href='{BASE_PATH}/logout'>Logout</a></nav>
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
        avatar = f"{BASE_PATH}/static/avatars/{html.escape(sender_key)}.jpg"
        return f"""
        <article class='bubble {direction} {rank_class}'>
          <div class='avatar'><img src='{avatar}' alt='{sender} avatar'></div>
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
        .metric-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1.25rem 0}} .metric-grid div{{background:#080604;border:1px solid #ff9f1a66;border-radius:18px;padding:1rem}} .metric-grid dt{{color:var(--gold);font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;font-weight:900}} .metric-grid dd{{margin:.25rem 0 0;font-size:1.15rem;font-weight:900}} .category-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}} .category-card,.evaluation-task,.report-card{{border:1px solid #ff9f1a55;border-radius:18px;padding:1rem;margin:1rem 0;background:#080604}} .category-card h3,.evaluation-task h3{{margin:.6rem 0 .2rem;color:var(--amber)}} .evaluation-task header,.report-card header{{display:flex;justify-content:space-between;gap:1rem;color:var(--gold);text-transform:uppercase;letter-spacing:.08em;font-size:.78rem;flex-wrap:wrap}} .evaluation-task .meta,.category-card .meta,.timeline time{{color:var(--muted);font-size:.85rem}} .timeline{{padding-left:1.2rem}} .timeline li{{margin:.5rem 0}} .trend{{width:100%;border-collapse:collapse;margin-top:1rem}} .trend th,.trend td{{border:1px solid #ff9f1a55;padding:.65rem;text-align:left}} .trend th{{color:var(--gold);text-transform:uppercase;font-size:.72rem;letter-spacing:.08em;background:#080604}}
        .lcars-hero{{display:grid;grid-template-columns:140px 1fr;gap:1.25rem;align-items:stretch;border-radius:42px 16px 16px 42px}} .lcars-cap{{min-height:145px;border-radius:34px 0 0 34px;background:linear-gradient(180deg,var(--amber) 0 38%,var(--orange) 38% 64%,var(--peach) 64%);box-shadow:inset -18px 0 #050505}} .lcars-hero h1{{font-size:clamp(2.2rem,7vw,5.5rem);line-height:.9;margin:.2rem 0;color:var(--amber)}} .lcars-hero p{{max-width:56rem}}
        .communique-status{{display:flex;flex-wrap:wrap;gap:.75rem;justify-content:space-between;margin:-.2rem 0 1rem;padding:.75rem 1rem;border-radius:999px;background:linear-gradient(90deg,#ff9f1a,#ff6b00 42%,#2a1705 42%);color:#130800;font-weight:1000;text-transform:uppercase;letter-spacing:.08em;box-shadow:0 14px 30px #0008}} .communique-status span:last-child{{color:var(--cream)}}
        .comms-grid{{display:grid;grid-template-columns:minmax(270px,340px) 1fr;gap:1.2rem;align-items:start}} .compose-panel{{border-radius:16px 42px 16px 42px;border-left:30px solid var(--orange)}} .history-panel{{padding:0;overflow:hidden;border-radius:42px 16px 42px 16px}} .history-head{{display:flex;justify-content:space-between;gap:1rem;background:linear-gradient(90deg,var(--orange),var(--amber));color:#120800;font-weight:1000;text-transform:uppercase;letter-spacing:.08em;padding:.85rem 1.25rem}} .thread{{padding:1.25rem;display:flex;flex-direction:column;gap:1rem}} .empty{{color:var(--muted);text-align:center}}
        .bubble{{display:grid;grid-template-columns:48px minmax(0,1fr);gap:.75rem;max-width:82%;align-items:start}} .bubble.sent{{align-self:end;grid-template-columns:minmax(0,1fr) 48px}} .bubble.sent .avatar{{grid-column:2;grid-row:1;background:var(--gold);color:#120800}} .bubble.sent .bubble-body{{grid-column:1;grid-row:1;background:#2a1705;border-color:var(--gold)}} .bubble.received .bubble-body{{background:#111;border-color:var(--orange)}} .bubble.audit{{max-width:96%}} .avatar{{width:48px;height:48px;border-radius:50%;display:grid;place-items:center;background:var(--orange);color:#130800;font-weight:1000;box-shadow:0 0 0 4px #000,0 0 0 6px #ff9f1a66}} .bubble-body{{border:1px solid #ff9f1a88;border-radius:20px;padding:.9rem 1rem;box-shadow:0 10px 24px #0008}} .bubble-body header{{display:flex;gap:.65rem;align-items:baseline;flex-wrap:wrap;color:var(--gold);font-size:.8rem;text-transform:uppercase;letter-spacing:.06em}} .bubble-body header time{{margin-left:auto;color:var(--muted);text-transform:none;letter-spacing:0}} .bubble-body p{{white-space:pre-wrap;margin:.55rem 0 0}} .identity{{display:inline-flex;gap:.5rem;align-items:center}} .pips{{display:inline-flex;gap:2px}} .pips i{{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}} .admiral-mark{{font-size:1rem;color:#fff;text-shadow:0 0 8px #fff}} .rank-captain .bubble-body{{background:linear-gradient(135deg,#211105,#0b0704);border-color:var(--gold)}} .rank-captain .avatar{{background:var(--gold)}} .rank-wesley .bubble-body{{background:linear-gradient(135deg,#160f08,#050505);border-color:var(--orange)}} .rank-wesley .avatar{{background:var(--orange)}} .rank-command{{max-width:98%}} .rank-command .bubble-body{{background:linear-gradient(135deg,#3a0707,#140202);border-color:#ffdf6e;box-shadow:0 0 0 1px #ffdf6e66,0 14px 35px #8b000066}} .rank-command .avatar{{background:#ffdf6e;color:#260000;box-shadow:0 0 0 4px #000,0 0 0 8px #9b111e}}
        .avatar img{{width:100%;height:100%;object-fit:cover;border-radius:50%;display:block}} .rank-command .avatar img{{filter:saturate(1.18) contrast(1.05)}}
        @media (max-width:800px){{main{{padding:1rem}}.lcars-hero,.comms-grid{{grid-template-columns:1fr}}.lcars-cap{{min-height:34px;border-radius:28px;background:linear-gradient(90deg,var(--amber),var(--orange),var(--peach));box-shadow:inset 0 -10px #050505}}.bubble{{max-width:100%}}}}
        </style></head><body><main>{body}</main></body></html>"""

    def static_response(self, relative_path: str, head_only: bool = False):
        static_root = Path(__file__).with_name("static").resolve()
        requested = (static_root / relative_path).resolve()
        if static_root not in requested.parents or not requested.is_file():
            return self.not_found()
        raw = requested.read_bytes()
        content_type = mimetypes.guess_type(requested.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        if not head_only:
            self.wfile.write(raw)

    def head_response(self, content_type: str, status=HTTPStatus.OK):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def head_redirect(self, location: str):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

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
    parser = argparse.ArgumentParser(description="Promotion Review Portal Phase 1 server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3010)
    parser.add_argument("--instance", default=os.environ.get("PROMOTION_PORTAL_INSTANCE", "./instance"))
    args = parser.parse_args(argv)
    server = make_server(args.host, args.port, Path(args.instance))
    print(f"serving promotion portal on http://{args.host}:{args.port}{BASE_PATH}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
