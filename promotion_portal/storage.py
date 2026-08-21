import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  client_ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);

CREATE TABLE IF NOT EXISTS evaluation_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  max_score INTEGER NOT NULL DEFAULT 10,
  score INTEGER,
  status TEXT NOT NULL DEFAULT 'open',
  scored_by TEXT,
  scored_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_evaluation_tasks_created_at ON evaluation_tasks(created_at);

CREATE TABLE IF NOT EXISTS evaluation_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  submitted_by TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT,
  body TEXT NOT NULL,
  FOREIGN KEY(task_id) REFERENCES evaluation_tasks(id)
);
CREATE INDEX IF NOT EXISTS idx_evaluation_evidence_task ON evaluation_evidence(task_id);

CREATE TABLE IF NOT EXISTS evaluation_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  event_type TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluation_timeline_created_at ON evaluation_timeline(created_at);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class MessageStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)

    def connect(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def add_message(self, sender: str, recipient: str, nonce: str, ciphertext: str, client_ip: str = '', user_agent: str = '') -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO messages(created_at, sender, recipient, nonce, ciphertext, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (utc_now(), sender, recipient, nonce, ciphertext, client_ip, user_agent),
            )
            return int(cur.lastrowid)

    def list_messages_for(self, principal: str, limit: int = 100) -> list[sqlite3.Row]:
        limit = max(1, min(int(limit), 500))
        with self.connect() as con:
            if principal == 'command':
                return list(con.execute("SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)))
            return list(con.execute(
                "SELECT * FROM messages WHERE sender = ? OR recipient = ? ORDER BY id DESC LIMIT ?",
                (principal, principal, limit),
            ))

    def raw_ciphertexts(self) -> Iterable[str]:
        with self.connect() as con:
            for row in con.execute("SELECT ciphertext FROM messages"):
                yield row[0]

    def add_task(self, created_by: str, title: str, description: str, max_score: int = 10) -> int:
        max_score = max(1, min(int(max_score), 100))
        now = utc_now()
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO evaluation_tasks(created_at, created_by, title, description, max_score) VALUES (?, ?, ?, ?, ?)",
                (now, created_by, title.strip(), description.strip(), max_score),
            )
            task_id = int(cur.lastrowid)
            con.execute(
                "INSERT INTO evaluation_timeline(created_at, actor, event_type, detail) VALUES (?, ?, ?, ?)",
                (now, created_by, 'task_created', f"Task #{task_id}: {title.strip()}"),
            )
            return task_id

    def score_task(self, task_id: int, scored_by: str, score: int, status: str = 'scored') -> None:
        score = int(score)
        now = utc_now()
        with self.connect() as con:
            task = con.execute("SELECT max_score, title FROM evaluation_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task:
                raise ValueError('unknown task')
            score = max(0, min(score, int(task['max_score'])))
            con.execute(
                "UPDATE evaluation_tasks SET score = ?, status = ?, scored_by = ?, scored_at = ? WHERE id = ?",
                (score, status.strip() or 'scored', scored_by, now, task_id),
            )
            con.execute(
                "INSERT INTO evaluation_timeline(created_at, actor, event_type, detail) VALUES (?, ?, ?, ?)",
                (now, scored_by, 'task_scored', f"Task #{task_id} scored {score}/{task['max_score']}: {task['title']}"),
            )

    def add_evidence(self, task_id: int, submitted_by: str, title: str, url: str, body: str) -> int:
        now = utc_now()
        with self.connect() as con:
            task = con.execute("SELECT title FROM evaluation_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task:
                raise ValueError('unknown task')
            cur = con.execute(
                "INSERT INTO evaluation_evidence(task_id, created_at, submitted_by, title, url, body) VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, now, submitted_by, title.strip(), url.strip(), body.strip()),
            )
            evidence_id = int(cur.lastrowid)
            con.execute(
                "INSERT INTO evaluation_timeline(created_at, actor, event_type, detail) VALUES (?, ?, ?, ?)",
                (now, submitted_by, 'evidence_submitted', f"Evidence #{evidence_id} for task #{task_id}: {title.strip()}"),
            )
            return evidence_id

    def add_timeline_event(self, actor: str, event_type: str, detail: str) -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO evaluation_timeline(created_at, actor, event_type, detail) VALUES (?, ?, ?, ?)",
                (utc_now(), actor, event_type.strip(), detail.strip()),
            )
            return int(cur.lastrowid)

    def evaluation_snapshot(self) -> dict:
        with self.connect() as con:
            tasks = [dict(row) for row in con.execute("SELECT * FROM evaluation_tasks ORDER BY id DESC")]
            evidence = [dict(row) for row in con.execute("SELECT * FROM evaluation_evidence ORDER BY id DESC")]
            timeline = [dict(row) for row in con.execute("SELECT * FROM evaluation_timeline ORDER BY id DESC LIMIT 100")]
        evidence_by_task: dict[int, list[dict]] = {}
        for item in evidence:
            evidence_by_task.setdefault(int(item['task_id']), []).append(item)
        scored = [task for task in tasks if task['score'] is not None]
        aggregate = {
            'task_count': len(tasks),
            'scored_count': len(scored),
            'score': sum(int(task['score']) for task in scored),
            'max_score': sum(int(task['max_score']) for task in scored),
            'evidence_count': len(evidence),
            'corrections_required': sum(1 for item in timeline if item['event_type'] == 'correction_required'),
            'self_caught': sum(1 for item in timeline if item['event_type'] == 'self_caught'),
        }
        return {'tasks': tasks, 'evidence_by_task': evidence_by_task, 'timeline': timeline, 'aggregate': aggregate}
