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
