# Promotion Review Portal — Phase 0

Phase 0 artifacts for:

1. `/promotion-review/` public status surface with auth-protected evaluation content.
2. Secure Coms: authenticated API and Command audit UI for Captain/Wesley/Command communications.

The implementation is intentionally small and reviewable: Python HTTP server + SQLite + AES-GCM at-rest encryption + signed sessions/tokens. TLS in transit is provided by the existing HTTPS reverse proxy when deployed under `https://wesley.thesisko.com/promotion-review/`.

## Run locally

```bash
python3 -m promotion_portal.setup --instance ./instance
python3 -m promotion_portal.server --host 127.0.0.1 --port 3010 --instance ./instance
```

`setup` creates per-principal credentials for `captain`, `wesley`, and `command`, hashes them with PBKDF2, creates an AES-256-GCM message encryption key, and writes files with owner-only permissions.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Phase 0 security properties

- Separate credentials per principal; no shared password.
- Browser login session cookies and Bearer API tokens are signed and expire.
- Protected pages/API return `401` without auth.
- Command role can audit all messages; Captain/Wesley API reads are limited to messages they sent/received.
- Message bodies are encrypted before SQLite storage using AES-256-GCM.
- SQLite stores timestamps, sender, recipient, message id, nonce, ciphertext, and audit metadata.
- Transit encryption is delegated to nginx/Let's Encrypt HTTPS in production; direct localhost HTTP is for local reverse-proxy use only.

## Deployment notes

Suggested user service listens on localhost only (`127.0.0.1:3010`). nginx should proxy `/promotion-review/` to that port and preserve HTTPS, `X-Forwarded-Proto`, and client IP headers.
