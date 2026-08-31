# Promotion Review Portal — Phase 1

Promotion review infrastructure for:

1. `/promotion-review/` public status surface.
2. `/promotion-review/evaluation` auth-protected evaluation ledger with officer-bar categories, grouped evidence, scores, review timeline, corrections-required, self-caught, and correction-trend metrics.
3. Officer Reports: authenticated daily-log review surface for recent shipped work, verification, corrections, and attention items.
4. Security Judgment: authenticated control/risk/trust-boundary page for Command review.
5. Secure Coms: authenticated API and Command audit UI for Captain/Wesley/Command communications.

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

## Phase 1 review properties

- Evaluation data is stored in SQLite tables for tasks, linked evidence, and timeline events.
- The protected evaluation page renders score aggregates, evidence count, corrections-required count, self-caught count, officer-bar categories, grouped evidence, and correction-trend rows from the ledger.
- `/promotion-review/api/status` exposes the same aggregate metrics, including `category_count` and `correction_trend`, for machine checks.
- `/promotion-review/reports` renders recent daily logs as Officer Reports for Command review.
- `/promotion-review/security` renders implemented controls, runtime deployment evidence, trust boundaries, open risks, and next security-evidence steps for Command review.
- Dynamic GET routes also support HEAD so link checkers and monitors do not receive false `501` failures.

## Security properties

- Separate credentials per principal; no shared password.
- Browser login session cookies and Bearer API tokens are signed and expire.
- Repeated failed login or API authentication attempts from the same client are throttled for 15 minutes.
- Protected pages/API return `401` without auth, including the Security Judgment page.
- The Security Judgment page reports owner-only modes for instance secrets/database and nginx deployment markers without exposing secret values.
- Static asset routing resolves paths under the package `static/` directory and rejects traversal outside that root.
- Command role can audit all messages; Captain/Wesley API reads are limited to messages they sent/received.
- Message bodies are encrypted before SQLite storage using AES-256-GCM.
- SQLite stores timestamps, sender, recipient, message id, nonce, ciphertext, and audit metadata.
- Transit encryption is delegated to nginx/Let's Encrypt HTTPS in production; direct localhost HTTP is for local reverse-proxy use only.

## Deployment notes

Suggested user service listens on localhost only (`127.0.0.1:3010`). nginx should proxy `/promotion-review/` to that port and preserve HTTPS, `X-Forwarded-Proto`, and client IP headers.
