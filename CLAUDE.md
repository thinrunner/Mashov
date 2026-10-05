# Mashov Hub — project memory

Family tool on top of Mashov (משו"ב): 2 children, 2 different schools (two Mashov accounts, different `semel`).
Communicate with the owner in Russian. UI language: Russian; Mashov content is Hebrew (render with `dir="auto"`).

## People
- Owner: builds and runs the system, hosts it on his Mac, enters SMS codes, receives service alerts.
- Wife: main day-to-day user.

## Core problem (drives every design choice)
Mashov is slow — opening a notification in the official app takes long. Requirements that follow:
- Background sync into local SQLite; UI and bot read only local data, never call Mashov at view time.
- Notifications carry the full content (grade + subject, full teacher message text, what changed) so nothing needs opening.
- Deep links open our own page (< 1 s), not Mashov.

## Decisions
- MVP instead of full docs/SPEC.md: Python service + SQLite + Telegram bot + basic web UI (owner defines structure). No Docker, Tailscale, passkey at start.
- Auth: SMS-only for now (owner's choice). Spike first (Phase 0), then core.
- Secrets in macOS Keychain; children's data never in the repo or in cloud sessions. Spike runs on the owner's Mac.

## Status
- Phase 0 spike ready: `spike/phase0.py`, run steps in README. Waiting for owner's `findings-*.md` + `probe-*.log`.
- Key unknowns: does `devicePass` re-login (`POST /api/loginDevice`) work for web clients; session lifetime; one login for both schools (`user/bindings`, `changeSchool`).
- Known: SMS request (`user/otp/request`) needs a Cloudflare Turnstile captcha → a bot cannot request SMS itself. Details: docs/api-findings.md.

## Open questions to the owner
- Does the wife actually use Telegram daily (vs WhatsApp)? Notification channel must be where she already is.
- Web UI outside home: Tailscale on her phone, or notifications-only until web is ready?
- Which phone number is registered for SMS in each school?
- Owner's Mac: Mac mini or MacBook (sleep = no sync)?
