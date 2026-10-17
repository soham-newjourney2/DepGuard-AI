# DepGuard AI — rules for Claude Code
Source of truth: `planning.md`. At session start read ONLY `planning.md` lines 1–60 (STATUS, LOG, PROTOCOL), then grep `^### P<n>` and read just the active phase + sections it cites.

- Follow planning.md §1 PROTOCOL exactly: one task → code + tests → `python tasks.py check` → update §0 STATUS + prepend LOG line → next task.
- Move to the next phase only when its Gate is fully green; then commit and tell me to `/clear`.
- API process never runs npm/node or anything from an upload — only the Docker worker does (§5.1).
- Never put untrusted text in `innerHTML`; use `dom.h()`.
- AI output must pass the grounding validator; never invent versions, CVEs or test results.
- UI must meet §6 (tokens, signature moments, quality bar) — no generic dashboards.
- Be terse: chat ≤3 lines, quiet test output, Grep before Read, ranged reads, no re-reading files you just wrote, Edit over rewrite.
