# DepGuard AI

Explains *why* an npm dependency vulnerability matters to *your* project, proposes the smallest defensible fix, and verifies it in an isolated container.

## Quick start
```
python tasks.py setup   # venv + deps + playwright chromium
python tasks.py dev     # http://localhost:8000
python tasks.py check   # ruff + unit/api tests
```
Copy `.env.example` to `.env` to configure scanner, AI provider and verification mode. See `planning.md` for the full spec.
