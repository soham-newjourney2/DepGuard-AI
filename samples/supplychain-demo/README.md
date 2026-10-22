# supplychain-demo (scan-only)

Planted supply-chain signals for the DepGuard demo. **Never install this project**: it is never
run by DepGuard (not in the verify allowlist) and the malicious version below no longer exists on
the npm registry.

| Planted signal | Where |
|---|---|
| Malicious package (OSV MAL-2025-25475, GHSA-mfc2-93pr-jf92) | `loadyaml@1.0.2` — removed by npm security; its lockfile entry has no integrity hash because the real one is unknown |
| Git dependency | `left-pad` resolved from `git+ssh://github.com/stevemao/left-pad` |
| Typosquat look-alike of `express` | `expresss@0.0.0` (a real, empty package on npm) |
| Committed password | `config/db.js` — a made-up database password in the code |

Expected results live in `samples/_answers/supplychain-demo.json` (`expected_risks`, `source: planted-by-design`).
