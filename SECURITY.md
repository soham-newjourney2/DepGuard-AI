# Security model

- The API process never executes npm, node, tests or any uploaded content. Only disposable Docker worker containers do.
- Uploads are size-, file-count- and ratio-limited; absolute paths, `..`, symlinks and nested archives are rejected or ignored.
- The test stage runs with no network, a read-only root, all capabilities dropped, as a non-root user, under a hard timeout. Only `npm test --if-present` is run, never a user-supplied command.
- Secrets are redacted from logs, reports and AI context. AI output is checked against the evidence it was given.
- No patch is applied without explicit human approval.

Report issues privately to the maintainers rather than opening a public issue.
