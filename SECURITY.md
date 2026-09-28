# Security Policy

Lamsystems-commander exists to put a hard wall between an LLM and your
machine. A bypass of that wall is the most important bug this project can
have, so please report one rather than posting it publicly first.

## Reporting a bypass or vulnerability

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository page. If that is
unavailable, open an issue titled `[security] contact requested` with no
details and a maintainer will reach out.

Please include:

- The exact command string (or tool call) that got through
- Which layer you expected to catch it (see "Safety architecture" in the README)
- Your Python version, OS, and the model/client you were driving it with
- Whether it required a user click (sudo gate / destructive dialog) to land

Things that count as vulnerabilities here:

- A non-whitelisted binary executing in strict allowlist mode
- Any route to shell execution that skips `pre_filter` (interpreter `-c`,
  script paths, wrapper unwrapping, `uv run`, env-var tricks, quoting tricks)
- A destructive command running without a fresh `lc_confirm_destructive` token
- A sudo command running without a fresh approval, or the session password
  cache being reused for a destructive command
- File-tool writes landing outside the intended path or over protected files
- Network exfil or SSH getting past the Layer 3 gate

Things that are **not** vulnerabilities (documented design limits):

- The user approving a dialog they should not have. The last line of defence
  is your finger on Cancel, and the README says so.
- Anything that requires the whitelist to have been extended by the user
- Damage a whitelisted read-only tool can do to the *model's* context (prompt
  injection via file contents) — real, but out of scope for this server

## Supported versions

Only the latest release on `main` receives fixes. There is no LTS branch.

## Disclosure

Fixes are pushed with a CHANGELOG entry crediting the reporter (unless you ask
not to be named). No bounty programme — this is a one-person project.
