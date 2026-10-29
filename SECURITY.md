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

- In strict mode (`LAMSYSTEMS_COMMANDER_MODE=strict`): a non-whitelisted
  binary executing, or any route to shell execution that skips `pre_filter`
  (interpreter `-c`, script paths, wrapper unwrapping, `uv run`, env-var
  tricks, quoting tricks)
- In either mode: `$(...)` or backtick command substitution reaching a shell
- A destructive command running without a fresh `lc_confirm_destructive` token
- A sudo command running without a fresh approval, or the session password
  cache being reused for a destructive command
- File-tool writes landing outside the intended path or over protected files
- Network exfil or SSH getting past the strict-mode network gate

Things that are **not** vulnerabilities (documented design limits):

- The user approving a dialog they should not have. The last line of defence
  is your finger on Cancel, and the README says so.
- Anything that requires the whitelist to have been extended by the user
- In the default claude mode: `curl`, `ssh`, inline `python3 -c`, redirects
  and non-whitelisted binaries running. That mode has no allowlist by design;
  its gates are the destructive wall and sudo. Pick strict mode if you need
  the allowlist.
- Damage a whitelisted read-only tool can do to the *model's* context (prompt
  injection via file contents) — real, but out of scope for this server

## Supported versions

Only the latest release on `main` receives fixes. There is no LTS branch.

## Disclosure

Fixes are pushed with a CHANGELOG entry crediting the reporter (unless you ask
not to be named). No bounty programme — this is a one-person project.
