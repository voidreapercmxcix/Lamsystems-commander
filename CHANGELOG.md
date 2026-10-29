# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Changed — BREAKING
- **Default mode is now `claude`: no binary allowlist.** Any installed binary
  runs; pipes, redirects, globs, `curl`, `ssh`, `gh`, package installs and
  inline `python3 -c` / `node -e` all work. The gates that remain in every
  mode: destructive wall + confirmation dialog, sudo gate, server-source
  protection, system-path write guard, shell-script approval, and the ban on
  `$(...)` / backticks. Built for driving the server from Claude.
- **`LAMSYSTEMS_COMMANDER_MODE=strict` restores the full pre-filter stack**
  (allowlist, dangerous flags, injection / traversal checks, redirect ban,
  interpreter and shell-script temp-dir gate, SSH gate, network-exfil gate,
  single-command process sessions) for leaving the server alone with a model
  you do not trust. Strict executes the shlex-rendered vetted tokens, not the
  raw string. An unknown mode refuses to start. Set it in the MCP client's
  `env` block.
- `lc_exec_command`'s tool description switches with the mode; strict
  regenerates the allowlist into it.

### Added
- Shell-script runs (`bash /abs/path.sh`, also sh/zsh/dash/ksh) behind the
  confirmation wall, with the approval token bound to the script's content.
- `gh`, `cargo`, `rustc`, `ninja` on the strict allowlist; `npm/pnpm/yarn run`
  allowed; cargo registry / install subcommands blocked.
- `test_prefilter_strict.py` (112 cases + 9 token tests); `test_prefilter.py`
  (75 + 7 + 9, claude mode) chains it so one command covers both modes.
- `nvme format` / `sanitize` / `delete-ns` / `write` / firmware subcommands on
  the destructive wall.

### Fixed
- **Approval dialogs could show no command.** zenity parses its text as
  Pango markup and kdialog as rich text, so any command containing `&`, `<`
  or `>` (every `&&`, every `2>&1`) failed to render and the dialog read
  "Are you sure you want to proceed?" with no command at all. zenity now runs
  with `--no-markup`, kdialog text is escaped, dialog stderr is written to the
  tool log instead of being swallowed, and both dialogs are 600px wide.
- On KDE Plasma, kdialog is tried before zenity (one dialog with command and
  password together; KWin rules can keep it on top). Detected via
  `XDG_CURRENT_DESKTOP` with a `/proc` kwin probe fallback, since MCP clients
  launch the server with a clean environment.
- `lc_confirm_destructive` treated a zenity launch failure (no display, crash)
  as a user decline and locked the command out for the session. Dialogs now
  discover `DISPLAY`/`WAYLAND_DISPLAY` from the session sockets, capture
  stderr, fall back zenity → kdialog, and only a real Cancel is cached.
- README documented the sudo gate as "no caching"; the opt-in
  `LAMSYSTEMS_COMMANDER_SUDO_CACHE` session cache and its TTL are now described.
- Session sudo cache path now runs `sudo -k` after each command, matching the
  password path. Previously a cached-password command left sudo's own
  timestamp primed for its default lifetime.

### Changed
- Every `rm` invocation is now destructive, not only recursive ones. A
  single-file delete needs its own `lc_confirm_destructive` token, so a
  session-allowed `lc_exec_command` can never delete a file without a
  per-command human approval.
- Tool annotations: only `lc_confirm_destructive` and `lc_kill_process` are
  flagged `destructiveHint: True`, so MCP clients honour "Always allow" on
  read/write/edit/move/exec/process tools instead of prompting on every call.
  Server-side gates are unchanged. See "Approval prompts" in the README.

## [0.1.0] - 2026-09-28

First public release.

### Added
- FastMCP server exposing 25 `lc_*` tools: shell, files, search, processes, git
- Six-layer safety architecture: stateless pre-filter pipeline, strict binary
  allowlist with wrapper unwrapping (`sudo`, `env`, `timeout`, `uv run`),
  file write guards, SSH / network-exfil gate, destructive-command hard wall
  with one-time confirmation tokens, and a sudo gate (elicitation, zenity,
  kdialog, pkexec)
- Opt-in session sudo password cache for non-destructive commands only
- Scratchpad offload for large command output, with BM25 search over it
- Tool call log at `~/.commander_workspace/tool_calls.log`
- `test_prefilter.py` harness (64 cases) and `check_import.py` smoke check
- Red-team findings and known limitations documented in the README

[Unreleased]: https://github.com/voidreapercmxcix/Lamsystems-commander/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/voidreapercmxcix/Lamsystems-commander/releases/tag/v0.1.0
