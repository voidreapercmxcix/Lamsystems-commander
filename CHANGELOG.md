# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Changed
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

[Unreleased]: https://github.com/Voidreaper2026/Lamsystems-commander/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Voidreaper2026/Lamsystems-commander/releases/tag/v0.1.0
