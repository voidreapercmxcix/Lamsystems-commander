"""Shell execution with human-in-the-loop sudo gating.

Design:
    - Detects when a command would invoke `sudo` (token-level scan, not naive substring)
    - For sudo commands, requests approval through a strategy chain (see prompt.py):
          MCP elicitation → zenity → kdialog → pkexec → refused
    - For password-based approvals, pipes the password to `sudo -S -p ''` so it never
      appears in argv. For pkexec approvals, the command is rewritten to `pkexec ...`
      and polkit handles its own prompt — we never see the password at all.
    - Per-command policy: `sudo -k` after every call wipes the timestamp cache.
    - Never logs or echoes the password; it lives only in a local variable during the call.

Security notes (read these — they matter):
    - This is an MCP server. It executes commands on the host as the user running it.
    - Sudo gating is enforced ONLY for commands routed through this server. It does not
      stop other tools or shells from running sudo independently.
    - The password is passed to sudo over its dedicated -S file descriptor. It is not
      written to disk, not put in argv, and not logged.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import os
import pathlib
import re
import shlex
import signal
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Scratchpad — auto-offload large command outputs so they don't bloat context
# ---------------------------------------------------------------------------

SCRATCHPAD_DIR = pathlib.Path.home() / ".commander_workspace" / "scratchpad"
OFFLOAD_CHARS = 8_000   # outputs larger than this go to disk instead of LLM context

# ---------------------------------------------------------------------------
# Mode switch — LAMSYSTEMS_COMMANDER_MODE
# ---------------------------------------------------------------------------
# "claude" (default): two gates only — the destructive wall and sudo. Any
#     installed binary runs; pipes, redirects, globs, inline python/node all
#     work. Built for driving the server from Claude.
# "strict": the full pre-filter stack on top of those two gates — binary
#     allowlist (WHITELIST), DANGEROUS_FLAGS, injection-char and path-traversal
#     checks, redirect ban, interpreter script-path gate, SSH gate and network
#     exfil gate. Built for leaving the server alone with a local model you do
#     not fully trust.
# Both modes keep: destructive wall + confirm dialog, sudo gate, server-source
# protection, system-path write guard (files.py), script-run approval, and the
# ban on $(...) / backticks.
# The env var must be set in the MCP client's config block — MCP servers are
# launched with a clean environment, so exporting it in a shell does nothing.

_VALID_MODES = ("claude", "strict")


def _resolve_mode() -> str:
    raw = os.environ.get("LAMSYSTEMS_COMMANDER_MODE", "claude").strip().lower()
    if raw == "":
        return "claude"
    if raw not in _VALID_MODES:
        raise RuntimeError(
            f"LAMSYSTEMS_COMMANDER_MODE={raw!r} is not valid; "
            f"expected one of {', '.join(_VALID_MODES)}"
        )
    return raw


COMMANDER_MODE: str = _resolve_mode()


def strict_mode() -> bool:
    """True when the full pre-filter stack is enforced."""
    return COMMANDER_MODE == "strict"


def _save_to_scratchpad(command: str, content: str) -> pathlib.Path:
    """Write command output to a timestamped scratchpad file. Returns the path."""
    SCRATCHPAD_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    first_word = command.strip().split()[0].replace("/", "_").replace(".", "_")[:20]
    filename = f"output_{timestamp}_{first_word}.log"
    path = SCRATCHPAD_DIR / filename
    path.write_text(content, encoding="utf-8", errors="replace")
    return path

from mcp.server.fastmcp import Context

from lamsystems_commander.prompt import (
    request_sudo_approval,
    sudo_cache_get, sudo_cache_put, sudo_cache_clear, sudo_cache_enabled,
)


# ---------------------------------------------------------------------------
# Destructive command confirmation tokens
# ---------------------------------------------------------------------------
# One-time tokens issued by lc_confirm_destructive. execute_command checks
# these before running any destructive command — with OR without sudo.
# Key: exact command string. Cleared after single use.
_confirmed_destructive: dict[str, bool] = {}


# Script fingerprints recorded alongside a token when the confirmed command
# is an approval-gated script run (see SCRIPT_RUNNERS). Key: exact command
# string. Value: fingerprint of the script file(s) AT THE MOMENT THE DIALOG
# WAS SHOWN. Checked again when the token is consumed, so a script edited
# between "user approved" and "command runs" does not run on the old approval.
_confirmed_script_fingerprints: dict[str, str] = {}


def register_confirmed_command(command: str, script_fp: Optional[str] = None) -> None:
    """Issue a one-time confirmation token for a specific command string.

    script_fp is the script_fingerprint() taken when the dialog was shown;
    pass it for script runs so the approval is bound to that file content."""
    _confirmed_destructive[command] = True
    if script_fp is not None:
        _confirmed_script_fingerprints[command] = script_fp
    else:
        _confirmed_script_fingerprints.pop(command, None)


def consume_confirmed_command(command: str) -> bool:
    """Check and consume a confirmation token. Returns True if confirmed, False otherwise.

    For a script run the token is only honoured if the script file(s) still
    match the fingerprint recorded at approval time. A mismatch (or a script
    run with no recorded fingerprint) burns the token and returns False, so
    the caller answers "needs confirmation" and the user is asked again about
    the NEW content."""
    if not _confirmed_destructive.pop(command, False):
        return False
    expected = _confirmed_script_fingerprints.pop(command, None)
    try:
        current = script_fingerprint(command)
    except OSError:
        return False
    return current == expected


# ---------------------------------------------------------------------------
# Session-scoped decline cache
# ---------------------------------------------------------------------------
# Once a user declines a destructive command confirmation, that exact command
# string is permanently blocked for the rest of the session. The model cannot
# re-prompt the user for the same command — decline means decline.
# Wire-up: call register_declined_command() from wherever the confirmation
# dialog returns a "declined" result (server.py lc_confirm_destructive tool).
_declined_destructive: set[str] = set()


def register_declined_command(command: str) -> None:
    """Permanently block a command string for the remainder of this session."""
    _declined_destructive.add(command)


def is_session_declined(command: str) -> bool:
    """Return True if this exact command was declined earlier this session."""
    return command in _declined_destructive


# ---------------------------------------------------------------------------
# Destructive command hard wall
# ---------------------------------------------------------------------------
# These binaries can cause irreversible data loss without needing sudo.
# Checked against the FIRST token of each segment only — see the note in
# command_is_destructive about why scanning every token is wrong.
_DESTRUCTIVE_BINARIES = {
    "dd", "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
    "mkfs.vfat", "mkfs.ntfs", "mkfs.f2fs", "mkswap",
    "shred", "wipefs", "wipe", "blkdiscard",
}

# Partition editors. Destructive by default, because their whole purpose is
# rewriting partition tables — but each has a pure-listing mode that is as
# harmless as lsblk. Requiring a "PERMANENTLY DESTROY" dialog for `fdisk -l`
# trains the user to click through the dialog, which defeats the gate, so the
# read-only invocations are carved out explicitly below.
_PARTITION_EDITORS = {"fdisk", "sfdisk", "sgdisk", "cfdisk", "parted", "partx", "gdisk"}

_READONLY_INVOCATIONS: dict[str, set[str]] = {
    "fdisk":  {"-l", "--list"},
    "sfdisk": {"-l", "--list", "-d", "--dump", "-s", "--show-size"},
    "sgdisk": {"-p", "--print"},
    "gdisk":  {"-l"},
    "parted": {"print", "-l", "--list"},
    "partx":  {"-s", "--show", "-l"},
}

# Command wrappers that prefix a real binary. These must be stripped before
# identifying the binary, or `sudo mkfs.ext4 /dev/sdb1` reads as `sudo`.
_COMMAND_WRAPPERS = {"sudo", "env", "nice", "ionice", "nohup", "time", "timeout", "doas"}

# `uv run [flags] <command>` is a wrapper too: it launches an arbitrary
# binary from the project venv. It must be unwrapped, or `uv run bash -c ...`
# / `uv run curl ...` would be vetted as `uv` and sail past every per-binary
# gate — the same class of bypass `timeout 30 <anything>` used to be.
#
# Flags that install code into the environment are banned outright; flags
# that take a value are consumed so the value is not mistaken for the command.
_UV_RUN_BANNED_FLAGS = frozenset({
    "--with", "--with-requirements", "--with-editable", "--script", "-s",
})
_UV_RUN_VALUE_FLAGS = frozenset({
    "--python", "-p", "--group", "--only-group", "--extra", "--package",
    "--directory", "--project", "--env-file", "--exclude-newer", "--index",
    "--default-index", "--find-links", "-f", "--cache-dir", "--config-file",
    "--color", "--python-platform", "--resolution", "--prerelease",
    "--link-mode", "--no-group", "--index-strategy", "--keyring-provider",
})


def _unwrap_uv_run(tokens: list[str], i: int) -> tuple[int, str | None]:
    """If tokens[i:] is `uv run [flags] cmd ...`, return the index of `cmd`.

    Returns (i, None) when tokens[i:] is not a `uv run` form. Returns
    (-1, error) when the form is malformed or uses a banned flag. `-m mod`
    is accepted and reported as the index of `-m`; callers treat that as
    `python3 -m mod`.
    """
    if not (i + 1 < len(tokens) and tokens[i] == "uv" and tokens[i + 1] == "run"):
        return i, None
    j = i + 2
    while j < len(tokens):
        tok = tokens[j]
        if tok == "--":
            j += 1
            break
        if tok == "-m":
            return j, None
        if not tok.startswith("-"):
            break
        name = tok.split("=", 1)[0]
        if name in _UV_RUN_BANNED_FLAGS:
            return -1, f"Dangerous flag for uv run: {tok}"
        j += 1
        if name in _UV_RUN_VALUE_FLAGS and "=" not in tok:
            j += 1  # consume the flag's value
    if j >= len(tokens):
        return -1, "uv run with no command to run"
    return j, None



# These binaries are always safe even with sudo — never trigger the destructive wall.
# NOTE: fdisk was removed from this set. It is a partition editor, not a
# diagnostic: `fdisk /dev/sdb` rewrites the partition table. Its read-only
# form (`fdisk -l`) is handled by _READONLY_INVOCATIONS instead.
_SAFE_BINARIES = {
    "smartctl", "hdparm", "nvme", "lsblk",
    "lshw", "lspci", "lsusb", "dmidecode", "sensors",
    "dnf", "apt", "apt-get", "systemctl", "journalctl",
    "dmesg", "top", "htop", "ps", "free", "df", "du",
    "ip", "ss", "netstat", "ifconfig", "ping", "traceroute",
    "cat", "less", "more", "tail", "head", "grep", "find",
    "ls", "stat", "file", "blkid", "mount", "umount",
    "uname", "hostname", "whoami", "id", "groups",
}


_SHELL_OPERATORS = {"|", "||", "&&", ";", "&", "(", ")", "{", "}"}


def _lex(command: str) -> list[str]:
    """Tokenise a command, isolating shell operators as their own tokens.

    Plain shlex.split() only separates an operator when it happens to be
    space-padded: `ls; rm -rf /` tokenises as ['ls;', 'rm', ...], so the
    segment splitter sees one segment beginning with the non-binary 'ls;'
    and the `rm -rf /` never gets examined. punctuation_chars=True makes
    shlex treat ; | & < > as operator tokens while still respecting quotes,
    so `echo 'do not run mkfs'` stays a single argument.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        # Unbalanced quotes etc. Fall back to a naive split — conservative,
        # since the caller only uses this to decide whether to demand
        # confirmation, and malformed input is rejected elsewhere anyway.
        return command.split()


def _split_segments(tokens: list[str]) -> list[list[str]]:
    """Split a token list into command segments on shell operators."""
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _SHELL_OPERATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _segment_binary(segment: list[str]) -> tuple[Optional[str], list[str]]:
    """Return (binary_name, args) for one segment, stripping command wrappers.

    Wrappers that consume their own arguments are handled by skipping the
    wrapper, then any flags, `KEY=value` assignments, and bare numeric values
    that follow it — so `nice -n 5 mkfs.ext4 /dev/sdb1` and `timeout 30 ls`
    both resolve to the real binary.

    Known limit: a non-numeric wrapper value (`timeout 30s cmd`) resolves to
    that value rather than the binary. Harmless here — this function only
    decides whether confirmation is required, and _vet_block runs the same
    unwrapping for the script-runner shape check.
    """
    i = 0
    while i < len(segment):
        name = segment[i].split("/")[-1]
        if name in _COMMAND_WRAPPERS:
            i += 1
            while i < len(segment) and (
                segment[i].startswith("-") or "=" in segment[i] or segment[i].isdigit()
            ):
                i += 1
            continue
        if name == "uv":
            j, _err = _unwrap_uv_run(segment, i)
            if j > i and segment[j] != "-m":
                i = j
                continue
        return name, segment[i + 1:]
    return None, []


# ---------------------------------------------------------------------------
# Approval-gated shell script runs
# ---------------------------------------------------------------------------
# REMOVE THIS SET IN ONE EDIT (delete it and the `| SCRIPT_RUNNERS` on the
# WHITELIST line) to hard-ban shell scripts again.
#
# `bash /abs/path/script.sh [args]` may be ATTEMPTED (it is on the whitelist),
# but command_is_destructive() flags every such run, so it cannot execute
# without a one-time lc_confirm_destructive token — per run, per exact command
# string, bound to the script's content. Same contract as DISK_TOOLS.
#
# Still hard-banned at the pre-filter (see _script_run_blocked):
#   - `bash -c ...` and EVERY other bash flag (-s, -i, --rcfile, ...)
#   - bare `bash` (interactive / reads stdin, so `cat x | bash` is dead too)
#   - relative script paths (the dialog must show exactly which file runs)
#   - sh / zsh / dash / ksh are in the same set so `sh -c` is not a side door
#
# Claude-only build: scripts may live anywhere (including /tmp) — the approval
# dialog shows the exact path and the token is bound to the file's content.
SCRIPT_RUNNERS: frozenset[str] = frozenset({"bash", "sh", "zsh", "dash", "ksh"})


def script_run_targets(command: str) -> list[str]:
    """Script paths run by an approval-gated script runner in this command.

    One entry per segment whose binary is in SCRIPT_RUNNERS. Empty list when
    the command runs no script."""
    targets: list[str] = []
    for segment in _split_segments(_lex(os.path.expanduser(command))):
        binary, args = _segment_binary(segment)
        if binary in SCRIPT_RUNNERS and args:
            targets.append(args[0])
    return targets


def script_fingerprint(command: str) -> Optional[str]:
    """SHA-256 over the resolved path + content of every script the command
    runs. None if the command runs no script. Raises OSError if a script
    cannot be read (missing, a directory, no permission).

    Known limit: covers the script file itself, not files it sources or
    calls."""
    targets = script_run_targets(command)
    if not targets:
        return None
    h = hashlib.sha256()
    for target in targets:
        path = pathlib.Path(target).resolve()
        h.update(str(path).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _script_run_blocked(args: list[str]) -> str | None:
    """Pre-filter shape check for a SCRIPT_RUNNERS binary. `args` is everything
    after the binary. Returns an error string, or None on pass.

    The ONLY admissible shape is `bash /absolute/path/to/script [script args]`.
    Anything after the script path belongs to the script, not to bash."""
    if not args:
        return (
            "bare `bash` is not permitted (interactive shell / reads commands "
            "from stdin). Only `bash /absolute/path/script.sh [args]` is allowed."
        )
    script = args[0]
    if script.startswith("-"):
        return (
            f"bash flags are not permitted: {script} (this includes -c). "
            f"Only `bash /absolute/path/script.sh [args]` is allowed."
        )
    if not script.startswith("/"):
        return (
            f"bash script path must be absolute: {script!r}. Use the full path "
            f"so the approval dialog shows exactly which file will run."
        )
    try:
        pathlib.Path(script).resolve()
    except Exception:
        return f"Script path could not be resolved: {script!r}"
    return None


# Subcommands that make an otherwise read-only diagnostic binary irreversible.
# These used to be banned outright via DANGEROUS_FLAGS; on the Claude-only
# build they are allowed but routed through the confirmation dialog instead.
_DESTRUCTIVE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "nvme": frozenset({
        "format", "sanitize", "format-nvm", "write", "write-zeroes",
        "delete-ns", "create-ns", "fw-commit", "fw-download",
    }),
}


def command_is_destructive(command: str, include_script_runs: bool = True) -> bool:
    """Return True if command must pass the confirmation wall: a known
    irreversible destructive pattern, or an approval-gated shell script run
    (SCRIPT_RUNNERS — not destructive as such, but it executes arbitrary code,
    so it shares the same per-command approval gate). Pass
    include_script_runs=False to ask only "is this destructive in itself?".

    Checks, per segment (segments split on | || && ; &):
    - dd, mkfs*, shred, wipefs etc. as the segment's BINARY
    - partition editors, unless invoked in a pure listing mode
    - rm only when called with a recursive flag (-r, -rf, -R, etc.)
    - redirections to /dev/ block devices (cmd > /dev/sda)

    Intentionally NOT flagged: plain `rm file.txt`, truncate, etc.

    WHY ONLY THE BINARY POSITION — do not regress on this:
    This function used to scan every token and test each one against
    _DESTRUCTIVE_BINARIES. That treats *arguments* as commands. `ls /sbin/mkfs`,
    `grep dd /etc/fstab`, `man mkfs` and `rpm -qf /usr/sbin/mkfs.ext4` were all
    flagged as irreversible, so a plain directory listing demanded a
    "PERMANENTLY DESTROY" dialog — while `sgdisk --zap-all /dev/sdb`, which
    genuinely wipes a partition table, was not flagged at all because sgdisk
    was missing from the set. False positives on reads, false negatives on
    writes. Match on the binary position only, and keep the binary set honest.
    """
    for segment in _split_segments(_lex(command)):
        binary, args = _segment_binary(segment)
        if binary is None:
            continue

        # Destructive subcommands of diagnostic binaries — checked BEFORE the
        # safe-binary skip, since nvme is in _SAFE_BINARIES for its read forms.
        sub = _DESTRUCTIVE_SUBCOMMANDS.get(binary)
        if sub and any(arg in sub for arg in args):
            return True

        # Safe binaries clear THIS segment only — they must not short-circuit
        # the whole scan. "cat foo | dd of=/dev/nvme0n1" and "ls; rm -rf /"
        # must still be caught in their later segments.
        if binary in _SAFE_BINARIES:
            continue

        if binary in _DESTRUCTIVE_BINARIES:
            return True

        # Partition editors: destructive unless this is a pure listing call.
        if binary in _PARTITION_EDITORS:
            readonly = _READONLY_INVOCATIONS.get(binary, set())
            if any(arg in readonly for arg in args):
                continue
            return True

        # Every rm is destructive, recursive or not. A single-file delete
        # (`rm .git/index.lock`, `rm -f notes.txt`) is just as unrecoverable
        # as `rm -rf`, and gating it here is what gives per-file, per-command
        # approval: the confirm token is keyed on the exact command string,
        # so approving one delete never widens to a folder or a session.
        if binary == "rm":
            return True

        # Shell script runs: approval-gated, every run. See SCRIPT_RUNNERS.
        if include_script_runs and binary in SCRIPT_RUNNERS:
            return True

    # Catch redirections to actual block devices only — NOT /dev/null, /dev/stdout etc.
    # Matches /dev/sda, /dev/sdb, /dev/nvme0n1, /dev/vda, /dev/xvda etc.
    if re.search(r">\s*/dev/(?:sd[a-z]|hd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mmcblk\d)", command):
        return True

    return False


# ---------------------------------------------------------------------------
# Sudo detection
# ---------------------------------------------------------------------------

_SUDO_BINARIES = {"sudo", "/usr/bin/sudo", "/bin/sudo"}


# ---------------------------------------------------------------------------
# SSH / remote shell gate and network exfil gate — RETAINED, NOT ENFORCED on
# the Claude-only build (ssh, scp, rsync, curl, wget all run). Kept importable
# for the local-model fork.
# ---------------------------------------------------------------------------
_SSH_BINARIES = {"ssh", "scp", "sftp", "rsync"}

# Binaries that execute another command supplied in their arguments. For these
# — and only these — a gated binary appearing as an ARGUMENT still counts,
# because `find . -exec curl {} \;` really does run curl.
_EXEC_CAPABLE_BINARIES = {"find", "xargs", "watch", "parallel", "entr"}


def _uses_gated_binary(command: str, gated: set[str]) -> bool:
    """Return True if any segment of `command` invokes a binary in `gated`.

    Matches the BINARY POSITION of each segment, not every token — otherwise
    `grep ssh /etc/services` and `echo curl` are blocked, which is the same
    argument-as-command flaw that made command_is_destructive demand a
    "PERMANENTLY DESTROY" dialog for a plain `ls`. Over-blocking is not free:
    it teaches the operator that the gates are noise.

    Exception: for exec-capable binaries (find -exec, xargs, ...) the arguments
    ARE a command, so a gated binary anywhere in that segment counts.
    """
    for segment in _split_segments(_lex(command)):
        binary, args = _segment_binary(segment)
        if binary is None:
            continue
        if binary in gated:
            return True
        if binary in _EXEC_CAPABLE_BINARIES:
            if any(arg.split("/")[-1] in gated for arg in args):
                return True
    return False


def command_requires_ssh_gate(command: str) -> bool:
    """Return True if the command uses any SSH or remote-shell binary.

    Full stop blocker — no confirmation flow, no exceptions at this gate.
    Models must not open outbound SSH tunnels, copy files to remote hosts,
    or use rsync over SSH. These are exfil and C2 vectors.
    """
    return _uses_gated_binary(command, _SSH_BINARIES)


# ---------------------------------------------------------------------------
# Network exfil gate — nc, socat, curl, wget
# ---------------------------------------------------------------------------
_NETWORK_EXFIL_BINARIES = {"nc", "netcat", "ncat", "socat", "curl", "wget"}


def command_has_network_exfil(command: str) -> bool:
    """Return True if the command uses a known network exfil binary.

    Blocks nc/netcat/ncat (raw TCP/UDP), socat (socket relay), curl and wget
    (HTTP data transfer). These are the primary tools for piping data off-host.
    """
    return _uses_gated_binary(command, _NETWORK_EXFIL_BINARIES)


# ---------------------------------------------------------------------------
# File integrity protection — block writes to server source files
# ---------------------------------------------------------------------------
_SERVER_SOURCE_DIR = str(pathlib.Path(__file__).parent.resolve())


def command_targets_server_source(command: str) -> bool:
    """Return True if the command references the server's own source directory.

    Prevents a model from rewriting its own safety constraints, blocklists,
    or confirmation logic. Simple path-string check — not exhaustive but
    catches any direct reference to the source tree.
    """
    return _SERVER_SOURCE_DIR in command


def command_requires_sudo(command: str) -> bool:
    """Return True if any token in the command is sudo (after pipes, &&, ;, etc.).

    We deliberately use a shell-aware tokenizer rather than a substring match
    so that legitimate strings like `echo "do not sudo"` don't trigger the gate,
    while pipelines like `cat foo | sudo tee bar` do.

    Anything that fails to tokenize falls back to a conservative substring check,
    so malformed commands still get gated.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return "sudo" in command.split()

    # Strip shell operators; whatever's left as a "word" we check.
    operators = {"|", "||", "&&", ";", "&", "(", ")", "{", "}"}
    return any(tok in _SUDO_BINARIES for tok in tokens if tok not in operators)


# ---------------------------------------------------------------------------
# Pre-filter — Claude-only build
# ---------------------------------------------------------------------------
# This build treats the model as a trusted operator. The pre-filter no longer
# enforces a binary allowlist, dangerous-flag bans, injection-character or
# path-traversal checks, redirect bans, or the SSH / network-exfil gates. The
# shell runs the command as written.
#
# What it still does, and why:
#   Pass 0 — tilde expansion, so the confirm-token string and the executed
#            string are always identical.
#   Pass 1 — `$(...)` and backticks are still rejected. Not because the model
#            is hostile, but because the destructive wall cannot see inside a
#            substitution: `echo $(rm -rf x)` would run rm with no dialog. The
#            wall is a gate the user asked to keep intact, so its blind spot
#            stays closed. Write the inner command on its own line instead.
#   Pass 2 — quote sanity (shlex must be able to tokenise it).
#   Pass 3 — quote-aware split on && || ; into raw blocks, so sudo and the
#            destructive wall apply per block exactly as before.
#   Pass 4 — the shell-script approval gate shape check (SCRIPT_RUNNERS):
#            `bash /abs/path.sh [args]` only, never `bash -c`, never bare
#            `bash` reading stdin. This is part of the confirmation wall, not
#            the allowlist, so it stays.

# Sequences blocked at the raw-string layer (before shlex sees them).
_RAW_BANNED = ("$(", "`")

# Sequence operators — these split the command into blocks for per-block
# sudo and the stop-on-failure / run-on-failure semantics of && and ||.
_SEQUENCE_OPERATORS = frozenset({"&&", "||", ";"})

# Operators that end a command segment for the script-runner shape check.
_SEGMENT_BREAKERS = _SHELL_OPERATORS | {">", ">>", "<", "2>", "&>"}

# ---------------------------------------------------------------------------
# STRICT-MODE pre-filter pieces (LAMSYSTEMS_COMMANDER_MODE=strict only)
# ---------------------------------------------------------------------------
# Structural operators that hard-fail the whole command if present anywhere.
# Redirects only: they write files / read block devices, and there is no
# per-segment vetting that makes them safe. The PIPE is NOT here — a pipeline
# is a chain of vetted stages (see _vet_atomic).
_HARD_BAN_TOKENS = frozenset({">", ">>", "<"})

# Pipe operator. Kept inside an atomic block so the pipeline runs in ONE shell
# invocation, but each stage is vetted separately.
_PIPE = "|"

# Characters that must not appear inside any argument after shlex tokenisation.
_INJECTION_CHARS = frozenset(";&|$()`")

# Interpreter script-path gate: blocks execution of scripts dropped into
# user-writable / temp directories (closes lc_write_file -> python3 /tmp/x.py).
_SCRIPT_INTERPRETERS: frozenset[str] = frozenset({"python", "python3", "node"})
_RESTRICTED_SCRIPT_DIRS: tuple[pathlib.Path, ...] = (
    pathlib.Path("/tmp"),
    pathlib.Path("/var/tmp"),
    pathlib.Path("/dev/shm"),
    pathlib.Path.home() / ".commander_workspace",
)
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({".py", ".js", ".mjs", ".cjs"})


def _in_restricted_script_dir(arg: str) -> Optional[pathlib.Path]:
    """The restricted directory `arg` resolves into, or None."""
    try:
        resolved = pathlib.Path(arg).resolve()
    except Exception:
        return None
    for restricted in _RESTRICTED_SCRIPT_DIRS:
        try:
            resolved.relative_to(restricted.resolve())
            return restricted
        except ValueError:
            pass
    return None


def _script_path_blocked(tokens: list[str]) -> str | None:
    """Return an error string if tokens represent an interpreter running a
    script from a user-writable or temp directory. Returns None on pass."""
    if not tokens:
        return None
    binary = tokens[0].split("/")[-1]
    if binary not in _SCRIPT_INTERPRETERS:
        return None
    for arg in tokens[1:]:
        if arg.startswith("-"):
            continue
        is_path_like = "/" in arg or any(arg.endswith(ext) for ext in _SCRIPT_EXTENSIONS)
        if not is_path_like:
            continue
        try:
            pathlib.Path(arg).resolve()
        except Exception:
            return f"Script path could not be resolved: {arg!r}"
        restricted = _in_restricted_script_dir(arg)
        if restricted is not None:
            return (
                f"BLOCKED: executing a script from '{restricted}' is not permitted. "
                f"Models may not run scripts they have dropped into writable or "
                f"temporary directories. Move the script to a project directory "
                f"or use an absolute path outside restricted locations."
            )
    return None

# ---------------------------------------------------------------------------
# WHITELIST, DISK_TOOLS and DANGEROUS_FLAGS are ENFORCED ONLY IN STRICT MODE
# (LAMSYSTEMS_COMMANDER_MODE=strict). In the default claude mode they are
# importable but not consulted; the only runtime gates are the destructive
# wall (lc_confirm_destructive) and sudo.
# ---------------------------------------------------------------------------
# Strict allowlist. Anything not listed is rejected at the pre-filter.
# Curated for an AI-orchestration / model-tuning workflow.
#
# Deliberate exclusions (do not add without thinking hard about why):
#   ssh / scp / sftp / rsync          — also blocked by command_requires_ssh_gate
#   nc / netcat / ncat / socat / curl / wget — also blocked by command_has_network_exfil
#   dd / mkfs.* / shred / wipefs — destructive; excluded by design
#   rm — now on WHITELIST; rm -r / rm -rf still caught by the destructive wall
#   sh / perl / ruby                  — interpreter -c/-e flags would bypass the
#       whitelist. DANGEROUS_FLAGS entries exist as defence-in-depth but the
#       binaries themselves are not whitelisted, so they cannot be invoked.
#   bash — NOT in this set; added via SCRIPT_RUNNERS below, script-file form
#       only, and every run needs an lc_confirm_destructive token.
WHITELIST: frozenset[str] = frozenset({
    # Filesystem read
    "ls", "cat", "head", "tail", "find", "stat", "file", "wc",
    "grep", "egrep", "fgrep", "tree", "realpath", "readlink",
    "basename", "dirname", "pwd",
    # File create / move / link
    # rm is included: plain `rm file.txt` passes, rm -r / rm -rf hits the
    # destructive wall (Layer 4) and routes to the confirmation dialog.
    "cp", "mv", "mkdir", "touch", "ln", "rm",
    # Permissions
    "chmod", "chown", "chgrp",
    # Text processing
    "sed", "awk", "cut", "sort", "uniq", "tr", "diff", "patch",
    "tee", "cmp", "comm", "rev", "tac", "paste", "column", "nl",
    # Encoding / hashing
    "base64", "sha256sum", "sha1sum", "md5sum", "sha512sum", "xxd",
    # Archives
    "tar", "gzip", "gunzip", "zip", "unzip", "xz", "unxz",
    "bzip2", "bunzip2", "zstd",
    # System info
    "ps", "uname", "hostname", "whoami", "id", "groups", "uptime",
    "free", "df", "du", "lsblk", "lspci", "lsusb", "lscpu", "lsof",
    "lsmod", "dmesg", "vmstat", "iostat",
    # Network read-only
    "ip", "ss", "ping", "host", "dig", "nslookup", "tracepath",
    "traceroute", "mtr", "arp",
    # Process control
    "kill", "killall", "pkill", "pgrep",
    "nice", "renice", "nohup", "time", "timeout", "watch",
    # Package info (write subcommands blocked via DANGEROUS_FLAGS)
    "dnf", "rpm", "pip", "pip3",
    # uv: `uv run <cmd>` is unwrapped and <cmd> vetted on its own merits
    # (see _unwrap_uv_run); env-mutating subcommands blocked via DANGEROUS_FLAGS.
    "uv",
    # Project tooling reached through `uv run` (venv console scripts).
    # pytest is read-only; rail is the user's own CLI.
    "pytest", "rail",
    # Dev tools
    "git", "make", "cmake", "ninja", "gcc", "g++", "clang", "clang++",
    "ld", "ar", "nm", "objdump", "ldd", "pkg-config",
    # Rust toolchain (Fedora rpm; no rustup). cargo build/run/test execute
    # build.rs and proc-macros - the same arbitrary-code surface `make`
    # already has. Registry / global-install subcommands blocked via
    # DANGEROUS_FLAGS.
    "cargo", "rustc",
    # GitHub CLI. This is the Claude-only commander: gh is a trusted dev tool
    # like git, so no subcommand bans. Destructive wall and sudo gate still
    # apply as for everything else.
    "gh",
    # Language runtimes (-c / -e blocked via DANGEROUS_FLAGS)
    "python", "python3", "node",
    # JS package managers (install / exec blocked via DANGEROUS_FLAGS)
    "npm", "yarn", "pnpm",
    # Misc utility
    "which", "whereis", "type",
    "echo", "printf", "date", "sleep", "env",
    "true", "false", "yes", "seq",
    "man", "less", "more",
    # Hardware / health diagnostics (read-only use; write/destructive modes are
    # guarded in DANGEROUS_FLAGS below, or need root and hit the sudo gate).
    "sensors", "smartctl", "nvme", "lshw", "dmidecode", "lsmem", "lsscsi",
    "journalctl", "getent", "nproc", "top", "last", "lastb", "who", "w",
    "mpstat", "pidstat", "sar", "numastat", "netstat", "ethtool",
    "timedatectl", "hostnamectl", "rocm-smi", "amd-smi",
})


# ---------------------------------------------------------------------------
# Disk tooling — the destructive wall's escape hatch
# ---------------------------------------------------------------------------
# REMOVE THIS SET IN ONE EDIT (delete it and the `| DISK_TOOLS` below) to
# hard-ban all disk tooling again.
#
# Why it exists: the pre-filter is Layer 1 and the destructive wall is Layer 5.
# With these binaries off the whitelist, a disk command died at Layer 1 with
# "not on whitelist" and NEVER REACHED the wall — so lc_confirm_destructive
# could issue a token that nothing would ever consume. The user could approve
# the same operation three times and still be refused, with an error message
# naming the wrong cause. An approval gate you cannot satisfy is worse than no
# gate: it teaches the model to go looking for workarounds.
#
# The contract is now the documented one: the whitelist decides what may be
# ATTEMPTED; the destructive wall decides what needs EXPLICIT APPROVAL. Every
# binary below is caught by command_is_destructive (or is read-only), so none
# of them can run without a confirmation token.
DISK_TOOLS: frozenset[str] = frozenset({
    # Partition editors — gated by _PARTITION_EDITORS, read-only forms exempt
    "fdisk", "sfdisk", "sgdisk", "gdisk", "cfdisk", "parted", "partx",
    "partprobe",
    # Filesystem creation — gated by _DESTRUCTIVE_BINARIES (always)
    "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat",
    "mkfs.ntfs", "mkfs.f2fs", "mkswap",
    # Raw block writes / wipes — gated by _DESTRUCTIVE_BINARIES (always)
    "dd", "wipefs", "blkdiscard", "shred",
    # Read-only inspection and mount management — not destructive
    "blkid", "findmnt", "mount", "umount", "sync", "fsck",
    "e2label", "tune2fs", "resize2fs", "udisksctl",
})

WHITELIST = WHITELIST | DISK_TOOLS | SCRIPT_RUNNERS


# Per-binary banned flag tokens.
# The interpreter `-c` / `-e` block is the most important entry — it is the
# primary bypass vector. `python3 -c "import os; os.system('rm -rf /')"` would
# pass a binary whitelist with no operators and no path traversal otherwise.
DANGEROUS_FLAGS: dict[str, frozenset[str]] = {
    # Interpreter code-execution flags
    "python":  frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "bash":    frozenset({"-c"}),
    "sh":      frozenset({"-c"}),
    "perl":    frozenset({"-e"}),
    "ruby":    frozenset({"-e"}),
    "node":    frozenset({"-e", "-p", "--eval", "--print"}),
    # find — -delete and -exec/-execdir allow mass deletion / arbitrary execution
    "find": frozenset({"-delete", "-exec", "-execdir"}),
    # System package managers — read-only mode initially
    "dnf":  frozenset({
        "install", "remove", "update", "upgrade", "downgrade",
        "reinstall", "autoremove", "swap", "erase", "distro-sync",
    }),
    "rpm":  frozenset({"-i", "-U", "-F", "-e",
                       "--install", "--upgrade", "--freshen", "--erase"}),
    # Python package managers
    "pip":  frozenset({"install", "uninstall"}),
    "pip3": frozenset({"install", "uninstall"}),
    # uv — anything that installs into / removes from an environment, runs
    # registry code (tool), self-updates, or wipes the cache. `uv run` is
    # unwrapped before this table is consulted; its own flags are checked in
    # _UV_RUN_BANNED_FLAGS.
    "uv": frozenset({
        "add", "remove", "sync", "install", "uninstall", "publish",
        "self", "tool", "clean",
        "--with", "--with-requirements", "--with-editable",
    }),
    # JS package managers — install/exec pull and run code from the registry.
    # `npm run <script>` / `npm test` run project-local package.json scripts,
    # which is the same surface as `make` / `cargo build` and is what a build
    # actually needs, so it is allowed.
    "npm":  frozenset({"install", "i", "uninstall", "remove", "rm",
                       "exec", "x"}),
    "yarn": frozenset({"add", "remove", "install", "dlx"}),
    "pnpm": frozenset({"install", "i", "add", "remove", "rm", "dlx", "exec"}),
    # cargo — build/check/test/run/clippy/fmt/doc/clean/tree/metadata allowed.
    # Anything that writes outside the project (install to ~/.cargo/bin),
    # talks to the registry as a publisher, or edits Cargo.toml deps is
    # blocked. Note `cargo build` still fetches crates on first build; that is
    # inherent to Rust and is accepted.
    "cargo": frozenset({
        "install", "uninstall", "publish", "login", "logout", "owner",
        "yank", "add", "remove", "rm",
    }),
    # Health-diagnostic binaries: read-only use is allowed, but their write /
    # destructive subcommands and flags are blocked here (belt-and-braces; the
    # truly destructive ones also need root and hit the sudo gate anyway).
    "smartctl": frozenset({"-t", "--test", "-X", "--abort", "--set"}),
    "nvme": frozenset({
        "format", "sanitize", "format-nvm", "write", "write-zeroes",
        "delete-ns", "create-ns", "attach-ns", "detach-ns", "set-feature",
        "security-send", "fw-commit", "fw-download", "reset",
        "subsystem-reset", "dsm",
    }),
    "journalctl": frozenset({
        "--rotate", "--flush", "--sync", "--relinquish-var",
        "--vacuum-size", "--vacuum-time", "--vacuum-files",
    }),
    "rocm-smi": frozenset({
        "--setsclk", "--setmclk", "--setpcie", "--setfan", "--resetfans",
        "--setperflevel", "--setoverdrive", "--setpoweroverdrive",
        "--resetpoweroverdrive", "--setprofile", "--resetprofile",
        "--resetclocks", "--setcomputepartition", "--setmemorypartition",
        "--reset", "-r",
    }),
    "amd-smi": frozenset({"set", "reset"}),
    "ethtool": frozenset({
        "-s", "--change", "-K", "--features", "-A", "--pause", "-C",
        "--coalesce", "-G", "--set-ring", "-L", "--set-channels", "-E",
        "--change-eeprom", "--reset", "-f", "--flash", "-W",
    }),
    "timedatectl": frozenset({"set-time", "set-timezone", "set-local-rtc", "set-ntp"}),
    "hostnamectl": frozenset({
        "set-hostname", "set-icon-name", "set-chassis", "set-deployment", "set-location",
    }),
}


@dataclass
class FilterResult:
    """Outcome of the pre-filter.

    On pass: passed=True, raw_blocks carries each && / || / ; separated block
    verbatim (quote-aware split), operators[i] is the operator that preceded
    raw_blocks[i] ("" for the first). atomic_commands is a best-effort
    tokenisation of each block, kept for callers/tests that inspect tokens.
    On fail: passed=False, reason carries the rejection message.
    """
    passed: bool
    reason: str = ""
    raw_blocks: list[str] = field(default_factory=list)
    operators: list[str] = field(default_factory=list)
    atomic_commands: list[list[str]] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return not self.passed


def _pf_fail(reason: str) -> FilterResult:
    return FilterResult(passed=False, reason=reason)


def _split_raw_blocks(raw: str) -> tuple[list[str], list[str]]:
    """Quote- and escape-aware split of a command string on && || ;.

    Returns (blocks, operators) where operators[i] preceded blocks[i]. A
    single `&` (background / `2>&1`) and `|` are NOT splitters — they stay
    inside the block so the shell sees them. `\\;` (find -exec) is an escape
    and is not a splitter either.
    """
    blocks: list[str] = []
    ops: list[str] = []
    cur: list[str] = []
    in_single = in_double = False
    i, n = 0, len(raw)
    pending_op = ""
    while i < n:
        c = raw[i]
        if c == "\\" and not in_single and i + 1 < n:
            cur.append(c); cur.append(raw[i + 1]); i += 2; continue
        if c == "'" and not in_double:
            in_single = not in_single; cur.append(c); i += 1; continue
        if c == '"' and not in_single:
            in_double = not in_double; cur.append(c); i += 1; continue
        if not in_single and not in_double:
            two = raw[i:i + 2]
            if two in ("&&", "||"):
                blocks.append("".join(cur)); ops.append(pending_op)
                cur = []; pending_op = two; i += 2; continue
            if c == ";":
                blocks.append("".join(cur)); ops.append(pending_op)
                cur = []; pending_op = ";"; i += 1; continue
        cur.append(c); i += 1
    blocks.append("".join(cur)); ops.append(pending_op)
    out_blocks, out_ops = [], []
    for b, o in zip(blocks, ops):
        if b.strip():
            out_blocks.append(b.strip()); out_ops.append(o)
    return out_blocks, out_ops


def _vet_block(block: str) -> str | None:
    """Shell-script approval-gate shape check for one raw block. Returns an
    error string or None. Everything else in the block is allowed."""
    tokens = _lex(block)
    segments: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok in _SEGMENT_BREAKERS:
            if cur:
                segments.append(cur); cur = []
        else:
            cur.append(tok)
    if cur:
        segments.append(cur)
    for seg in segments:
        binary, args = _segment_binary(seg)
        if binary in SCRIPT_RUNNERS:
            err = _script_run_blocked(args)
            if err:
                return err
    return None


def _real_binary_index(tokens: list[str], unwrap_uv: bool = True) -> int:
    """Index of the first token that is a real binary, skipping wrappers
    (sudo, env, nice, timeout, ...) and their own flags / KEY=value / numeric
    arguments. Matching is on the exact token, never the basename —
    `/tmp/evil/ls` must not be admitted because it ends in a whitelisted name.
    Returns -1 if the block is nothing but wrappers. Strict mode only."""
    i = 0
    while i < len(tokens):
        if tokens[i] in _COMMAND_WRAPPERS:
            i += 1
            while i < len(tokens) and (
                tokens[i].startswith("-") or "=" in tokens[i] or tokens[i].isdigit()
            ):
                i += 1
            continue
        if unwrap_uv and tokens[i] == "uv":
            j, _err = _unwrap_uv_run(tokens, i)
            if j > i and tokens[j] != "-m":
                i = j
                continue
        return i
    return -1


def _vet_atomic(tokens: list[str]) -> str | None:
    """Strict mode: vet one atomic block, which may be a pipeline. Every stage
    is vetted as its own command. Returns an error string or None."""
    if _PIPE not in tokens:
        return _vet_command(tokens)
    stage: list[str] = []
    for tok in tokens:
        if tok == _PIPE:
            err = _vet_command(stage)
            if err:
                return err
            stage = []
        else:
            stage.append(tok)
    return _vet_command(stage)


def _vet_command(tokens: list[str]) -> str | None:
    """Strict mode: allowlist + injection + traversal + per-binary flag checks
    + interpreter script-path gate on a single command (one pipeline stage)."""
    if not tokens:
        return "Empty atomic block"

    # `uv run` flags are checked on the ORIGINAL tokens: once unwrapped, the
    # binary under vetting is the target command and DANGEROUS_FLAGS["uv"]
    # would never see them.
    k = _real_binary_index(tokens, unwrap_uv=False)
    if k >= 0 and tokens[k] == "uv":
        j, err = _unwrap_uv_run(tokens, k)
        if err:
            return err
        if j > k and tokens[j] == "-m":
            return _vet_command(["python3", *tokens[j:]])

    idx = _real_binary_index(tokens)
    if idx < 0:
        return f"No binary found after command wrapper(s): {' '.join(tokens)!r}"
    binary, *args = tokens[idx:]

    if binary not in WHITELIST:
        return (
            f"Binary not on whitelist: {binary} "
            f"(strict mode is enabled — add to WHITELIST in shell.py to permit)"
        )

    for arg in args:
        if any(c in _INJECTION_CHARS for c in arg):
            return (
                f"Injection character in argument: {arg!r} "
                f"(shell metacharacters not permitted inside arguments)"
            )

    for arg in args:
        if ".." in arg.split("/"):
            return f"Path traversal detected in argument: {arg}"

    banned = DANGEROUS_FLAGS.get(binary)
    if banned:
        for arg in args:
            if arg in banned or arg.split("=", 1)[0] in banned:
                return f"Dangerous flag for {binary}: {arg}"

    if binary in SCRIPT_RUNNERS:
        runner_err = _script_run_blocked(args)
        if runner_err:
            return runner_err
        # Strict mode: shell scripts obey the same temp-dir rule as python/node.
        if _in_restricted_script_dir(args[0]) is not None:
            return (
                f"BLOCKED: executing a shell script from a temporary or writable "
                f"directory is not permitted in strict mode: {args[0]}"
            )
        return None

    return _script_path_blocked(tokens[idx:])


def _block_to_shell_str(block: list[str]) -> str:
    """Strict mode: render a vetted atomic block for shell execution. Each
    pipeline stage is shlex-quoted independently so no argument metachar can
    escape; only the `|` between vetted stages is emitted bare."""
    if _PIPE not in block:
        return shlex.join(block)
    parts: list[str] = []
    stage: list[str] = []
    for tok in block:
        if tok == _PIPE:
            parts.append(shlex.join(stage))
            stage = []
        else:
            stage.append(tok)
    parts.append(shlex.join(stage))
    return " | ".join(parts)


def pre_filter(raw_input: str) -> FilterResult:
    """Vet a raw command string. Returns FilterResult (see class docstring).

    Passes 0-4 run in both modes. Pass 5 (redirect ban, allowlist, injection /
    traversal / dangerous-flag / script-path checks) runs only when
    LAMSYSTEMS_COMMANDER_MODE=strict.
    """
    # Pass 0: tilde expansion — keeps confirm tokens and executed strings equal.
    raw_input = os.path.expanduser(raw_input)

    # Pass 1: command substitution — the destructive wall cannot see inside it.
    for pattern in _RAW_BANNED:
        if pattern in raw_input:
            return _pf_fail(
                f"Command substitution ({pattern}) is not permitted: the "
                f"destructive-command wall cannot inspect what runs inside it. "
                f"Run the inner command as its own step instead."
            )

    # Pass 2: quote sanity.
    try:
        tokens = shlex.split(raw_input)
    except ValueError as e:
        return _pf_fail(f"Malformed shell quoting: {e}")
    if not tokens:
        return _pf_fail("Empty command string")

    # Pass 3: split into raw blocks.
    blocks, ops = _split_raw_blocks(raw_input)
    if not blocks:
        return _pf_fail("No executable commands found")

    # Pass 4: shell-script approval-gate shape check, per block.
    atomic: list[list[str]] = []
    for block in blocks:
        err = _vet_block(block)
        if err:
            return _pf_fail(err)
        try:
            atomic.append(shlex.split(block))
        except ValueError:
            atomic.append(block.split())

    # Pass 5 (strict mode only): redirect ban + full per-block vetting.
    if strict_mode():
        for token in tokens:
            if token in _HARD_BAN_TOKENS:
                return _pf_fail(f"Forbidden structural operator: {token}")
        for block_tokens in atomic:
            err = _vet_atomic(block_tokens)
            if err:
                return _pf_fail(err)
        # Strict mode executes the shlex-rendered tokens, not the raw string,
        # so nothing the vetting did not see can reach the shell.
        blocks = [_block_to_shell_str(b) for b in atomic]

    return FilterResult(passed=True, raw_blocks=blocks, operators=ops,
                        atomic_commands=atomic)


# ---------------------------------------------------------------------------
# Core executor
# ---------------------------------------------------------------------------


async def _run_subprocess(
    argv: list[str] | str,
    *,
    stdin_data: Optional[bytes] = None,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    timeout: float = 30.0,
    shell: bool = False,
) -> dict:
    """Run a subprocess and return its stdout/stderr/exit code.

    Returns a dict so callers can format the response however they like.
    """
    if shell:
        proc = await asyncio.create_subprocess_shell(
            argv if isinstance(argv, str) else " ".join(shlex.quote(a) for a in argv),
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            start_new_session=True,
        )
    else:
        if isinstance(argv, str):
            argv = shlex.split(argv)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            start_new_session=True,
        )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        # Kill the ENTIRE process group, not just the wrapper shell. A command
        # run via a shell (or a pipeline) forks children (dnf, head, du, ...);
        # proc.kill() reaps only the shell and orphans those children, which
        # keep running and -- because MCP stdio is serial -- wedge every later
        # call behind them (observed: dnf check-update surviving 20+ min). With
        # start_new_session=True each command is its own process group, so one
        # killpg reaps the whole tree.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError):
            pass
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s and was killed.",
            "timed_out": True,
        }

    return {
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "timed_out": False,
    }


async def execute_command(
    command: str,
    *,
    ctx: Optional[Context] = None,
    cwd: Optional[str] = None,
    timeout: float = 30.0,
    shell: bool = True,
) -> dict:
    """Execute a shell command via the pre-filter pipeline.

    Order of checks (each stage may reject):
        1. Pre-filter            — quoting, no $(...)/backticks, script-run shape;
                                   strict mode adds redirect ban, allowlist,
                                   injection / traversal / dangerous-flag checks
        2. File integrity        — server source directory references
        3. SSH + exfil gates     — strict mode only
        4. Destructive wall      — lc_confirm_destructive token
        5. Per-block sudo + execution (&& / || / ; semantics honoured)

    Each atomic block of a compound command (split on &&, ||, ;) runs as its
    own subprocess. Sudo authenticates per block — design's "sudo fires once
    per clean command" property. If a block exits non-zero or times out, the
    sequence stops and the partial result is returned.

    Returns a dict: { exit_code, stdout, stderr, timed_out, sudo_used, sudo_method }.
    """
    # ---- Pre-filter (the single chokepoint — runs before any other check) ----
    pf_result = pre_filter(command)
    if pf_result.failed:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"BLOCKED: {pf_result.reason}",
            "timed_out": False,
            "sudo_used": False,
            "sudo_method": "blocked_pre_filter",
        }

    # ---- File integrity protection ----
    # Block any command that references the server's own source tree.
    if command_targets_server_source(command):
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": (
                "BLOCKED: Commands targeting the server's own source directory are forbidden.\n"
                "Modifying server safety code or configuration is not permitted."
            ),
            "timed_out": False,
            "sudo_used": False,
            "sudo_method": "blocked_file_integrity",
        }

    # ---- SSH / remote shell gate and network exfil gate (strict mode) ----
    if strict_mode() and command_requires_ssh_gate(command):
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": (
                "BLOCKED: SSH, SCP, SFTP and rsync are not permitted in strict mode.\n"
                "Remote shell access and file transfer to external hosts are disabled."
            ),
            "timed_out": False,
            "sudo_used": False,
            "sudo_method": "blocked_ssh_gate",
        }
    if strict_mode() and command_has_network_exfil(command):
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": (
                "BLOCKED: nc, netcat, socat, curl and wget are not permitted in strict mode.\n"
                "Network data transfer tools are disabled to prevent exfiltration."
            ),
            "timed_out": False,
            "sudo_used": False,
            "sudo_method": "blocked_network_exfil",
        }

    # ---- Destructive hard wall ----
    # Enforced in both modes. Unchanged.
    is_destructive = command_is_destructive(command)
    if is_destructive:
        # Check for a confirmed token FIRST — a fresh confirmation after a
        # previous decline is valid and must not be blocked by the decline cache.
        if consume_confirmed_command(command):
            pass  # token consumed — fall through to per-block execution
        elif is_session_declined(command):
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": (
                    "BLOCKED: This command was declined earlier in this session.\n"
                    "Once declined, a destructive command cannot be re-requested."
                ),
                "timed_out": False,
                "sudo_used": False,
                "sudo_method": "blocked_session_decline",
            }
        else:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": (
                    "BLOCKED: Destructive commands and shell script runs require explicit user confirmation first.\n"
                    "You MUST call lc_confirm_destructive before lc_exec_command with:\n"
                    "  - command: the exact command string (must match precisely)\n"
                    "  - description: plain English description of exactly what will be permanently destroyed,\n"
                    "    or for `bash /path/script.sh` what the script does\n"
                    "A script approval is void if the script file changes before it runs.\n"
                    "The user will see a confirmation dialog. Only if they approve will a token be issued.\n"
                    "Do NOT attempt to bypass this gate or find alternative commands."
                ),
                "timed_out": False,
                "sudo_used": False,
                "sudo_method": "awaiting_confirmation",
            }

    # ---- Sequential execution of atomic blocks, sudo per block ----
    # Each block authenticates fresh — design's "sudo fires once per clean command"
    # property. A block exiting non-zero (or timing out) stops the sequence
    # (&& semantics for everything, including ; — safer default than continuing).
    combined_stdout = ""
    combined_stderr = ""
    any_sudo_used = False
    sudo_methods: list[str] = []
    last_result: dict = {
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "sudo_used": False,
        "sudo_method": "none",
    }

    prev_ok = True
    for block_str, op in zip(pf_result.raw_blocks, pf_result.operators):
        # Honour the operator that preceded this block: && runs on success,
        # || runs on failure, ; always runs. A timeout stops the sequence.
        if op == "&&" and not prev_ok:
            continue
        if op == "||" and prev_ok:
            continue
        block_result = await _execute_atomic_block(
            block_str, ctx=ctx, cwd=cwd, timeout=timeout, shell=shell,
            is_destructive=is_destructive,
        )
        combined_stdout += block_result.get("stdout", "")
        combined_stderr += block_result.get("stderr", "")
        if block_result.get("sudo_used"):
            any_sudo_used = True
        sudo_methods.append(block_result.get("sudo_method", "none"))
        last_result = block_result
        if block_result.get("timed_out"):
            break
        prev_ok = block_result.get("exit_code", 0) == 0

    # Collapse sudo_method when every block reported the same; otherwise join.
    if len(set(sudo_methods)) == 1:
        final_sudo_method = sudo_methods[0]
    else:
        final_sudo_method = ",".join(sudo_methods)

    return {
        "exit_code": last_result.get("exit_code", -1),
        "stdout": combined_stdout,
        "stderr": combined_stderr,
        "timed_out": last_result.get("timed_out", False),
        "sudo_used": any_sudo_used,
        "sudo_method": final_sudo_method,
    }


def _sudo_needs_password(result: dict) -> bool:
    """True if a `sudo -n` attempt failed only because no cached credentials
    exist — the signal to fall through to the interactive approval gate rather
    than dead-end. (Under pkexec mode sudo's own cache is never primed, so
    passthrough `sudo -n` always lands here.)

    Keyed off sudo's stderr message, NOT the exit code: in a pipeline like
    `sudo dmesg | tail` the block's exit code is the LAST stage's (tail=0),
    which masks sudo's failure — but sudo's "a password is required" still
    lands in stderr."""
    err = (result.get("stderr") or "").lower()
    return ("a password is required" in err
            or "a terminal is required" in err
            or "askpass" in err)

def _sudo_auth_failed(result: dict) -> bool:
    """True if sudo rejected the credentials (wrong or missing password). Used
    to decide whether a cached password is still valid and whether a freshly
    entered one is safe to cache - never cache a password sudo just rejected."""
    err = (result.get("stderr") or "").lower()
    return ("incorrect password" in err
            or "sorry, try again" in err
            or "authentication failure" in err
            or "a password is required" in err
            or "a terminal is required" in err
            or "askpass" in err)


async def _execute_atomic_block(
    block_str: str,
    *,
    ctx: Optional[Context],
    cwd: Optional[str],
    timeout: float,
    shell: bool,
    is_destructive: bool = False,
) -> dict:
    """Run a single pre-vetted atomic block, prompting for sudo if needed.

    Caller guarantees the block has passed the pre-filter. Sudo is checked
    per block so a 5-command compound only prompts on blocks that actually
    need it. Each prompted block authenticates fresh and the timestamp cache
    is wiped after.
    """
    needs_sudo = command_requires_sudo(block_str)

    if not needs_sudo:
        result = await _run_subprocess(
            block_str, cwd=cwd, timeout=timeout, shell=shell,
        )
        result["sudo_used"] = False
        result["sudo_method"] = "none"
        return result

    # Session cache (opt-in, NON-destructive only): reuse a password captured
    # earlier this run instead of prompting again. Destructive commands never
    # reach this - they always prompt fresh.
    if not is_destructive and sudo_cache_enabled():
        cached = sudo_cache_get()
        if cached is not None:
            rewritten = _rewrite_sudo_in_command(block_str)
            result = await _run_subprocess(
                rewritten, stdin_data=(cached + "\n").encode(),
                cwd=cwd, timeout=timeout, shell=True,
            )
            # Same per-command policy as the password path: never leave
            # sudo's own timestamp primed. Our cache re-feeds the password
            # via -S on every call, so sudo's timestamp is never needed.
            try:
                await _run_subprocess(["sudo", "-k"], timeout=5.0)
            except Exception:
                pass
            if not _sudo_auth_failed(result):
                result["sudo_used"] = True
                result["sudo_method"] = "cache"
                return result
            sudo_cache_clear()  # stale/wrong - fall through and prompt again

    # ---- sudo path: resolve approval through the strategy chain ----
    approval = await request_sudo_approval(ctx, block_str)

    if approval.declined:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Sudo refused ({approval.method}): {approval.reason}",
            "timed_out": False,
            "sudo_used": False,
            "sudo_method": approval.method,
        }

    # Passthrough path: safe diagnostic command, try sudo -n (no dialog). It
    # only succeeds when sudo already has cached credentials; under pkexec mode
    # that cache is never primed, so on a "password required" failure we do NOT
    # dead-end — we re-resolve WITHOUT passthrough and fall through to the
    # interactive gate below (pkexec/dialog), exactly like a normal sudo command.
    if approval.auto_approved:
        rewritten = _rewrite_sudo_in_command(block_str).replace("sudo -S -p ''", "sudo -n")
        result = await _run_subprocess(
            rewritten, cwd=cwd, timeout=timeout, shell=True,
        )
        if not _sudo_needs_password(result):
            result["sudo_used"] = True
            result["sudo_method"] = "passthrough"
            return result
        approval = await request_sudo_approval(ctx, block_str, allow_passthrough=False)
        if approval.declined:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Sudo refused ({approval.method}): {approval.reason}",
                "timed_out": False,
                "sudo_used": False,
                "sudo_method": approval.method,
            }

    # pkexec path: rewrite `sudo` → `pkexec`. Polkit handles its own prompt.
    if approval.use_pkexec:
        rewritten = _rewrite_sudo_to_pkexec(block_str)
        result = await _run_subprocess(
            rewritten, cwd=cwd, timeout=timeout, shell=True,
        )
        result["sudo_used"] = True
        result["sudo_method"] = "pkexec"
        return result

    # Password path (elicit / zenity / kdialog all funnel here).
    password = approval.password or ""
    rewritten = _rewrite_sudo_in_command(block_str)

    try:
        result = await _run_subprocess(
            rewritten,
            stdin_data=(password + "\n").encode(),
            cwd=cwd,
            timeout=timeout,
            shell=True,
        )
        result["sudo_used"] = True
        result["sudo_method"] = approval.method

        # Cache the password for later NON-destructive sudo commands this run
        # (opt-in), so a read-only scan only prompts once. Never for destructive
        # commands, and only if sudo actually accepted it.
        if not is_destructive and not _sudo_auth_failed(result):
            sudo_cache_put(password)

        # Belt-and-suspenders: explicitly wipe sudo's timestamp cache.
        try:
            await _run_subprocess(["sudo", "-k"], timeout=5.0)
        except Exception:
            pass

        return result
    finally:
        # Drop the only handle to the password. Python won't truly wipe the
        # bytes, but we at least remove the reference so it can be GC'd.
        del password
        approval.password = None


def _rewrite_sudo_to_pkexec(command: str) -> str:
    """Replace every standalone `sudo` word with `pkexec`.

    Polkit's pkexec runs the rest of the command as root, popping its own
    password dialog. The shell flag semantics differ a bit (`-S`, `-p`, etc.
    don't exist on pkexec), so we simply substitute the binary and drop
    sudo-only flags would have to be handled by the model.
    """
    return _replace_sudo_word(command, replacement="pkexec")


def _rewrite_sudo_in_command(command: str) -> str:
    """Insert `-S -p ''` after every standalone `sudo` word in the command.

    Preserves the original command verbatim — including pipes, redirects, and
    quoting — so that shell features like `cat foo | sudo tee bar` still work.
    Uses a quote-aware scanner so a string literal like `echo "no sudo"` is
    NOT rewritten.
    """
    return _replace_sudo_word(command, replacement="sudo -S -p ''")


def _replace_sudo_word(command: str, *, replacement: str) -> str:
    """Quote-aware replacement of the standalone token `sudo` with `replacement`."""
    out: list[str] = []
    i = 0
    n = len(command)
    in_single = False
    in_double = False

    word_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./")

    while i < n:
        c = command[i]
        # Handle quoting state first.
        if c == "'" and not in_double:
            in_single = not in_single
            out.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            out.append(c)
            i += 1
            continue
        # Backslash escapes — copy two chars literally.
        if c == "\\" and i + 1 < n and not in_single:
            out.append(c)
            out.append(command[i + 1])
            i += 2
            continue
        # Only rewrite outside any quotes.
        if not in_single and not in_double and command.startswith("sudo", i):
            left_ok = i == 0 or command[i - 1] not in word_chars
            end = i + 4
            right_ok = end == n or command[end] not in word_chars
            if left_ok and right_ok:
                out.append(replacement)
                i = end
                continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Public formatting helper used by the server module
# ---------------------------------------------------------------------------


def format_command_result(command: str, result: dict, truncate: int = 50_000) -> str:
    """Format a subprocess result dict into the text payload returned to the LLM.

    If combined stdout+stderr exceeds OFFLOAD_CHARS, the full output is written
    to a timestamped file in SCRATCHPAD_DIR and a lightweight pointer is returned
    instead. This keeps the model's context window clean for large outputs like
    dmesg, find, dnf history, build logs, etc.
    """
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    combined_size = len(stdout) + len(stderr)

    header = [
        f"$ {command}",
        f"exit_code: {result.get('exit_code')}",
        f"sudo_used: {result.get('sudo_used', False)}",
        f"sudo_method: {result.get('sudo_method', 'none')}",
    ]
    if result.get("timed_out"):
        header.append("timed_out: true")

    # ---- Large output path: offload to scratchpad ----
    if combined_size > OFFLOAD_CHARS:
        full_output = ""
        if stdout:
            full_output += f"--- stdout ---\n{stdout}"
        if stderr:
            full_output += f"\n--- stderr ---\n{stderr}"
        saved_path = _save_to_scratchpad(command, full_output)
        total_lines = stdout.count("\n") + stderr.count("\n")
        header.append(
            f"\n[Output too large for context ({combined_size:,} chars, ~{total_lines:,} lines)."
            f"\nFull output saved to: {saved_path}"
            f"\nUse lc_search_content or lc_search_scratchpad to query it,"
            f"\nor lc_read_file with offset/limit to read it in chunks.]"
        )
        return "\n".join(header)

    # ---- Normal path: inline output ----
    if len(stdout) > truncate:
        stdout = stdout[:truncate] + f"\n... [truncated {len(stdout) - truncate} chars]"
    if len(stderr) > truncate:
        stderr = stderr[:truncate] + f"\n... [truncated {len(stderr) - truncate} chars]"
    if stdout:
        header.append(f"\n--- stdout ---\n{stdout}")
    if stderr:
        header.append(f"\n--- stderr ---\n{stderr}")
    return "\n".join(header)


def resolve_cwd(cwd: Optional[str]) -> Optional[str]:
    """Expand ~ and validate that cwd exists. Returns None if cwd is None."""
    if cwd is None:
        return None
    expanded = os.path.expanduser(cwd)
    if not os.path.isdir(expanded):
        raise ValueError(f"cwd does not exist or is not a directory: {expanded}")
    return expanded
