"""Process management: list, kill, and interact with long-running processes.

Long-running processes are tracked in an in-memory session registry. Each gets
a stable session_id that the LLM can use to stream output, send input, or kill it.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from lamsystems_commander.shell import (
    pre_filter,
    command_requires_ssh_gate,
    command_has_network_exfil,
    command_targets_server_source,
    command_is_destructive,
    consume_confirmed_command,
    is_session_declined,
)


# ---------------------------------------------------------------------------
# Session registry for long-running processes
# ---------------------------------------------------------------------------


@dataclass
class ProcessSession:
    session_id: str
    command: str
    process: asyncio.subprocess.Process
    started_at: float
    stdout_buf: list[bytes] = field(default_factory=list)
    stderr_buf: list[bytes] = field(default_factory=list)
    stdout_reader: Optional[asyncio.Task] = None
    stderr_reader: Optional[asyncio.Task] = None

    def is_alive(self) -> bool:
        return self.process.returncode is None


_SESSIONS: dict[str, ProcessSession] = {}


async def _drain(stream: asyncio.StreamReader, buf: list[bytes]) -> None:
    """Read a stream until EOF, accumulating into buf."""
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        buf.append(chunk)


# ---------------------------------------------------------------------------
# command_gate — universal pre-flight check for all process launches
# ---------------------------------------------------------------------------
# Every command entering start_process MUST pass through here before any
# subprocess is created. Runs the same gate stack as lc_exec_command:
#   1. Pre-filter pipeline (whitelist, injection chars, path traversal,
#      per-binary dangerous flags, pipe/redirect ban)
#   2. SSH gate
#   3. Network exfil gate
#   4. File integrity protection
#   5. Destructive hard wall (one-time confirmation token)
#
# Returns (None, atomic_tokens) on pass — atomic_tokens is the single
# vetted token list to pass directly to create_subprocess_exec.
# Returns (error_string, None) on any failure.

def command_gate(command: str) -> tuple[str | None, list[str] | None]:
    """Vet a command string through the full safety gate stack.

    Returns (None, tokens) on pass, (error_message, None) on any failure.
    Callers must check the first element before launching any subprocess.
    """
    # Gate 1: pre-filter pipeline
    pf = pre_filter(command)
    if pf.failed:
        return f"Pre-filter rejected: {pf.reason}", None

    # process sessions only support a single atomic command — no && / || / ;
    if len(pf.atomic_commands) != 1:
        return (
            "start_process only accepts a single command. "
            "Compound commands (&&, ||, ;) are not allowed in process sessions. "
            "Use lc_exec_command for compound one-shot commands instead.",
            None,
        )

    # Gate 2: SSH gate
    if command_requires_ssh_gate(command):
        return "Blocked: SSH/SCP/SFTP/rsync are not permitted (network gate)", None

    # Gate 3: network exfil gate
    if command_has_network_exfil(command):
        return "Blocked: nc/curl/wget/socat are not permitted (network exfil gate)", None

    # Gate 4: file integrity protection
    if command_targets_server_source(command):
        return "Blocked: commands targeting the server source directory are not permitted", None

    # Gate 5: destructive hard wall — same rule as execute_command.
    # Without this, lc_start_process was a way to run `mkfs.ext4 /dev/sdb1`
    # with no confirmation dialog at all, while lc_exec_command required one
    # for the identical string. A gate that one tool enforces and another
    # ignores is not a gate.
    if command_is_destructive(command):
        if is_session_declined(command):
            return (
                "Blocked: this command was declined earlier in this session. "
                "Once declined, a destructive command cannot be re-requested.",
                None,
            )
        if not consume_confirmed_command(command):
            return (
                "Blocked: destructive commands require explicit user confirmation first.\n"
                "Call lc_confirm_destructive with the EXACT command string and a plain "
                "English description of what will be permanently destroyed. A one-time "
                "token is issued only if the user approves.",
                None,
            )

    return None, pf.atomic_commands[0]


# ---------------------------------------------------------------------------
# List processes (system-wide)
# ---------------------------------------------------------------------------


async def list_processes(filter_substring: Optional[str] = None, limit: int = 50) -> str:
    """List running processes via `ps -eo`. Optional substring filter on command."""
    proc = await asyncio.create_subprocess_exec(
        "ps", "-eo", "pid,ppid,user,pcpu,pmem,etime,cmd", "--sort=-pcpu",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    lines = stdout.decode(errors="replace").splitlines()
    if not lines:
        return "No process output."
    header, *rows = lines
    if filter_substring:
        needle = filter_substring.lower()
        rows = [r for r in rows if needle in r.lower()]
    rows = rows[:limit]
    return "\n".join([header, *rows])


# ---------------------------------------------------------------------------
# Kill a process by PID
# ---------------------------------------------------------------------------


def kill_process(pid: int, signal_name: str = "TERM") -> str:
    """Send a signal to a PID. Default SIGTERM; SIGKILL for force.

    NOTE: killing root-owned or other-user processes will fail without sudo.
    For those, use exec_command with `sudo kill ...`, which goes through the gate.
    """
    sig = getattr(signal, f"SIG{signal_name.upper()}", None)
    if sig is None:
        return f"Error: unknown signal '{signal_name}'"
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return f"Error: no process with PID {pid}"
    except PermissionError:
        return (
            f"Error: permission denied killing PID {pid}. "
            f"Try via exec_command with `sudo kill -{signal_name} {pid}`."
        )
    return f"Sent SIG{signal_name.upper()} to PID {pid}"


# ---------------------------------------------------------------------------
# Long-running process management
# ---------------------------------------------------------------------------


async def start_process(command: str, cwd: Optional[str] = None) -> str:
    """Start a long-running process and return its session_id.

    The command is vetted through the full safety gate stack (pre-filter pipeline,
    SSH gate, network exfil gate, file integrity protection) before any subprocess
    is created. Compound commands (&&, ||, ;) are not allowed — one atomic command
    per session.

    Use read_process_output to poll its stdout/stderr and interact_with_process
    to send input on stdin.
    """
    # Gate: full safety check before any subprocess is created
    gate_error, tokens = command_gate(command)
    if gate_error:
        return json.dumps({"error": gate_error}, indent=2)

    proc = await asyncio.create_subprocess_exec(
        *tokens,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    session = ProcessSession(
        session_id=uuid.uuid4().hex[:12],
        command=command,
        process=proc,
        started_at=time.time(),
    )
    if proc.stdout:
        session.stdout_reader = asyncio.create_task(_drain(proc.stdout, session.stdout_buf))
    if proc.stderr:
        session.stderr_reader = asyncio.create_task(_drain(proc.stderr, session.stderr_buf))

    _SESSIONS[session.session_id] = session
    return json.dumps({
        "session_id": session.session_id,
        "pid": proc.pid,
        "command": command,
        "started_at": session.started_at,
    }, indent=2)


def list_sessions() -> str:
    """List all process sessions managed by this server."""
    out = []
    for s in _SESSIONS.values():
        out.append({
            "session_id": s.session_id,
            "command": s.command,
            "pid": s.process.pid,
            "alive": s.is_alive(),
            "exit_code": s.process.returncode,
            "uptime_sec": round(time.time() - s.started_at, 1),
        })
    return json.dumps(out, indent=2) if out else "No active sessions."


async def read_process_output(session_id: str, drain: bool = True) -> str:
    """Return any accumulated stdout/stderr for a session.

    If `drain` is True (default), the buffers are emptied after reading so
    subsequent calls only see new output.
    """
    s = _SESSIONS.get(session_id)
    if s is None:
        return f"Error: no session {session_id}"

    stdout = b"".join(s.stdout_buf).decode(errors="replace")
    stderr = b"".join(s.stderr_buf).decode(errors="replace")
    if drain:
        s.stdout_buf.clear()
        s.stderr_buf.clear()

    return json.dumps({
        "session_id": session_id,
        "alive": s.is_alive(),
        "exit_code": s.process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }, indent=2)


async def interact_with_process(session_id: str, input_text: str) -> str:
    """Write `input_text` to the session's stdin (newline appended if absent)."""
    s = _SESSIONS.get(session_id)
    if s is None:
        return f"Error: no session {session_id}"
    if not s.is_alive():
        return f"Error: session {session_id} has exited (code={s.process.returncode})"
    if s.process.stdin is None:
        return f"Error: session {session_id} has no open stdin"

    payload = input_text if input_text.endswith("\n") else input_text + "\n"
    s.process.stdin.write(payload.encode())
    try:
        await s.process.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        return f"Error: stdin pipe closed for session {session_id}"
    return f"Wrote {len(payload)} bytes to session {session_id} stdin"


def stop_process_session(session_id: str, force: bool = False) -> str:
    """Terminate a managed session. `force=True` sends SIGKILL."""
    s = _SESSIONS.get(session_id)
    if s is None:
        return f"Error: no session {session_id}"
    if not s.is_alive():
        return f"Session {session_id} already exited (code={s.process.returncode})"
    s.process.send_signal(signal.SIGKILL if force else signal.SIGTERM)
    return f"Sent SIG{'KILL' if force else 'TERM'} to session {session_id} (pid={s.process.pid})"
