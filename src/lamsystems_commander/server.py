"""lamsystems_commander — Desktop Commander-style MCP server for Claude and other MCP clients.

Tools (all prefixed `lc_` so they don't collide with any other MCP server):

    Shell
        lc_exec_command         — run a shell command (gated for sudo)

    Files
        lc_read_file
        lc_write_file
        lc_edit_block
        lc_list_directory
        lc_move_file
        lc_create_directory
        lc_get_file_info

    Processes
        lc_list_processes       — system-wide ps output
        lc_kill_process         — signal a PID
        lc_start_process        — start a long-running process, returns session_id
        lc_list_sessions        — list managed sessions
        lc_read_process_output  — pull stdout/stderr from a session
        lc_interact_with_process — write to a session's stdin
        lc_stop_process_session

    Search
        lc_search_files         — find files by name
        lc_search_content       — grep/ripgrep file contents

    Git
        lc_git_status
        lc_git_diff
        lc_git_log
        lc_git_branch
"""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
from typing import Optional

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, ConfigDict, Field

from lamsystems_commander import files, git_tools, processes, search, shell

# ---------------------------------------------------------------------------
# Tool call logger
# ---------------------------------------------------------------------------
_LOG_DIR = pathlib.Path.home() / ".commander_workspace"
_LOG_FILE = _LOG_DIR / "tool_calls.log"


def _setup_tool_logger() -> logging.Logger:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("lamsystems_commander.tools")
    if not logger.handlers:
        handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger


_tool_log = _setup_tool_logger()

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP("lamsystems_commander")


# ===========================================================================
# Shell — the only tool with the sudo gate
# ===========================================================================


class ExecCommandInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    command: str = Field(..., description="Shell command to run. If it contains `sudo` you'll be prompted for your password via elicitation.", min_length=1)
    cwd: Optional[str] = Field(default=None, description="Working directory. Defaults to the server's cwd. Supports ~ expansion.")
    timeout_seconds: float = Field(default=60.0, description="Kill the command after this many seconds.", ge=1.0, le=3600.0)


def _exec_command_description() -> str:
    """Build the lc_exec_command tool description from the LIVE allowlist, so
    the model is told exactly what it may run instead of discovering the rules
    by trial-and-error. Generated from shell.WHITELIST so it never drifts."""
    from lamsystems_commander.shell import WHITELIST
    allowed = ", ".join(sorted(WHITELIST))
    return (
        "Run a shell command on the host, through a strict security allowlist. "
        "Read these rules first - a command that breaks any of them is rejected "
        "before it runs (you get a 'BLOCKED: ...' error, not output).\n\n"
        "ALLOWED BINARIES - only these run; anything else is rejected, even under "
        f"sudo:\n{allowed}\n\n"
        "RULES:\n"
        "- No shell interpreters (bash, sh, perl, ruby). To run a script use "
        "`python3 FILE.py` or `node FILE.js` - a script FILE, never inline code "
        "(`python3 -c ...` / `node -e ...` are blocked).\n"
        "- Pipes work: `a | b | c` (every stage must be an allowed binary). "
        "Sequencing works: `a && b`, `a || b`, `a ; b`.\n"
        "- Redirects `>`, `>>`, `<` are BANNED. To write a file, use `tee` or a "
        "`python3` script.\n"
        "- No shell metacharacters INSIDE an argument (semicolon, ampersand, pipe, "
        "dollar, parentheses, backtick). e.g. `grep 'a|b'` is rejected - use "
        "`grep -e a -e b`. `$(...)` command substitution and backticks are banned.\n"
        "- No `..` path traversal in an argument.\n"
        "- Package managers (dnf, rpm, pip, npm, yarn, pnpm) allow read-only "
        "subcommands only; install/remove/update/upgrade are blocked. `systemctl` "
        "allows status/query subcommands only.\n"
        "- sudo: prefix an allowed binary with `sudo` (e.g. `sudo dmesg`); a "
        "one-time password dialog appears for that command. sudo on a "
        "non-allowed binary is still rejected.\n\n"
        "Returns a block with exit code, stdout, and stderr."
    )


@mcp.tool(
    name="lc_exec_command",
    description=_exec_command_description(),
    annotations={
        "title": "Execute shell command (sudo-gated)",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def lc_exec_command(params: ExecCommandInput, ctx: Context) -> str:
    """Run a shell command on the host.

    Sudo commands are GATED: the server pauses, asks the user (via MCP
    elicitation) to enter their password for THIS COMMAND ONLY, then runs it.
    No password caching — every sudo call requires fresh approval.

    Non-sudo commands run normally with no prompt.

    Returns a formatted block containing exit code, stdout, and stderr.

    Args:
        params.command: Full shell command (pipes, redirects, etc. supported).
        params.cwd: Optional working directory.
        params.timeout_seconds: How long to wait before killing the command.
    """
    _tool_log.info(f"CALL lc_exec_command | command={params.command!r} | cwd={params.cwd!r} | timeout={params.timeout_seconds}")
    try:
        cwd = shell.resolve_cwd(params.cwd)
    except ValueError as e:
        _tool_log.error(f"FAIL lc_exec_command | cwd error: {e}")
        return f"Error: {e}"
    try:
        result = await shell.execute_command(
            params.command,
            ctx=ctx,
            cwd=cwd,
            timeout=params.timeout_seconds,
            shell=True,
        )
        _tool_log.info(f"OK   lc_exec_command | exit_code={result.get('exit_code')} | sudo={result.get('sudo_used')} | sudo_method={result.get('sudo_method')}")
        return shell.format_command_result(params.command, result)
    except Exception as e:
        _tool_log.error(f"FAIL lc_exec_command | {type(e).__name__}: {e}")
        raise


# ===========================================================================
# Files
# ===========================================================================


class ReadFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Path to file. Supports ~ expansion.", min_length=1)
    offset: int = Field(default=0, description="Line offset (0-based).", ge=0)
    limit: Optional[int] = Field(default=None, description="Max lines to return.", ge=1)


@mcp.tool(
    name="lc_read_file",
    annotations={"title": "Read file", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_read_file(params: ReadFileInput) -> str:
    """Read a text file. Returns the contents, sliced by `offset` and `limit` lines."""
    return files.read_file(params.path, offset=params.offset, limit=params.limit)


class WriteFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Path to file. Parent dirs are created if missing.", min_length=1)
    content: str = Field(..., description="Content to write.")
    mode: str = Field(default="overwrite", description="'overwrite' (default) or 'append'.", pattern="^(overwrite|append)$")


@mcp.tool(
    name="lc_write_file",
    annotations={"title": "Write file", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_write_file(params: WriteFileInput) -> str:
    """Write content to a file. Use mode='append' to append rather than overwrite."""
    return files.write_file(params.path, params.content, mode=params.mode)


class EditBlockInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Path to file.", min_length=1)
    old_string: str = Field(..., description="Exact substring to replace. Include enough context to be unique.")
    new_string: str = Field(..., description="Replacement text.")
    expected_replacements: int = Field(default=1, description="How many occurrences should exist; refuses if count differs.", ge=1)


@mcp.tool(
    name="lc_edit_block",
    annotations={"title": "Edit block (find/replace)", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_edit_block(params: EditBlockInput) -> str:
    """Surgically replace an exact substring in a file.

    Refuses if `old_string` is not present, or appears a different number of
    times than `expected_replacements`. This makes edits explicit and safe.
    """
    return files.edit_block(
        params.path, params.old_string, params.new_string,
        expected_replacements=params.expected_replacements,
    )


class ListDirInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Directory path.", min_length=1)
    show_hidden: bool = Field(default=False, description="Include dotfiles.")


@mcp.tool(
    name="lc_list_directory",
    annotations={"title": "List directory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_list_directory(params: ListDirInput) -> str:
    """List a directory's contents with type, permissions, size, and mtime."""
    return files.list_directory(params.path, show_hidden=params.show_hidden)


class MoveFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(..., description="Source path.", min_length=1)
    destination: str = Field(..., description="Destination path.", min_length=1)


@mcp.tool(
    name="lc_move_file",
    annotations={"title": "Move/rename file", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_move_file(params: MoveFileInput) -> str:
    """Move or rename a file or directory."""
    return files.move_file(params.source, params.destination)


class CreateDirInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Directory to create.", min_length=1)
    parents: bool = Field(default=True, description="Create parent dirs as needed.")


@mcp.tool(
    name="lc_create_directory",
    annotations={"title": "Create directory", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_create_directory(params: CreateDirInput) -> str:
    """Create a directory (mkdir -p by default)."""
    return files.create_directory(params.path, parents=params.parents)


class FileInfoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="File or directory path.", min_length=1)


@mcp.tool(
    name="lc_get_file_info",
    annotations={"title": "Stat file", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_get_file_info(params: FileInfoInput) -> str:
    """Return stat info as JSON: size, permissions, owner, mtime, etc."""
    return files.get_file_info(params.path)


# ===========================================================================
# Processes
# ===========================================================================


class ListProcessesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filter_substring: Optional[str] = Field(default=None, description="Case-insensitive substring filter on the command column.")
    limit: int = Field(default=50, description="Max rows.", ge=1, le=500)


@mcp.tool(
    name="lc_list_processes",
    annotations={"title": "List processes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
async def lc_list_processes(params: ListProcessesInput) -> str:
    """List running system processes, sorted by CPU. Optional substring filter."""
    return await processes.list_processes(params.filter_substring, params.limit)


class KillProcessInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(..., description="Process ID.", ge=1)
    signal_name: str = Field(default="TERM", description="Signal name without SIG prefix (e.g. TERM, KILL, HUP, INT).")


@mcp.tool(
    name="lc_kill_process",
    annotations={"title": "Kill process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_kill_process(params: KillProcessInput) -> str:
    """Send a signal to a PID. Killing other-user processes needs sudo via lc_exec_command."""
    return processes.kill_process(params.pid, params.signal_name)


class StartProcessInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(..., description="Command to start (long-running, interactive, etc.).", min_length=1)
    cwd: Optional[str] = Field(default=None, description="Working directory.")


@mcp.tool(
    name="lc_start_process",
    annotations={"title": "Start long-running process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
)
async def lc_start_process(params: StartProcessInput) -> str:
    """Start a long-running process. Returns a session_id for further interaction.

    Does NOT go through the sudo gate — for sudo background jobs, run them via
    lc_exec_command instead, since interactive elicitation only fits inside a
    single tool call.
    """
    return await processes.start_process(params.command, cwd=params.cwd)


@mcp.tool(
    name="lc_list_sessions",
    annotations={"title": "List managed sessions", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_list_sessions() -> str:
    """List long-running process sessions managed by this server."""
    return processes.list_sessions()


class ReadOutputInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., description="Session ID from lc_start_process.", min_length=1)
    drain: bool = Field(default=True, description="Empty the buffer after reading.")


@mcp.tool(
    name="lc_read_process_output",
    annotations={"title": "Read process output", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
async def lc_read_process_output(params: ReadOutputInput) -> str:
    """Pull any accumulated stdout/stderr from a managed session."""
    return await processes.read_process_output(params.session_id, drain=params.drain)


class InteractInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., description="Session ID.", min_length=1)
    input_text: str = Field(..., description="Text to write to the process's stdin (newline appended if absent).")


@mcp.tool(
    name="lc_interact_with_process",
    annotations={"title": "Send stdin to process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_interact_with_process(params: InteractInput) -> str:
    """Write to a managed session's stdin (e.g., for REPLs, prompts)."""
    return await processes.interact_with_process(params.session_id, params.input_text)


class StopSessionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., description="Session ID.", min_length=1)
    force: bool = Field(default=False, description="Send SIGKILL instead of SIGTERM.")


@mcp.tool(
    name="lc_stop_process_session",
    annotations={"title": "Stop managed session", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
)
async def lc_stop_process_session(params: StopSessionInput) -> str:
    """Terminate a managed session."""
    return processes.stop_process_session(params.session_id, force=params.force)


# ===========================================================================
# Search
# ===========================================================================


class SearchFilesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: str = Field(..., description="Directory to search from.", min_length=1)
    pattern: str = Field(..., description="Glob pattern (e.g. '*.py', 'foo_*.json').", min_length=1)
    max_results: int = Field(default=200, description="Stop after N matches.", ge=1, le=5000)
    include_hidden: bool = Field(default=False, description="Include dotfiles/dotdirs.")


@mcp.tool(
    name="lc_search_files",
    annotations={"title": "Find files by name", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_search_files(params: SearchFilesInput) -> str:
    """Recursively find files matching a glob pattern."""
    return search.search_files(
        params.root, params.pattern,
        max_results=params.max_results,
        include_hidden=params.include_hidden,
    )


class SearchContentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: str = Field(..., description="Directory to search from.", min_length=1)
    pattern: str = Field(..., description="Regex pattern.", min_length=1)
    file_glob: Optional[str] = Field(default=None, description="Limit to filenames matching this glob (e.g. '*.py').")
    case_insensitive: bool = Field(default=False, description="Case-insensitive match.")
    max_results: int = Field(default=200, description="Stop after N matches.", ge=1, le=5000)
    context_lines: int = Field(default=0, description="Lines of context around each match (ripgrep only).", ge=0, le=20)


@mcp.tool(
    name="lc_search_content",
    annotations={"title": "Search file contents (regex)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_search_content(params: SearchContentInput) -> str:
    """Grep-style content search. Uses ripgrep when installed, Python fallback otherwise."""
    return await search.search_content(
        params.root, params.pattern,
        file_glob=params.file_glob,
        case_insensitive=params.case_insensitive,
        max_results=params.max_results,
        context_lines=params.context_lines,
    )


class ConfirmDestructiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(..., description="The EXACT command string that will be executed. Must match precisely.", min_length=1)
    description: str = Field(..., description="Plain English: exactly what will be permanently destroyed (device, path, data).", min_length=1)


class _DestructiveConfirm(BaseModel):
    """Elicitation response schema for the destructive-operation dialog.

    MUST be a Pydantic model class, NOT a raw JSON-schema dict.
    `mcp.server.elicitation.elicit_with_validation` calls `schema.model_fields`
    and `schema.model_json_schema()` on whatever it is given. Passing a dict
    raises AttributeError before the dialog is ever shown — and the caller
    below used to swallow that exception silently, so the gate appeared to
    "work" while never issuing a token. Do not change this back to a dict.

    Per the MCP spec, elicitation schemas may only contain primitive fields.
    """
    confirmed: bool = Field(
        default=False,
        description="I understand this is irreversible and want to proceed.",
    )


@mcp.tool(
    name="lc_confirm_destructive",
    annotations={"title": "Confirm destructive operation (REQUIRED before destructive commands)", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
async def lc_confirm_destructive(params: ConfirmDestructiveInput, ctx: Context) -> str:
    """MANDATORY gate before any destructive command (rm -r, dd, mkfs, shred, wipefs, /dev/ writes).

    Shows the user an explicit confirmation dialog describing exactly what will be destroyed.
    If the user approves, issues a one-time token allowing lc_exec_command to proceed once.
    If declined, the operation is permanently cancelled — do NOT retry or find alternatives.

    Args:
        params.command: Exact command string — must match what you will pass to lc_exec_command.
        params.description: Human-readable description of what will be permanently destroyed.
    """
    # Normalise ~ to the real home directory so the token registered here
    # matches the expanded form that pre_filter produces in lc_exec_command.
    command = os.path.expanduser(params.command)

    from lamsystems_commander.shell import register_confirmed_command, register_declined_command
    import subprocess

    _tool_log.info(f"CALL lc_confirm_destructive | command={command!r}")

    msg = (
        f"⚠️  DESTRUCTIVE OPERATION — CANNOT BE UNDONE\n\n"
        f"{params.description}\n\n"
        f"Command: {command}"
    )

    def _granted(method: str) -> str:
        register_confirmed_command(command)
        _tool_log.info(f"OK   lc_confirm_destructive | GRANTED via {method} | command={command!r}")
        return (
            f"✓ User confirmed via {method}. One-time token issued.\n"
            f"You may now call lc_exec_command with the EXACT command: {command}"
        )

    def _refused(method: str) -> str:
        register_declined_command(command)
        _tool_log.info(f"OK   lc_confirm_destructive | DECLINED via {method} | command={command!r}")
        return (
            "✗ User declined. Operation permanently cancelled for this session. "
            "Do NOT retry or look for alternatives."
        )

    # -- Strategy 1: MCP elicitation (native in-client dialog) --------------
    # The SDK returns action == "accept" | "decline" | "cancel". There is no
    # "submit" action. Checking for one turned every approval into a silent
    # decline — that is the bug that made three authorisations do nothing.
    # Do not reintroduce it.
    try:
        result = await ctx.elicit(message=msg, schema=_DestructiveConfirm)
    except Exception as e:
        # Client does not support elicitation, or the SDK rejected the call.
        # Log it — swallowing this silently is how the dict-schema bug hid for
        # so long — then fall through to the GUI fallback.
        _tool_log.warning(
            f"lc_confirm_destructive | elicitation unavailable "
            f"({type(e).__name__}: {e}); falling back to zenity"
        )
    else:
        # Elicitation worked, so it is authoritative. Do not prompt twice.
        data = getattr(result, "data", None)
        if result.action == "accept" and data is not None and data.confirmed:
            return _granted("in-app dialog")
        return _refused(f"in-app dialog (action={result.action})")

    # -- Strategy 2: zenity dialog fallback --------------------------------
    # run() is blocking and this is an async server, so hand it to a thread;
    # otherwise a 120s dialog stalls the whole event loop.
    try:
        r = await asyncio.to_thread(
            subprocess.run,
            [
                "zenity", "--question",
                "--title=⚠️ DESTRUCTIVE OPERATION",
                f"--text={msg}\n\nProceed?",
                "--ok-label=CONFIRM — DESTROY",
                "--cancel-label=Cancel",
                "--width=500",
            ],
            timeout=120,
        )
    except Exception as e:
        _tool_log.warning(f"lc_confirm_destructive | zenity unavailable ({type(e).__name__}: {e})")
    else:
        if r.returncode == 0:
            return _granted("zenity")
        return _refused("zenity")

    # -- No mechanism available: refuse, loudly ----------------------------
    # This path must never read as approval. The previous wording was advisory
    # prose, which models interpreted as consent and then looped against the
    # destructive wall.
    _tool_log.error(
        f"FAIL lc_confirm_destructive | NO TOKEN ISSUED — no confirmation mechanism "
        f"available | command={command!r}"
    )
    return (
        "ERROR: NO TOKEN ISSUED. No confirmation mechanism is available — this "
        "client does not support elicitation and zenity could not be launched.\n"
        "The command has NOT been approved and lc_exec_command will refuse it.\n"
        "Do NOT retry this tool and do NOT look for an alternative command. "
        "Tell the user they must run the command themselves in a terminal."
    )


# ===========================================================================
# Scratchpad — inspect and search auto-offloaded command outputs
# ===========================================================================


@mcp.tool(
    name="lc_list_scratchpad",
    annotations={"title": "List scratchpad files", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_list_scratchpad() -> str:
    """List all files in the auto-offload scratchpad (~/.commander_workspace/scratchpad/).

    When lc_exec_command output exceeds the size threshold it is saved here instead
    of being returned inline. Use this to see what large outputs are available,
    then read them with lc_read_file or search them with lc_search_scratchpad.
    """
    import os
    from lamsystems_commander.shell import SCRATCHPAD_DIR

    if not SCRATCHPAD_DIR.exists():
        return "Scratchpad directory does not exist yet — no large outputs have been saved."

    entries = sorted(SCRATCHPAD_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    if not entries:
        return f"Scratchpad is empty: {SCRATCHPAD_DIR}"

    lines = [f"Scratchpad: {SCRATCHPAD_DIR}", f"{'File':<50} {'Size':>10}  Modified"]
    lines.append("-" * 80)
    for entry in entries:
        stat = entry.stat()
        size = stat.st_size
        import datetime
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size_str = f"{size:,} B" if size < 1024 else (f"{size/1024:.1f} KB" if size < 1_048_576 else f"{size/1_048_576:.1f} MB")
        lines.append(f"{entry.name:<50} {size_str:>10}  {mtime}")
    return "\n".join(lines)


class SearchScratchpadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(..., description="Keywords or phrase to search for.", min_length=1)
    filename: Optional[str] = Field(default=None, description="Limit search to this specific scratchpad file (basename only). If omitted, searches all files.")
    max_results: int = Field(default=30, description="Maximum number of matching lines to return.", ge=1, le=500)
    context_lines: int = Field(default=2, description="Lines of context to show around each match.", ge=0, le=20)


@mcp.tool(
    name="lc_search_scratchpad",
    annotations={"title": "Search scratchpad (BM25)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_search_scratchpad(params: SearchScratchpadInput) -> str:
    """BM25 keyword search across saved command outputs in the scratchpad.

    Ranks every line of every scratchpad file by relevance to your query and
    returns the top matches with surrounding context. Much more useful than
    grep for exploratory queries like 'errors', 'permission denied', 'failed', etc.

    Args:
        params.query: Keywords to search for (space-separated).
        params.filename: Optional — limit to one specific file.
        params.max_results: How many matching lines to return.
        params.context_lines: Lines of context around each match.
    """
    from lamsystems_commander.shell import SCRATCHPAD_DIR

    if not SCRATCHPAD_DIR.exists():
        return "Scratchpad is empty — no large outputs have been saved yet."

    # Resolve target files
    if params.filename:
        target = SCRATCHPAD_DIR / params.filename
        if not target.exists():
            return f"File not found in scratchpad: {params.filename}"
        files_to_search = [target]
    else:
        files_to_search = sorted(SCRATCHPAD_DIR.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files_to_search:
            return "No .log files found in scratchpad."

    # Build corpus: list of (filename, line_number, text) tuples
    corpus: list[tuple[str, int, str]] = []
    for fpath in files_to_search:
        try:
            for lineno, line in enumerate(fpath.read_text(errors="replace").splitlines(), start=1):
                corpus.append((fpath.name, lineno, line))
        except OSError:
            continue

    if not corpus:
        return "Scratchpad files are empty."

    # BM25 scoring
    try:
        from rank_bm25 import BM25Okapi
        tokenised = [row[2].lower().split() for row in corpus]
        bm25 = BM25Okapi(tokenised)
        query_tokens = params.query.lower().split()
        scores = bm25.get_scores(query_tokens)

        # Pair scores with corpus entries and sort
        ranked = sorted(zip(scores, corpus), key=lambda x: x[0], reverse=True)
        top = [(score, fname, lno, text) for score, (fname, lno, text) in ranked if score > 0][:params.max_results]

    except ImportError:
        # Fallback: simple case-insensitive keyword match if rank_bm25 not installed
        keywords = params.query.lower().split()
        top = []
        for fname, lno, text in corpus:
            if any(kw in text.lower() for kw in keywords):
                top.append((1.0, fname, lno, text))
            if len(top) >= params.max_results:
                break

    if not top:
        return f"No matches found for: {params.query}"

    # Build file line maps for context retrieval
    file_lines: dict[str, list[str]] = {}
    for fpath in files_to_search:
        try:
            file_lines[fpath.name] = fpath.read_text(errors="replace").splitlines()
        except OSError:
            file_lines[fpath.name] = []

    output_parts = [f"Top {len(top)} results for: '{params.query}'\n"]
    seen_contexts: set[tuple[str, int]] = set()

    for score, fname, lno, _text in top:
        all_lines = file_lines.get(fname, [])
        start = max(0, lno - 1 - params.context_lines)
        end = min(len(all_lines), lno + params.context_lines)
        # Deduplicate overlapping context blocks
        context_key = (fname, start)
        if context_key in seen_contexts:
            continue
        seen_contexts.add(context_key)

        block = [f"[{fname}:{lno}] (score: {score:.2f})"]
        for i, line in enumerate(all_lines[start:end], start=start + 1):
            prefix = ">>>" if i == lno else "   "
            block.append(f"{prefix} {i:>6}: {line}")
        output_parts.append("\n".join(block))

    return "\n\n".join(output_parts)


# ===========================================================================
# Git
# ===========================================================================


class GitCwdInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwd: Optional[str] = Field(default=None, description="Repository directory. Defaults to server cwd.")


@mcp.tool(
    name="lc_git_status",
    annotations={"title": "git status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_git_status(params: GitCwdInput) -> str:
    """`git status -sb` for the repo at `cwd`."""
    return await git_tools.git_status(cwd=params.cwd)


class GitDiffInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwd: Optional[str] = Field(default=None, description="Repository directory.")
    staged: bool = Field(default=False, description="Show staged diff instead of working tree.")
    path: Optional[str] = Field(default=None, description="Limit diff to this path.")


@mcp.tool(
    name="lc_git_diff",
    annotations={"title": "git diff", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_git_diff(params: GitDiffInput) -> str:
    """`git diff` — optionally staged, optionally for a single path."""
    return await git_tools.git_diff(cwd=params.cwd, staged=params.staged, path=params.path)


class GitLogInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwd: Optional[str] = Field(default=None, description="Repository directory.")
    limit: int = Field(default=20, description="Max commits.", ge=1, le=500)
    path: Optional[str] = Field(default=None, description="Limit log to this path.")


@mcp.tool(
    name="lc_git_log",
    annotations={"title": "git log", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_git_log(params: GitLogInput) -> str:
    """`git log --oneline --decorate` — most recent commits."""
    return await git_tools.git_log(cwd=params.cwd, limit=params.limit, path=params.path)


@mcp.tool(
    name="lc_git_branch",
    annotations={"title": "git branch", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_git_branch(params: GitCwdInput) -> str:
    """`git branch -a -vv` — show all local and remote-tracking branches with tracking info."""
    return await git_tools.git_branch(cwd=params.cwd)


# ===========================================================================
# Tool call log
# ===========================================================================


class GetToolLogInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lines: int = Field(default=50, description="Number of recent log lines to return.", ge=1, le=500)
    filter_level: Optional[str] = Field(default=None, description="Filter by level: 'INFO', 'ERROR', or None for all.")


@mcp.tool(
    name="lc_get_tool_log",
    annotations={"title": "Read tool call log", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def lc_get_tool_log(params: GetToolLogInput) -> str:
    """Read recent entries from the tool call log (~/.commander_workspace/tool_calls.log).

    Every lc_exec_command call is logged with timestamp, command, exit code, and
    any errors. Use this to diagnose why a previous tool call failed.

    Args:
        params.lines: How many recent lines to return.
        params.filter_level: Optional filter — 'INFO' for successful calls, 'ERROR' for failures only.
    """
    if not _LOG_FILE.exists():
        return "Tool call log does not exist yet — no commands have been run this session."

    try:
        all_lines = _LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return f"Could not read log: {e}"

    if params.filter_level:
        level = params.filter_level.upper()
        all_lines = [l for l in all_lines if f"[{level}]" in l]

    recent = all_lines[-params.lines:]
    if not recent:
        return "Log is empty or no entries match the filter."

    return f"Tool call log (last {len(recent)} entries):\n\n" + "\n".join(recent)
