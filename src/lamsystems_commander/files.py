"""File operation tools — read, write, edit, list, move, stat, mkdir.

These run as the user owning the MCP server process. Operations on root-owned
paths must go through the shell tool, which will route them through the sudo gate.
"""

from __future__ import annotations

import json
import os
import shutil
import stat as stat_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path)).resolve(strict=False)


def _format_mode(mode: int) -> str:
    """Render the 'rwxrwxrwx' style string for a stat mode."""
    return stat_module.filemode(mode)


def _format_size(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}{unit}"
        n /= 1024.0
    return f"{n:.1f}P"


# ---------------------------------------------------------------------------
# File guard — blocks writes to protected paths
# ---------------------------------------------------------------------------
# Applied to write_file, edit_block, and move_file before any disk operation.
# Two classes of protection:
#
#   1. Server source directory — a model must not be able to rewrite its own
#      safety constraints, allowlists, or gate logic via the file tools.
#      (lc_exec_command already has this via command_targets_server_source;
#      this closes the equivalent gap in the file path.)
#
#   2. System paths — writes outside the home directory to OS-managed paths
#      (/etc, /usr, /bin, /boot, /dev, /sys, /proc, /run, /lib, /lib64)
#      are blocked. Legitimate admin writes go through lc_exec_command with
#      explicit sudo approval.

_SERVER_SOURCE_DIR = Path(__file__).parent.resolve()
_HOME_DIR = Path.home().resolve()

_BLOCKED_WRITE_PREFIXES: tuple[Path, ...] = (
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/sys"),
    Path("/proc"),
    Path("/dev"),
    Path("/run"),
)


def _file_guard(path: Path, operation: str = "write") -> Optional[str]:
    """Return an error string if a write/move to `path` is blocked, else None.

    Called before every mutating file operation. Returns None on pass.
    """
    resolved = path.resolve() if path.exists() else path

    # Block 1: server source directory integrity
    try:
        resolved.relative_to(_SERVER_SOURCE_DIR)
        return (
            f"BLOCKED: {operation} to the server source directory is not permitted. "
            f"A model cannot modify its own safety constraints via file tools."
        )
    except ValueError:
        pass

    # Block 2: system paths outside home
    for blocked in _BLOCKED_WRITE_PREFIXES:
        try:
            resolved.relative_to(blocked)
            return (
                f"BLOCKED: {operation} to system path '{blocked}' is not permitted via "
                f"file tools. Use lc_exec_command with appropriate sudo approval instead."
            )
        except ValueError:
            pass

    return None  # all clear


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def read_file(path: str, offset: int = 0, limit: Optional[int] = None) -> str:
    """Read a text file. `offset` and `limit` count lines, not bytes.

    Returns the file contents (sliced if requested) plus a header showing the
    real path, total line count, and which lines were returned.
    """
    p = _expand(path)
    if not p.exists():
        return f"Error: file not found: {p}"
    if p.is_dir():
        return f"Error: path is a directory, not a file: {p}"

    # Binary-safe peek: read in binary, decode with replace.
    try:
        raw = p.read_bytes()
    except PermissionError as e:
        return f"Error: permission denied: {e}"

    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    total = len(lines)

    end = total if limit is None else min(total, offset + limit)
    sliced = "".join(lines[offset:end])

    header = (
        f"# {p}\n"
        f"# total_lines={total}, returned={offset}..{end}\n"
    )
    return header + sliced


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


def write_file(path: str, content: str, mode: str = "overwrite") -> str:
    """Write a file. `mode` is 'overwrite' or 'append'.

    Creates parent directories as needed.
    """
    p = _expand(path)
    if mode not in ("overwrite", "append"):
        return f"Error: invalid mode '{mode}', use 'overwrite' or 'append'"

    guard = _file_guard(p, "write")
    if guard:
        return guard

    p.parent.mkdir(parents=True, exist_ok=True)
    fmode = "w" if mode == "overwrite" else "a"
    try:
        with open(p, fmode, encoding="utf-8") as fh:
            fh.write(content)
    except PermissionError as e:
        return f"Error: permission denied: {e}"

    return f"Wrote {len(content)} chars to {p} ({mode})"


# ---------------------------------------------------------------------------
# Edit block — surgical find/replace
# ---------------------------------------------------------------------------


def edit_block(
    path: str,
    old_string: str,
    new_string: str,
    expected_replacements: int = 1,
) -> str:
    """Replace `old_string` with `new_string` exactly `expected_replacements` times.

    Refuses if the actual count differs from expected — surfaces a clear error
    so the caller can broaden context, narrow it, or set the right count.
    """
    p = _expand(path)
    if not p.exists():
        return f"Error: file not found: {p}"
    if old_string == new_string:
        return "Error: old_string and new_string are identical — nothing to do"

    guard = _file_guard(p, "edit")
    if guard:
        return guard

    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return "Error: file is not utf-8 text. Use write_file or a shell tool."
    except PermissionError as e:
        return f"Error: permission denied: {e}"

    count = text.count(old_string)
    if count == 0:
        return f"Error: old_string not found in {p}"
    if count != expected_replacements:
        return (
            f"Error: expected {expected_replacements} replacement(s), but old_string "
            f"appears {count} time(s) in {p}. Pass expected_replacements={count} "
            f"if you want to replace all of them, or expand old_string for uniqueness."
        )

    new_text = text.replace(old_string, new_string)
    p.write_text(new_text, encoding="utf-8")
    return f"Replaced {count} occurrence(s) in {p}"


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------


def list_directory(path: str, show_hidden: bool = False) -> str:
    """List a directory's contents with type, size, and mtime."""
    p = _expand(path)
    if not p.exists():
        return f"Error: directory not found: {p}"
    if not p.is_dir():
        return f"Error: not a directory: {p}"

    try:
        entries = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError as e:
        return f"Error: permission denied: {e}"

    rows = [f"# {p}", f"{'TYPE':<5} {'PERMS':<11} {'SIZE':>8}  {'MTIME':<20} NAME"]
    for entry in entries:
        if not show_hidden and entry.name.startswith("."):
            continue
        try:
            st = entry.lstat()
        except FileNotFoundError:
            continue  # symlink to nowhere etc.
        kind = (
            "DIR" if entry.is_dir() else
            "LNK" if entry.is_symlink() else
            "FILE"
        )
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        rows.append(
            f"{kind:<5} {_format_mode(st.st_mode):<11} "
            f"{_format_size(st.st_size):>8}  {mtime}  {entry.name}"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Move / rename
# ---------------------------------------------------------------------------


def move_file(source: str, destination: str) -> str:
    src = _expand(source)
    dst = _expand(destination)
    if not src.exists():
        return f"Error: source not found: {src}"

    guard = _file_guard(src, "move (source)")
    if guard:
        return guard
    guard = _file_guard(dst, "move (destination)")
    if guard:
        return guard

    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dst))
    except PermissionError as e:
        return f"Error: permission denied: {e}"
    return f"Moved {src} -> {dst}"


# ---------------------------------------------------------------------------
# Create directory
# ---------------------------------------------------------------------------


def create_directory(path: str, parents: bool = True) -> str:
    p = _expand(path)
    try:
        p.mkdir(parents=parents, exist_ok=True)
    except PermissionError as e:
        return f"Error: permission denied: {e}"
    return f"Created directory {p}"


# ---------------------------------------------------------------------------
# Stat info
# ---------------------------------------------------------------------------


def get_file_info(path: str) -> str:
    p = _expand(path)
    if not p.exists():
        return f"Error: not found: {p}"
    st = p.lstat()
    info = {
        "path": str(p),
        "type": (
            "directory" if p.is_dir() else
            "symlink" if p.is_symlink() else
            "file"
        ),
        "size_bytes": st.st_size,
        "size_human": _format_size(st.st_size),
        "permissions": _format_mode(st.st_mode),
        "owner_uid": st.st_uid,
        "group_gid": st.st_gid,
        "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "created": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
    }
    if p.is_symlink():
        info["link_target"] = os.readlink(p)
    return json.dumps(info, indent=2)
