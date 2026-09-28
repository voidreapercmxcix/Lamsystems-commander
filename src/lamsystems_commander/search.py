"""Search tools — by name and by content.

Prefers ripgrep (`rg`) when installed for content search because it is dramatically
faster than Python on large trees. Falls back to a pure-Python recursive walk so
the server still works on a fresh system without rg installed.
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import re
import shutil
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Search by name
# ---------------------------------------------------------------------------


def search_files(
    root: str,
    pattern: str,
    max_results: int = 200,
    include_hidden: bool = False,
) -> str:
    """Recursively find files matching a glob pattern (e.g. '*.py', 'foo_*.json').

    Returns one path per line. Stops after `max_results` to keep the LLM context lean.
    """
    base = Path(os.path.expanduser(root)).resolve()
    if not base.exists():
        return f"Error: root not found: {base}"
    if not base.is_dir():
        return f"Error: root is not a directory: {base}"

    matches: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if not include_hidden and fn.startswith("."):
                continue
            if fnmatch.fnmatch(fn, pattern):
                matches.append(os.path.join(dirpath, fn))
                if len(matches) >= max_results:
                    return "\n".join(matches) + f"\n... [stopped at {max_results}]"
    return "\n".join(matches) if matches else f"No matches for '{pattern}' under {base}"


# ---------------------------------------------------------------------------
# Search by content
# ---------------------------------------------------------------------------


async def search_content(
    root: str,
    pattern: str,
    *,
    file_glob: Optional[str] = None,
    case_insensitive: bool = False,
    max_results: int = 200,
    context_lines: int = 0,
) -> str:
    """Search file *contents* for a regex.

    Uses ripgrep when available, otherwise a Python fallback. Result format
    is one match per line: `path:lineno:matched-text`.
    """
    base = Path(os.path.expanduser(root)).resolve()
    if not base.exists():
        return f"Error: root not found: {base}"

    rg = shutil.which("rg")
    if rg:
        return await _rg_search(
            rg, str(base), pattern,
            file_glob=file_glob,
            case_insensitive=case_insensitive,
            max_results=max_results,
            context_lines=context_lines,
        )
    return _python_search(
        base, pattern,
        file_glob=file_glob,
        case_insensitive=case_insensitive,
        max_results=max_results,
    )


async def _rg_search(
    rg: str,
    root: str,
    pattern: str,
    *,
    file_glob: Optional[str],
    case_insensitive: bool,
    max_results: int,
    context_lines: int,
) -> str:
    argv = [rg, "--line-number", "--no-heading", "--color=never"]
    if case_insensitive:
        argv.append("-i")
    if context_lines > 0:
        argv += ["-C", str(context_lines)]
    if file_glob:
        argv += ["-g", file_glob]
    argv += ["--max-count", str(max(1, max_results))]
    argv += [pattern, root]

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode not in (0, 1):  # rg returns 1 when no matches
        return f"ripgrep error: {stderr.decode(errors='replace')}"

    text = stdout.decode(errors="replace")
    if not text.strip():
        return f"No matches for /{pattern}/ under {root}"

    lines = text.splitlines()
    if len(lines) > max_results:
        return "\n".join(lines[:max_results]) + f"\n... [stopped at {max_results}]"
    return text


def _python_search(
    base: Path,
    pattern: str,
    *,
    file_glob: Optional[str],
    case_insensitive: bool,
    max_results: int,
) -> str:
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return f"Error: invalid regex: {e}"

    matches: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if file_glob and not fnmatch.fnmatch(fn, file_glob):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if regex.search(line):
                            matches.append(f"{path}:{lineno}:{line.rstrip()}")
                            if len(matches) >= max_results:
                                return "\n".join(matches) + f"\n... [stopped at {max_results}]"
            except (OSError, UnicodeDecodeError):
                continue
    return "\n".join(matches) if matches else f"No matches for /{pattern}/ under {base}"
