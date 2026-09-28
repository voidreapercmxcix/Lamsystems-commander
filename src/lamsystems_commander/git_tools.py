"""Git helpers — thin async wrappers around the git CLI.

These exist so the LLM can answer common questions ("what changed?", "what's the
branch?") without needing to compose its own shell commands.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional


async def _run_git(args: list[str], cwd: Optional[str] = None, timeout: float = 30.0) -> str:
    if cwd:
        cwd = os.path.expanduser(cwd)
        if not os.path.isdir(cwd):
            return f"Error: cwd not found: {cwd}"

    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"Error: git {' '.join(args)} timed out after {timeout}s"

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if proc.returncode != 0:
        return f"git exit {proc.returncode}\n{out}{err}".rstrip()
    return out if out else "(no output)"


async def git_status(cwd: Optional[str] = None) -> str:
    """`git status -sb` — short branch-aware status."""
    return await _run_git(["status", "-sb"], cwd=cwd)


async def git_diff(
    cwd: Optional[str] = None,
    staged: bool = False,
    path: Optional[str] = None,
) -> str:
    """`git diff` — optionally staged, optionally for a single path."""
    args = ["diff"]
    if staged:
        args.append("--staged")
    if path:
        args += ["--", path]
    return await _run_git(args, cwd=cwd)


async def git_log(cwd: Optional[str] = None, limit: int = 20, path: Optional[str] = None) -> str:
    """`git log` — one line per commit, optionally filtered to a path."""
    args = ["log", f"-n{max(1, limit)}", "--oneline", "--decorate"]
    if path:
        args += ["--", path]
    return await _run_git(args, cwd=cwd)


async def git_branch(cwd: Optional[str] = None) -> str:
    """`git branch -a -vv` — current and all remote-tracking branches."""
    return await _run_git(["branch", "-a", "-vv"], cwd=cwd)
