"""Stateless verification of shell.py's pre_filter in CLAUDE mode (the
default, LAMSYSTEMS_COMMANDER_MODE unset or "claude"), then runs
test_prefilter_strict.py for strict mode. Pass --claude-only to skip strict.

In claude mode the allowlist, dangerous-flag, injection, traversal, redirect,
SSH and network-exfil gates are not enforced. What this suite checks:
  "pass"           — pre-filter passes AND the destructive wall does not fire
  "fail_prefilter" — pre-filter fails (bad quoting, $(...)/backticks, or a
                     shell-script run in a non-approvable shape)
  "destructive"    — pre-filter passes, destructive hard wall fires
                     (needs an lc_confirm_destructive token to run)
Plus: block splitting semantics and the script approval-token behaviour.
"""

import os
import sys
import pathlib

os.environ.pop("LAMSYSTEMS_COMMANDER_MODE", None)   # force the default

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
    command_is_destructive,
    _split_raw_blocks,
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
    if command_is_destructive(command):
        return "destructive"
    return "pass"


CASES = [
    # ---- everything a dev shell should just run ----
    ("ls -la",                                     "pass"),
    ("cargo build --release",                      "pass"),
    ("cargo run",                                  "pass"),
    ("cargo add serde",                            "pass"),
    ("npm install",                                "pass"),
    ("npm run build",                              "pass"),
    ("pip install requests",                       "pass"),
    ("uv add requests",                            "pass"),
    ("uv run --with requests pytest",              "pass"),
    ("python3 -c 'print(1)'",                      "pass"),
    ("node -e 'console.log(1)'",                   "pass"),
    ("python3 /tmp/scratch.py",                    "pass"),
    ("curl -sL https://example.com/x.tar.gz -o x.tar.gz", "pass"),
    ("wget https://example.com/file",              "pass"),
    ("ssh user@host uptime",                       "pass"),
    ("scp file user@host:/tmp/",                   "pass"),
    ("rsync -av src/ dst/",                        "pass"),
    ("gh pr create -t x -b y",                     "pass"),
    ("go build ./...",                             "pass"),
    ("godot --headless --export-release linux build/game", "pass"),
    ("echo hi > out.txt",                          "pass"),
    ("cat in.txt >> log.txt",                      "pass"),
    ("sort < in.txt",                              "pass"),
    ("cargo build 2>&1 | tail -20",                "pass"),
    ("grep 'a|b' file",                            "pass"),
    ("grep -E '(foo|bar)$' file",                  "pass"),
    ("cd ../other && ls",                          "pass"),
    ("find . -name '*.pyc' -exec echo {} \\;",    "pass"),
    ("ls /sbin/mkfs",                              "pass"),
    ("man mkfs",                                   "pass"),
    ("fdisk -l",                                   "pass"),
    ("nvme list",                                  "pass"),
    ("smartctl -a /dev/nvme0",                     "pass"),
    ("sudo dmesg | tail",                          "pass"),
    ("sudo dnf install clippy",                    "pass"),
    ("systemctl --user restart foo",               "pass"),
    ("a && b || c ; d",                            "pass"),
    ("sleep 10 &",                                 "pass"),
    ("timeout 30 cargo test",                      "pass"),
    ("env RUSTFLAGS=-Dwarnings cargo build",       "pass"),
    ("echo 'do not run mkfs'",                     "pass"),
    ("echo 'rm -rf /' > notes.txt",                "pass"),
    # ---- destructive wall (kept, unchanged) ----
    ("rm notes.txt",                               "destructive"),
    ("rm -rf build/",                              "destructive"),
    ("ls; rm -rf /",                               "destructive"),
    ("ls | rm -rf /",                              "destructive"),
    ("sudo rm -rf /var/log",                       "destructive"),
    ("nice -n 5 mkfs.ext4 /dev/sdb1",              "destructive"),
    ("dd if=/dev/zero of=/dev/sda",                "destructive"),
    ("cat foo | dd of=/dev/nvme0n1",               "destructive"),
    ("shred -u secret.txt",                        "destructive"),
    ("wipefs -a /dev/sdb",                         "destructive"),
    ("fdisk /dev/sdb",                             "destructive"),
    ("sgdisk --zap-all /dev/sdb",                  "destructive"),
    ("echo x > /dev/sda",                          "destructive"),
    ("nvme format /dev/nvme0n1",                   "destructive"),
    ("sudo nvme sanitize /dev/nvme0",              "destructive"),
    ("bash /home/lam/install.sh",                  "destructive"),
    ("bash /tmp/install.sh",                       "destructive"),
    ("sh /home/lam/x.sh",                          "destructive"),
    ("uv run bash /home/lam/x.sh",                 "destructive"),
    # ---- pre-filter rejects (the only things left) ----
    ("echo $(rm -rf /)",                           "fail_prefilter"),
    ("echo `id`",                                  "fail_prefilter"),
    ("echo 'unterminated",                         "fail_prefilter"),
    ("",                                           "fail_prefilter"),
    ("bash",                                       "fail_prefilter"),
    ("bash -c 'rm -rf /'",                         "fail_prefilter"),
    ("sh -c id",                                   "fail_prefilter"),
    ("zsh -c id",                                  "fail_prefilter"),
    ("bash install.sh",                            "fail_prefilter"),
    ("cat x.sh | bash",                            "fail_prefilter"),
    ("bash < x.sh",                                "fail_prefilter"),
    ("ls && bash -c id",                           "fail_prefilter"),
    ("uv run bash -c id",                          "fail_prefilter"),
    ("timeout 5 bash -i",                          "fail_prefilter"),
]


def main() -> int:
    assert not strict_mode(), "expected claude mode (LAMSYSTEMS_COMMANDER_MODE unset)"
    print("mode: claude")
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

    split_fails = split_tests()
    token_fails = token_tests()
    return 1 if (fails or split_fails or token_fails) else 0


def split_tests() -> int:
    """Raw block splitting: quote/escape aware, && || ; only."""
    cases = [
        ("a && b || c ; d", (["a", "b", "c", "d"], ["", "&&", "||", ";"])),
        ("echo 'a && b' && c", (["echo 'a && b'", "c"], ["", "&&"])),
        ('echo "x;y" ; z', (['echo "x;y"', "z"], ["", ";"])),
        ("cargo build 2>&1 | tail", (["cargo build 2>&1 | tail"], [""])),
        ("find . -exec echo {} \\; ; ls", (["find . -exec echo {} \\;", "ls"], ["", ";"])),
        ("sleep 1 &", (["sleep 1 &"], [""])),
        ("~/bin/x", ([str(pathlib.Path.home() / "bin/x")], [""])),
    ]
    print()
    fails = 0
    for cmd, expected in cases:
        if cmd.startswith("~"):
            import os
            cmd = os.path.expanduser(cmd)
        got = _split_raw_blocks(cmd)
        ok = got == expected
        if not ok:
            fails += 1
        print(f"{'ok  ' if ok else 'FAIL'}  split {cmd!r} -> {got}")
    print(f"{len(cases) - fails}/{len(cases)} split tests pass")
    return fails


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
    rc = main()
    if "--claude-only" not in sys.argv:
        import subprocess
        print("\n" + "=" * 80 + "\nstrict mode (test_prefilter_strict.py)\n" + "=" * 80)
        strict = pathlib.Path(__file__).resolve().parent / "test_prefilter_strict.py"
        rc = subprocess.call([sys.executable, str(strict)]) or rc
    raise SystemExit(rc)
