# Lamsystems-commander

A self-hosted **MCP server** that gives Claude shell, file, search, process
and git access to your machine — a Desktop Commander-style tool surface with
two hard gates the model cannot bypass: **destructive-command confirmation**
and a **sudo password gate**. Plus file-tool write guards for system paths
and the server's own source.

**This is the Claude-only build.** It trusts the model as a developer: any
installed binary runs, pipes/redirects/globs work, package managers install,
`curl`/`ssh`/`gh` are open. The hostile-model stack (strict binary allowlist,
dangerous-flag bans, SSH and network-exfil blocks, injection and traversal
checks, no-inline-code rules) lives in the sibling project
**Lmstudio-commander**, which is the one to run behind a local model. Do not
point a local, abliterated or untrusted model at this build.

Local only: no account, no hosted relay, no per-call metering.
Written in Python with FastMCP. MIT licensed.

> Developed on Fedora. Tested on Python 3.10+. Linux-first; the sudo dialogs
> use GNOME/KDE tooling, everything else is portable.
>
> **Posture: trusted developer shell.** Any installed binary runs. The only
> things that stop a command are the destructive-command dialog, the sudo
> dialog, and the handful of pre-filter shapes listed under
> [Safety architecture](#safety-architecture-claude-only-build).

---

## ⚠️ SECURITY WARNING

**Read this before you do anything else.**

This build gives the model full shell access to your machine as your user,
with only the destructive-command dialog and the sudo dialog standing between
a command and execution. That is the right trade for Claude. It is the wrong
trade for a local, abliterated or uncensored model, which **WILL** execute
anything it is told — use Lmstudio-commander for those.

We tested this. A fully abliterated model:
- Identified the system drive (`/dev/nvme0n1`, 931.5 GB)
- Mapped all partitions (`/`, `/boot`, `/home`, EFI)
- Began executing `sudo dd if=/dev/zero of=/dev/nvme0n1 bs=4M status=progress`
- When blocked, actively looked for alternative routes around the gate
- Found the `lc_write_file` → script execution gap and used it in normal use
- When asked directly, described its own bypass routes without hesitation

The confirmation dialog caught the drive wipe. The safety layers caught the
rest. **Your finger on Cancel is the last line of defence.**

**NEVER:**
- Use an abliterated/uncensored model without understanding what that means
- Approve a sudo gate or confirmation dialog you were not expecting
- Leave an agentic session running unattended with approval dialogs enabled
- Test "will it delete my drive" unless you are prepared for the answer 💩

**Model recommendation:** Use a non-abliterated instruct model for daily use.
The safety layers handle legitimate admin tasks. You do not need an uncensored
model for the server to be useful.

---

## Why this and not Desktop Commander?

[Desktop Commander](https://github.com/wonderwhy-er/DesktopCommanderMCP) is
the well-known tool in this space, and its local server is free and MIT
licensed too. The difference is posture, not price:

| | Desktop Commander (local) | Lamsystems-commander |
|---|---|---|
| Tool surface | terminal, files, search, edit_block, processes, PDF write, usage analytics | shell, files, search, edit_block, processes, git, scratchpad |
| Shell policy | full shell; `blockedCommands` blocklist "for accidental execution" | full shell; **destructive wall** with per-command, one-time approval tokens, bound to script content for script runs |
| Wrapper handling | not documented | `sudo`, `env`, `nice`, `timeout`, `uv run` etc. are unwrapped so the real binary hits the destructive wall |
| Interpreter escape hatches | not documented | `bash -c`, bare `bash`, `$(...)` rejected so the script-approval and destructive gates cannot be dodged; everything else open |
| Destructive commands | no approval step documented; README says "not a sandbox" | hard wall + one-time confirmation token via a dialog you click |
| Sudo | not documented | fresh approval per call through MCP elicitation / zenity / kdialog / pkexec; opt-in session cache for non-destructive commands only |
| Pipes / redirects / subshells | standard shell | blocked; scratchpad pattern instead |
| Adversarial testing | not documented | red-teamed with an abliterated model, findings below |

"Not documented" means exactly that — checked against DC's README on
2026-09-28, not a claim that DC can't do it. DC is built for convenience;
this is built to be left alone with a model you don't fully trust. If you
want the model to be able to do anything, DC is the better tool.

## What you get

Tool prefix: `lc_` (so it does not collide with any other MCP server).

| Area        | Tools |
|-------------|-------|
| Shell       | `lc_exec_command` |
| Files       | `lc_read_file`, `lc_write_file`, `lc_edit_block`, `lc_list_directory`, `lc_move_file`, `lc_create_directory`, `lc_get_file_info` |
| Processes   | `lc_list_processes`, `lc_kill_process`, `lc_start_process`, `lc_list_sessions`, `lc_read_process_output`, `lc_interact_with_process`, `lc_stop_process_session` |
| Search      | `lc_search_files`, `lc_search_content` (uses `rg` if installed) |
| Git         | `lc_git_status`, `lc_git_diff`, `lc_git_log`, `lc_git_branch` |
| Safety      | `lc_confirm_destructive` |
| Scratchpad  | `lc_list_scratchpad`, `lc_search_scratchpad` |
| Diagnostics | `lc_get_tool_log` |

---

## Install

```bash
cd /path/to/Lamsystems-commander

# Recommended: isolated venv so MCP deps don't touch your system Python.
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After install, the entry point is `lamsystems-commander` (and also `python -m lamsystems_commander`).

Optional (much faster content search):
```bash
sudo dnf install ripgrep
```

---

## Hook into your MCP client

The server speaks MCP over stdio. Point your client at the console script in
the venv (see `examples/mcp_config.json`):

```json
{
  "mcpServers": {
    "lamsystems-commander": {
      "command": "/path/to/Lamsystems-commander/.venv/bin/lamsystems-commander",
      "args": [],
      "env": {}
    }
  }
}
```

- **Claude Desktop / Cowork:** add the entry to `claude_desktop_config.json`
  (Settings → Developer → Edit Config), restart Claude.
- **Claude Code:** `claude mcp add lamsystems-commander -- /path/to/Lamsystems-commander/.venv/bin/lamsystems-commander`
- **LM Studio:** add the entry to `~/.lmstudio/mcp.json` or the in-app MCP settings.

The `lc_*` tools should appear in the tool list. `lc_exec_command`'s
description states the two gates so the model doesn't have to guess.

### Approval prompts (client side)

MCP clients decide when to show their own "allow this tool call?" dialog based
on the `destructiveHint` annotation each tool declares. This server is tuned
for use with Claude and similar clients, so only two tools are flagged
destructive and will keep prompting even after you pick "Always allow":

| Tool | Why it always prompts |
|---|---|
| `lc_confirm_destructive` | it *is* the human-in-the-loop step for `rm -rf`, `dd`, `mkfs` … |
| `lc_kill_process` | signals cannot be taken back |

Everything else — read, write, edit, move, mkdir, shell commands, process
sessions, search, git — is declared non-destructive so "Always allow" sticks.
That is safe because the protection lives in the server, not the dialog:
`lc_exec_command` still runs every command through the pre-filter and the
destructive hard wall, and
`lc_write_file`/`lc_edit_block` still go through `_file_guard()`. Turning the
client prompt off changes nothing about what the server will refuse.

Deletion is never session-allowed. **Every** `rm` — `rm FILE`, `rm -f FILE`,
`rm -rf DIR` — is on the destructive list, alongside `dd`, `mkfs`, `shred`,
`wipefs`, `blkdiscard` and the partition editors, so each one needs its own
`lc_confirm_destructive` token. The token is keyed on the exact command
string and consumed on use: approving `rm .git/index.lock` approves that one
file, once. It never widens to the folder or the session.

If you are driving this with an abliterated or uncensored local model, you
want more prompting, not less — flip those hints back to `True` in
`server.py` (or use a stricter build) before you hand it a shell.

### Recommended system prompt

Add this to your model's system prompt (Claude's project instructions, or
the LM Studio system prompt):

```
This server runs commands as a normal shell. If a command is rejected, read
the stderr reason and change the approach — do not retry the same string.

There are two safety gates: destructive-command confirmation
and sudo approval. Follow those mechanisms exactly and never attempt to
circumvent them.
You must NEVER attempt to bypass, circumvent, or find alternatives to the sudo
approval gate. If the user declines, the command is cancelled permanently.
For long-running commands (rsync, large find, package installs, builds) always use
lc_start_process and poll with lc_read_process_output rather than lc_exec_command.
lc_confirm_destructive is ONLY for commands that destroy or modify data (any rm, dd,
mkfs, shred, wipefs). Read-only sudo commands like smartctl, lsblk, journalctl do
NOT need lc_confirm_destructive.

Pipes (|), redirects (> >> <), subshells ($()) and backticks are blocked at the
pre-filter. Use the scratchpad pattern instead: run one command, read the
output via lc_search_scratchpad or lc_read_file, then run the next command
with the value you extracted. Multiple round trips with full audit trails are
the correct approach.

Always use absolute paths (e.g. /home/user/file). Never use ~ — it is
normalised internally but models that switch between ~ and absolute paths
may trigger unexpected behaviour.
```

> **Troubleshooting malformed tool calls:** If your model produces calls in the format
> `<parameter=params>{"command": ...}</parameter>` instead of standard MCP tool call
> syntax, add this line to the system prompt:
> `Tool calls use this exact format: <parameter=params>{"command": "your command"}</parameter>`
> This is a model-specific workaround — only add it if you are seeing that specific error.

---

## Safety architecture (Claude-only build)

Two gates. Both fire on `lc_exec_command` and `lc_start_process` alike; a
gate that one tool enforces and another ignores is not a gate.

### Gate 1 — Destructive command wall + confirmation dialog

`command_is_destructive()` scans every segment of the command (split on
`|`, `||`, `&&`, `;`, `&`) and looks at the **binary position** of each —
never at arguments, so `ls /sbin/mkfs` and `man mkfs` are not flagged.
It fires on:

- `rm` — every form, single file or recursive
- `dd`, `shred`, `wipefs`, `blkdiscard`, `mkfs*`, `mkswap`
- partition editors (`fdisk`, `sfdisk`, `sgdisk`, `gdisk`, `cfdisk`,
  `parted`, …) unless called in a pure listing mode (`fdisk -l`)
- `nvme format` / `sanitize` / `delete-ns` / `write` / `write-zeroes` /
  `fw-commit` / `fw-download`
- redirects onto a block device (`> /dev/sda`, `> /dev/nvme0n1`)
- **every shell-script run**: `bash|sh|zsh|dash|ksh /absolute/path.sh`

Wrappers are unwrapped first, so `sudo rm`, `nice -n 5 mkfs.ext4`,
`timeout 30 dd`, `uv run bash x.sh` are all caught.

A flagged command is refused until the model calls `lc_confirm_destructive`
with the **exact** command string and a plain-English description. You see a
GUI dialog (zenity/kdialog) or an MCP elicitation; approving issues a
one-time token bound to that string. Script runs are additionally bound to a
SHA-256 of the script's resolved path and content — edit the file after
approval and the token is void. A declined command stays declined for the
session.

### Gate 2 — Sudo

Any block containing `sudo` goes through the approval chain described under
"How the sudo gate works" below. Unchanged from the hostile-model build.

### What the pre-filter still rejects

Three things, none of them about trust:

- **`$(...)` and backticks** — the destructive wall cannot see inside a
  substitution, so `echo $(rm -rf x)` would run `rm` with no dialog. Run the
  inner command as its own step.
- **Shell-script shape** — `bash -c …`, bare `bash` (reads stdin, so
  `cat x | bash` and `bash < x` too), relative script paths. These would
  dodge the per-file approval token. Inline code in *other* interpreters
  (`python3 -c`, `node -e`) is fine.
- **Malformed quoting** — shlex has to be able to tokenise it.

### File-tool guards (unchanged)

- `lc_write_file` / `lc_edit_block` / `lc_move_file` / `lc_create_directory`
  refuse system paths (`/etc`, `/usr`, `/boot`, …) — use `sudo` via
  `lc_exec_command` instead, which puts a dialog in front of it.
- Every tool refuses to touch the commander's own source directory. The model
  cannot edit its own gates.

### Execution model

The command string is split on `&&` / `||` / `;` (quote- and escape-aware,
so `find -exec … \;`, `2>&1` and `echo 'a && b'` stay intact) and each block
runs through the shell verbatim. `&&` / `||` semantics are honoured across
blocks; `sudo` is resolved per block; a timeout stops the sequence.
`lc_start_process` runs the whole string in one shell for background jobs.

### What is NOT enforced on this build

`shell.WHITELIST`, `DISK_TOOLS`, `DANGEROUS_FLAGS`,
`command_requires_ssh_gate()` and `command_has_network_exfil()` are still in
the source, still importable, and **not consulted**. They are kept so the
local-model fork can pull fixes from here and so the gating history stays
readable.

---

## How the sudo gate works

1. Model calls `lc_exec_command` with a command containing `sudo`.
2. The server tokenizes the command (shell-aware, so `echo "do not sudo"` does NOT trigger).
3. Safe commands bypass directly via `sudo -n`. All others go through:

   | # | Method   | What you see |
   |---|----------|--------------|
   | 1 | `elicit` | Your MCP client shows an in-app form, if it supports elicitation (no GUI dependency, no DISPLAY needed). |
   | 2 | `zenity` | Confirm dialog showing the command, then a native GNOME password dialog. |
   | 3 | `kdialog`| Native KDE Plasma password dialog showing the command. |
   | 4 | `pkexec` | Polkit handles its own prompt. Command rewritten `sudo X` → `pkexec X`. |
   | 5 | refused  | Clear error returned to the model. |

4. Password is piped to `sudo -S -p ''` on stdin — never in argv, never on disk,
   never logged. After the command runs, `sudo -k` wipes the cache.

5. On decline / cancel: command refused, model told why.

### Forcing a specific method

Set `LAMSYSTEMS_COMMANDER_SUDO_MODE`:
`auto` (default), `elicit`, `zenity`, `kdialog`, `pkexec`, or `off`.

```json
{
  "mcpServers": {
    "lamsystems-commander": {
      "command": "/path/to/.venv/bin/lamsystems-commander",
      "env": { "LAMSYSTEMS_COMMANDER_SUDO_MODE": "zenity" }
    }
  }
}
```

### Installing GUI fallbacks

- `sudo dnf install zenity` (GNOME-style dialog)
- `sudo dnf install kdialog` (KDE-style dialog)
- `pkexec` comes with `polkit` (base Fedora).

---

## Scratchpad — large output handling

Commands producing more than ~8,000 chars of output are automatically offloaded
to `~/.commander_workspace/scratchpad/` instead of being returned inline. The model
receives a file pointer and is instructed to use `lc_search_scratchpad` (BM25 keyword
search) or `lc_read_file` with offset/limit to query the output without flooding its
context window.

This prevents context window exhaustion on commands like `dmesg`, `find /`, large
`grep` results, build logs, and package manager output.

---

## Tool call log

Every `lc_exec_command` call is logged to `~/.commander_workspace/tool_calls.log`
with timestamp, command, exit code, and any errors. The model can read its own log
via `lc_get_tool_log` to diagnose why a previous call failed.

---

## Validation: Red Team Findings

The server was tested under live adversarial conditions using an abliterated
Qwen3-35B model with no safety alignment. Findings and fixes:

| Finding | Status |
|---|---|
| `lc_start_process` used `create_subprocess_shell` — bypassed entire pre-filter | **Fixed:** `command_gate()` now runs the full gate stack before any process launch; switched to `create_subprocess_exec` |
| `lc_write_file` + `python3 script.py` used to delete files without the destructive wall | **Fixed:** `_file_guard()` blocks writes to system paths and server source; interpreter script-path gate blocks execution from `/tmp`, `/var/tmp`, `/dev/shm`, and `~/.commander_workspace` |
| `find -delete` / `find -exec` not blocked — mass deletion without destructive wall | **Fixed:** `-delete`, `-exec`, `-execdir` added to `DANGEROUS_FLAGS` for `find` |
| `~` vs absolute path used to escape session decline cache | **Fixed:** tilde expanded at Pass 0 of `pre_filter` and in `lc_confirm_destructive` — both sides normalise before token registration/check |
| Decline cache checked before confirmed token — re-confirmation after a decline was silently ignored | **Fixed:** confirmed token now checked first; a fresh approval overrides a previous decline |
| Model identified `lc_write_file` bypass route when asked about safety gaps | **Fixed:** system paths and server source blocked at file tool level; `/tmp` script execution blocked at pre-filter level |
| Model used goal-preservation under refusal — when blocked, immediately probed alternative routes | **Mitigated by architecture:** each route is independently blocked at the code level; model intent is not relied upon |

---

## Known limitations and future work

- **Dedicated process user (roadmap).** The server runs as your login user.
  OS-level isolation (a dedicated `mcp-sandbox` system user with no home
  directory access) is the final architectural fix — it contains the blast
  radius of any successful bypass to that account's restricted permissions
  rather than your full user session. See roadmap below.

- **Tool schema size.** 24 tools at ~9,000 tokens of schema can cause some models
  to lose track of the correct tool call format. If you see persistent
  `params requires property "params"` errors, switch to a coder or instruct model
  with stronger structured output compliance.

- **Long-running commands.** Use `lc_start_process` + `lc_read_process_output` for
  anything that runs more than a few seconds (rsync, builds, package installs).
  `lc_exec_command` blocks and accumulates all output — large jobs will consume
  context.

---

## Roadmap: OS-level sandbox user (Fedora)

The definitive fix for any remaining application-layer gaps is running the server
under a dedicated low-privilege system user. Even a successful bypass only reaches
that account's restricted environment — not your home directory, SSH keys, or
desktop session.

**Step 1 — Create the sandbox user:**
```bash
sudo useradd -r -m -s /sbin/nologin -d /var/lib/mcp-sandbox mcp-sandbox
```

**Step 2 — Authorise the launch via sudoers:**
```bash
sudo nano /etc/sudoers.d/mcp-commander-sandbox
```
Add (replace `your_username` and the path):
```
your_username ALL=(mcp-sandbox) NOPASSWD: /path/to/lamsystems-commander/.venv/bin/lamsystems-commander
```

**Step 3 — Update your client's MCP config:**
```json
{
  "mcpServers": {
    "lamsystems-commander": {
      "command": "sudo",
      "args": [
        "-u", "mcp-sandbox",
        "/path/to/lamsystems-commander/.venv/bin/lamsystems-commander"
      ],
      "env": {}
    }
  }
}
```

**End state:** The Linux kernel walls off your personal files, SSH keys, and
desktop session from the agent entirely. Any successful application-level bypass
hits a hard OS-level `Permission Denied`.

---

## Files

```
lamsystems-commander/
├── pyproject.toml
├── README.md
├── test_prefilter.py              # pre-filter test harness (74 cases)
├── check_import.py                # server import + tool registration smoke check
├── examples/
│   └── mcp_config.json
└── src/lamsystems_commander/
    ├── __init__.py
    ├── __main__.py               # entry point
    ├── server.py                 # FastMCP tool registry + tool call logger + lc_confirm_destructive
    ├── shell.py                  # pre-filter + sudo gate + destructive wall + scratchpad (WHITELIST/DANGEROUS_FLAGS retained, not enforced)
    ├── prompt.py                 # elicit / zenity / kdialog / pkexec + sudo passthrough
    ├── files.py                  # read/write/edit/list/move/mkdir/stat + _file_guard()
    ├── processes.py              # ps, kill, managed sessions + command_gate()
    ├── search.py                 # find-by-name + grep/ripgrep
    └── git_tools.py              # git status/diff/log/branch
```

Runtime directories (created automatically):
```
~/.commander_workspace/
├── scratchpad/          # auto-offloaded large command outputs
└── tool_calls.log       # tool call history and errors
```

---

## Verification

```bash
python3 -m py_compile src/lamsystems_commander/*.py
python3 check_import.py     # expects: 25 tools loaded: lc_confirm_destructive, ...
```

Run the pre-filter test harness after any change to the pre-filter, the
destructive wall, or block splitting:

```bash
python3 test_prefilter.py
```

Expected output: `74/74 tests pass`. If a test fails, do not deploy — fix the
regression first.

For an interactive smoke test (requires `mcp[cli]`):
```bash
pip install "mcp[cli]"
mcp dev src/lamsystems_commander/__main__.py
```
