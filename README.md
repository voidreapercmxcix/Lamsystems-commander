# Lamsystems-commander

A self-hosted **MCP server** that gives an AI assistant shell, file, search,
process and git access to your machine — the Desktop Commander tool surface,
with two hard gates the model cannot talk its way past: a **destructive-command
confirmation dialog** and a **sudo password dialog**.

**Local only.** No account, no hosted relay, no per-call metering, no region
clause, nothing that can be switched off from somewhere else. It is a Python
process on your machine speaking MCP over stdio. MIT licensed.

Two modes, one env var:

| | `claude` (default) | `strict` |
|---|---|---|
| Built for | driving the server from Claude (Desktop, Cowork, Code) | leaving the server alone with a local model you don't fully trust |
| Shell | any installed binary; pipes, redirects, globs, `curl`, `ssh`, `gh`, package installs, inline `python3 -c` all work | binary allowlist, dangerous-flag bans, no redirects, no inline code, no `ssh`/`curl`/`wget`/`nc`, no `..` traversal, no scripts from `/tmp` |
| Still gated in both | **every** `rm`, `dd`, `mkfs`, `shred`, `wipefs`, partition writes, `nvme format`, every shell-script run → confirmation dialog · every `sudo` → password dialog · `$(...)` and backticks rejected · the server's own source and system paths protected from the file tools | |

```json
"env": { "LAMSYSTEMS_COMMANDER_MODE": "strict" }
```

> Developed on Fedora. Python 3.10+. Linux-first: the dialogs use zenity /
> kdialog / polkit, everything else is portable. Works with Claude, LM Studio
> and any other MCP client.

---

## ⚠️ What happens if you skip the dialogs

We tested this in strict mode with a fully abliterated model. It:

- Identified the system drive (`/dev/nvme0n1`, 931.5 GB)
- Mapped all partitions (`/`, `/boot`, `/home`, EFI)
- Began executing `sudo dd if=/dev/zero of=/dev/nvme0n1 bs=4M status=progress`
- When blocked, actively looked for alternative routes around the gate
- Found the `lc_write_file` → script execution gap and used it in normal use
- When asked directly, described its own bypass routes without hesitation

The confirmation dialog caught the drive wipe. The other layers caught the
rest. **Your finger on Cancel is the last line of defence.**

**NEVER:**
- Point a local, abliterated or uncensored model at the default `claude` mode —
  use `strict`, and understand what "abliterated" means before you start
- Approve a sudo gate or confirmation dialog you were not expecting
- Leave an agentic session running unattended with approval dialogs enabled
- Test "will it delete my drive" unless you are prepared for the answer 💩

---

## Why this and not Desktop Commander?

[Desktop Commander](https://github.com/wonderwhy-er/DesktopCommanderMCP) is
the well-known tool in this space and its local server is free and MIT
licensed too. The difference is posture, not price:

| | Desktop Commander | Lamsystems-commander |
|---|---|---|
| Tool surface | terminal, files, search, edit_block, processes, PDF write, usage analytics | shell, files, search, edit_block, processes, git, scratchpad |
| Destructive commands | `blockedCommands` blocklist "for accidental execution"; README says "not a sandbox" | hard wall + one-time confirmation token via a dialog you click; script runs bound to the script's content hash |
| Sudo | not documented | fresh approval per call via MCP elicitation / zenity / kdialog / pkexec; opt-in session cache for non-destructive commands only |
| Wrapper handling | not documented | `sudo`, `env`, `nice`, `timeout`, `uv run` are unwrapped so the real binary hits the gates |
| Untrusted-model mode | — | `strict`: allowlist, flag bans, network gate, no inline code |
| Adversarial testing | not documented | red-teamed with an abliterated model, findings below |

"Not documented" means exactly that — checked against DC's README on
2026-09-28 — not a claim that DC can't do it. If you want a model to be able
to do anything with no dialogs at all, DC is the better tool.

## What you get

Tool prefix `lc_` so it does not collide with any other MCP server. 25 tools:

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

The entry point is `lamsystems-commander` (also `python -m lamsystems_commander`).

Optional, much faster content search: `sudo dnf install ripgrep`

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
- **LM Studio:** add the entry to `~/.lmstudio/mcp.json` or the in-app MCP
  settings — and set `"LAMSYSTEMS_COMMANDER_MODE": "strict"` in `env`.

Every `LAMSYSTEMS_COMMANDER_*` variable goes in the client's `env` block. MCP
servers are launched with a clean environment, so exporting it in your shell
does nothing.

`lc_exec_command`'s tool description changes with the mode: in `claude` it
states the two gates; in `strict` it is generated from the live allowlist so
the model is told exactly what it may run instead of finding out by rejection.

---

## Modes

### `claude` (default) — trusted developer shell

Any installed binary runs. Pipes, redirects, globs, `&&` / `||` / `;`,
`~`, `curl`, `ssh`, `gh`, `cargo install`, `npm install`, `python3 -c`,
`node -e` — all as in a normal shell. The command string is split on
sequence operators (quote- and escape-aware, so `find -exec … \;`, `2>&1`
and `echo 'a && b'` stay intact), each block runs through the shell verbatim,
`&&` / `||` semantics hold across blocks and `sudo` is resolved per block.

What still stops a command in this mode:

- the destructive wall and its dialog (below)
- the sudo dialog (below)
- `$(...)` and backticks — the destructive wall cannot see inside a
  substitution, so `echo $(rm -rf x)` would run `rm` with no dialog. Run the
  inner command as its own step.
- shell-script shape — `bash -c …`, bare `bash` (reads stdin, so
  `cat x | bash` too), relative script paths. These would dodge the
  per-file approval token.
- anything referencing the commander's own source directory
- malformed quoting

That is the right trade for Claude. It is the wrong trade for a model that
will do whatever it is told. For those:

### `strict` — hostile-model shell

Everything above, plus the full pre-filter stack, applied per block and per
pipeline stage before any shell exists:

- **Binary allowlist** (`WHITELIST` in `shell.py`): exact match on the
  binary after wrappers are unwrapped. ~200 binaries curated for an
  AI-orchestration / model-tuning workflow — filesystem, text, archives,
  system info, read-only network, git, make/cmake/ninja, gcc/clang,
  cargo/rustc, python/node, npm/yarn/pnpm, uv, dnf/rpm/pip, hardware
  diagnostics. `/tmp/evil/ls` is not `ls`.
- **Dangerous flags** (`DANGEROUS_FLAGS`): `python3 -c`, `node -e`,
  `find -delete/-exec`, package-manager install/remove/update, `cargo
  install/publish`, `npm install/exec`, `nvme format`, `smartctl -t`,
  `rocm-smi --set*`, `ethtool -s`, …
- **No redirects** (`>`, `>>`, `<`) — use `tee` or a script. Pipes are fine;
  every stage is vetted.
- **No shell metacharacters inside an argument**, no `..` path component.
- **Interpreter script-path gate**: `python3`, `node` and the shell runners
  will not execute a file from `/tmp`, `/var/tmp`, `/dev/shm` or
  `~/.commander_workspace`. This closes `lc_write_file` → run it.
- **SSH gate** (`ssh`, `scp`, `sftp`, `rsync`) and **network-exfil gate**
  (`nc`, `netcat`, `ncat`, `socat`, `curl`, `wget`) — blocked outright and
  also off the allowlist, so they hold even if you extend it.
- **`uv run <cmd>`** is unwrapped and `<cmd>` vetted as if typed bare;
  env-mutating `uv` subcommands and `--with` are blocked.
- `lc_start_process` takes one atomic command, no `&&` / `;`.
- The shell executes the shlex-rendered vetted tokens, not your raw string,
  so a glued `echo hi>/tmp/x` becomes a literal argument.

Extending the allowlist is editing `WHITELIST` / `DANGEROUS_FLAGS` at the
top of the pre-filter section in `shell.py`, then re-running the harness.
If you widen it for your local model, that is your call and your blast
radius; `SECURITY.md` says what counts as a bug in each mode.

### Recommended system prompt

```
This server has two safety gates: destructive-command confirmation and sudo
approval. Follow them exactly and never attempt to circumvent them. If the
user declines a dialog, the command is cancelled — do not retry it or look
for an alternative route.

If a command is rejected, read the stderr reason and change the approach;
do not retry the same string.

lc_confirm_destructive is ONLY for commands that destroy or modify data (any
rm, dd, mkfs, shred, wipefs) and for shell-script runs. Read-only sudo
commands like smartctl, lsblk, journalctl do NOT need it.

For long-running commands (rsync, large find, package installs, builds) use
lc_start_process and poll with lc_read_process_output, not lc_exec_command.

Always use absolute paths. Never use ~.
```

Add in strict mode:

```
This server enforces a strict binary allowlist. Pipes work; redirects, inline
code (python3 -c, node -e), $(...), backticks and .. are rejected. Use the
scratchpad pattern for multi-step data flow: run one command, read the output
via lc_search_scratchpad or lc_read_file, then run the next.
```

> **Malformed tool calls:** if your model emits
> `<parameter=params>{"command": ...}</parameter>` instead of MCP tool-call
> syntax, add `Tool calls use this exact format:
> <parameter=params>{"command": "your command"}</parameter>` to the system
> prompt. Model-specific; only add it if you see that error.

---

## The two gates

Both fire on `lc_exec_command` and `lc_start_process` alike. A gate that one
tool enforces and another ignores is not a gate.

### Gate 1 — Destructive wall + confirmation dialog

`command_is_destructive()` scans every segment of the command (split on
`|`, `||`, `&&`, `;`, `&`) and looks at the **binary position** of each —
never at arguments, so `ls /sbin/mkfs` and `man mkfs` are not flagged. It
fires on:

- `rm` — every form, single file or recursive
- `dd`, `shred`, `wipefs`, `blkdiscard`, `mkfs*`, `mkswap`
- partition editors (`fdisk`, `sfdisk`, `sgdisk`, `gdisk`, `cfdisk`,
  `parted`, …) unless called in a pure listing mode (`fdisk -l`)
- `nvme format` / `sanitize` / `delete-ns` / `write` / `write-zeroes` /
  `fw-commit` / `fw-download`
- redirects onto a block device (`> /dev/sda`)
- **every shell-script run**: `bash|sh|zsh|dash|ksh /absolute/path.sh`

Wrappers are unwrapped first, so `sudo rm`, `nice -n 5 mkfs.ext4`,
`timeout 30 dd`, `uv run bash x.sh` are all caught.

A flagged command is refused until the model calls `lc_confirm_destructive`
with the **exact** command string and a plain-English description of what
will be destroyed. You see an MCP elicitation form if the client supports
it, otherwise a zenity / kdialog dialog showing exactly what will be lost.
Approving issues a one-time token bound to that string, consumed on use:
approving `rm .git/index.lock` approves that one file, once. It never widens
to the folder or the session. Script runs are additionally bound to a
SHA-256 of the script's resolved path and content — edit the file after
approval and the token is void.

A declined command stays declined for the session. A dialog that cannot be
shown, or times out, is **not** a decline: the tool reports it loudly,
issues no token and caches nothing. Only a real click on Cancel is cached.
A fresh approval after a decline wins.

`~` is expanded before tokens are issued or checked, so a model cannot
escape a decline by switching between `~/foo` and `/home/user/foo`.

### Gate 2 — Sudo

1. Model calls `lc_exec_command` with a command containing `sudo`.
2. The server tokenises it (shell-aware; `echo "do not sudo"` does not trigger).
3. Read-only diagnostics (`smartctl`, `lsblk`, `dmesg`, `journalctl`, `lspci`,
   `ip`, `fsck`, package-manager query subcommands, `systemctl status` …)
   pass through via `sudo -n`. Everything else:

   | # | Method | What you see |
   |---|--------|--------------|
   | 1 | `elicit` | Your MCP client shows an in-app form, if it supports elicitation. |
   | 2 | `kdialog` / `zenity` | Native dialog showing the command, with a password field. On KDE Plasma kdialog is tried first (one dialog, and KWin can keep it on top); elsewhere zenity first. |
   | 3 | `pkexec` | Polkit handles its own prompt. `sudo X` → `pkexec X`; the server never sees a password. |
   | 4 | refused | Clear error returned to the model. |

4. Password is piped to `sudo -S -p ''` on stdin — never in argv, never on
   disk, never logged. After the command runs, `sudo -k` wipes sudo's own
   timestamp.
5. Decline / cancel: command refused, model told why.

Each `&&` / `;` block containing `sudo` gets its own approval.

**The dialog shows the command verbatim.** zenity parses its text as Pango
markup and kdialog as rich text by default, so any command containing `&`,
`<` or `>` — every `&&`, every `2>&1` — used to fail to render and the
dialog showed "Are you sure you want to proceed?" with **no command at all**.
That is the worst failure an approval gate can have. Both dialogs now run
with markup off / the text escaped, and dialog stderr is written to the tool
log instead of being swallowed.

Force a method with `LAMSYSTEMS_COMMANDER_SUDO_MODE`: `auto` (default),
`elicit`, `zenity`, `kdialog`, `pkexec`, or `off`. Dialog timeout:
`LAMSYSTEMS_COMMANDER_SUDO_DIALOG_TIMEOUT` seconds (default 90).

GUI fallbacks: `sudo dnf install zenity` or `kdialog`; `pkexec` comes with
polkit.

### Prompt fatigue

A long diagnostic session can mean ten or fifteen password dialogs in a
row. The supported answer is the session cache:

```json
"env": { "LAMSYSTEMS_COMMANDER_SUDO_CACHE": "session" }
```

A password entered once is held in server memory and reused for later
**non-destructive** sudo commands. Rules:

- Destructive commands never read or fill the cache — they always prompt
  fresh, after the `lc_confirm_destructive` token.
- The cache idles out after `LAMSYSTEMS_COMMANDER_SUDO_CACHE_TTL` seconds
  (default 900), sliding on each use, and is wiped when the server exits.
- Only the password methods use it; under `pkexec` polkit holds the
  credential.
- A cached password sudo rejects is dropped immediately and you are prompted.
- `sudo -k` still runs after every cached command.

Some people instead bind a hotkey that types the password and presses
Enter. If you do that, the only thing keeping the gate a gate is that you
read the dialog before you press it — the key fires the same whether the
command is `smartctl` or `dd`. Put it somewhere out of the way (a side
mouse button, a chorded combo), never on a key you hit by reflex, and know
that the password now lives in your macro tool's config, outside this
server's never-on-disk promise.

### File-tool guards

- `lc_write_file` / `lc_edit_block` / `lc_move_file` / `lc_create_directory`
  refuse system paths (`/etc`, `/usr`, `/bin`, `/boot`, `/sys`, `/proc`,
  `/dev`, `/run`, …) — use `sudo` via `lc_exec_command`, which puts a dialog
  in front of it.
- Every tool refuses to touch the commander's own source directory. The
  model cannot edit its own gates.

### Client-side approval prompts

MCP clients show their own "allow this tool call?" prompt based on the
`destructiveHint` each tool declares. Only two tools are flagged, so they
keep prompting even after "Always allow": `lc_confirm_destructive` (it *is*
the human-in-the-loop step) and `lc_kill_process` (signals cannot be taken
back). Everything else is declared non-destructive so "Always allow" sticks.
That is safe because the protection lives in the server, not the client
dialog: turning the client prompt off changes nothing about what the server
refuses. If you are driving a local model you want *more* prompting — flip
those hints to `True` in `server.py`.

---

## Scratchpad — large output handling

Output over ~8,000 chars is offloaded to `~/.commander_workspace/scratchpad/`
instead of returned inline. The model gets a file pointer and uses
`lc_search_scratchpad` (BM25 keyword search) or `lc_read_file` with
offset/limit, so `dmesg`, `find /`, build logs and package-manager output
don't flood its context.

## Tool call log

Every `lc_exec_command` call is logged to `~/.commander_workspace/tool_calls.log`
with timestamp, command, exit code and errors; dialog failures land there
too. The model can read it via `lc_get_tool_log` to see why a call failed.

---

## Validation: red-team findings

Tested under live adversarial conditions with an abliterated Qwen3-35B model
in strict mode. Findings and fixes:

| Finding | Status |
|---|---|
| `lc_start_process` bypassed the entire pre-filter | **Fixed:** `command_gate()` runs the full gate stack before any process launch |
| `lc_write_file` + `python3 script.py` deleted files without the destructive wall | **Fixed:** `_file_guard()` blocks system paths and server source; strict mode's script-path gate blocks execution from `/tmp`, `/var/tmp`, `/dev/shm`, `~/.commander_workspace` |
| `find -delete` / `find -exec` — mass deletion without the wall | **Fixed:** blocked in `DANGEROUS_FLAGS` (strict) |
| `~` vs absolute path escaped the session decline cache | **Fixed:** tilde expanded before token registration and check on both sides |
| Decline cache checked before confirmed token — re-confirmation silently ignored | **Fixed:** confirmed token checked first |
| Approval dialog showed no command for any string containing `&`, `<` or `>` | **Fixed:** zenity `--no-markup`, kdialog text escaped, dialog stderr logged |
| Model described its own bypass routes when asked | **Fixed:** each route above closed at the code level |
| Goal-preservation under refusal — immediately probed alternative routes | **Mitigated by architecture:** every route is independently blocked; model intent is not relied on |

---

## Known limitations and roadmap

- **Runs as your login user.** The definitive fix for any remaining
  application-layer gap is a dedicated low-privilege system user, so a
  successful bypass reaches that account's sandbox and not your home
  directory, SSH keys or desktop session. See below.
- **Tool schema size.** 25 tools at ~9,000 tokens of schema can make weaker
  models lose the tool-call format. Persistent `params requires property
  "params"` errors mean switch to a coder/instruct model with better
  structured-output compliance.
- **Long-running commands.** `lc_exec_command` blocks and accumulates
  output; use `lc_start_process` + `lc_read_process_output` for anything
  over a few seconds.
- **Script fingerprint covers the script file only**, not files it sources
  or calls.

### OS-level sandbox user (Fedora)

```bash
sudo useradd -r -m -s /sbin/nologin -d /var/lib/mcp-sandbox mcp-sandbox
sudo nano /etc/sudoers.d/mcp-commander-sandbox
```
```
your_username ALL=(mcp-sandbox) NOPASSWD: /path/to/Lamsystems-commander/.venv/bin/lamsystems-commander
```
```json
{
  "mcpServers": {
    "lamsystems-commander": {
      "command": "sudo",
      "args": ["-u", "mcp-sandbox", "/path/to/Lamsystems-commander/.venv/bin/lamsystems-commander"],
      "env": {}
    }
  }
}
```

End state: the kernel walls off your personal files and desktop session from
the agent entirely. Any application-level bypass hits `Permission Denied`.

---

## Files

```
Lamsystems-commander/
├── pyproject.toml
├── README.md · CHANGELOG.md · SECURITY.md · LICENSE
├── test_prefilter.py              # claude-mode harness; chains the strict one
├── test_prefilter_strict.py       # strict-mode harness
├── check_import.py                # import + tool registration smoke check
├── examples/mcp_config.json
└── src/lamsystems_commander/
    ├── __main__.py               # entry point
    ├── server.py                 # FastMCP tool registry, tool log, lc_confirm_destructive
    ├── shell.py                  # mode switch, pre-filter, WHITELIST / DANGEROUS_FLAGS, destructive wall, executor, scratchpad
    ├── prompt.py                 # elicit / zenity / kdialog / pkexec, sudo passthrough, session cache
    ├── files.py                  # read/write/edit/list/move/mkdir/stat + _file_guard()
    ├── processes.py              # ps, kill, managed sessions + command_gate()
    ├── search.py                 # find-by-name + grep/ripgrep
    └── git_tools.py              # git status/diff/log/branch
```

Runtime: `~/.commander_workspace/{scratchpad/, tool_calls.log}`, created
automatically.

## Verification

```bash
python3 -m py_compile src/lamsystems_commander/*.py
python3 check_import.py                                  # 25 tools loaded
LAMSYSTEMS_COMMANDER_MODE=strict python3 check_import.py # same 25
python3 test_prefilter.py                                # both modes
```

Expected: claude mode `75/75`, `7/7` split, `9/9` token; strict mode
`112/112`, `9/9` token. Run it after any change to the pre-filter, the
destructive wall, block splitting, `WHITELIST` or `DANGEROUS_FLAGS`. If a
test fails, do not deploy.

Interactive smoke test (needs `mcp[cli]`):
```bash
pip install "mcp[cli]"
mcp dev src/lamsystems_commander/__main__.py
```
