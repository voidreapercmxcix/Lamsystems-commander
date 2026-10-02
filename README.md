# Lamsystems-commander

A safety-first, self-hosted **MCP server** that gives an AI assistant shell,
file, search, process and git access to your machine — a Desktop
Commander-style tool surface inside a strict, layered safety architecture:
a stateless pre-filter pipeline, a hard-coded binary allowlist, wrapper-aware
vetting (`sudo`, `env`, `timeout`, `uv run` …), SSH and network-exfil blocks,
file-tool write guards, destructive-command confirmation, and a sudo gate.
None of these layers can be bypassed by model behaviour alone.

Works with Claude (Desktop, Cowork, Claude Code), LM Studio, and any other
MCP client. Local only: no account, no hosted relay, no per-call metering.
Written in Python with FastMCP. MIT licensed.

> Developed on Fedora. Tested on Python 3.10+. Linux-first; the sudo dialogs
> use GNOME/KDE tooling, everything else is portable.
>
> **Default posture is restrictive.** Out of the box the server runs in strict
> allowlist mode: only binaries on the WHITELIST will execute. Many commands
> that work in a normal shell — including `curl`, `wget`, `ssh`,
> `python3 -c …`, `dnf install` — are rejected by design. See
> [Strict allowlist mode](#strict-allowlist-mode) below if you need to extend
> the whitelist for your own setup.

---

## ⚠️ SECURITY WARNING

**Read this before you do anything else.**

This server gives a local LLM full shell access to your machine as your user.
If you use an abliterated or uncensored model, it **WILL** execute destructive
commands without hesitation if instructed to do so.

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
- Don't test "will it delete my drive" unless you are prepared for the answer 💩

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
| Shell policy | full shell; `blockedCommands` blocklist "for accidental execution" | **strict allowlist**; everything not listed is rejected before a shell exists |
| Wrapper handling | not documented | `sudo`, `env`, `nice`, `timeout`, `uv run` etc. are unwrapped and the real binary is vetted |
| Interpreter escape hatches | not documented | `python -c`, `node -e`, `find -exec`, package-manager installs blocked per binary |
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
description lists the current allowlist so the model doesn't have to guess.

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
`lc_exec_command` still runs every command through the pre-filter, the
allowlist, the network/SSH gate and the destructive hard wall, and
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
This server enforces a strict binary allowlist (the pre-filter pipeline).
Commands using binaries not on the WHITELIST will be rejected with a clear
stderr message. Read the rejection reason and try a different approach —
do not repeatedly retry the same blocked command.

There are multiple safety layers including destructive-command confirmation
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

## Safety architecture

Six independent layers protect against destructive or exfiltrating actions.
Every shell command passes through Layer 1 first; the others fire after, in
order, and any single layer is enough to block a command on its own.

### Layer 1 — Pre-filter pipeline (Python, stateless)

Every command entering `lc_exec_command` **and** `lc_start_process` is vetted
before anything else runs. The filter is a single stateless function — no
sessions, no caches, no timing windows — and it operates on the raw command
string before any shell or subprocess is created.

The pipeline runs six passes:

0. **Tilde expansion.** `~` is expanded to the real home directory path before
   any further processing. This ensures that `rm -rf ~/foo` and
   `rm -rf /home/user/foo` are always treated as the same command — preventing
   a model from using path format switching to escape the session decline cache.
1. **Raw-string scan.** Hard-rejects any input containing `$(` or backticks.
   Subshells and command substitution would let the model construct a payload
   that the structural tokeniser cannot see, so they are killed at the source.
2. **Tokenisation.** The command is parsed with Python's `shlex` lexer (POSIX
   mode). Malformed quoting raises a clean `ValueError` and rejects the
   command. No regex, no hand-rolled parser.
3. **Hard-banned operators.** Pipes (`|`), redirects (`>`, `>>`, `<`) anywhere
   in the token list reject the entire command. The scratchpad replaces pipes
   for inter-command data flow; redirects bypass the audit trail.
4. **Sequence splitting.** `&&`, `||`, and `;` split the command into atomic
   blocks. Each block is vetted independently. Any block failing rejects the
   whole compound — never partial admit.
5. **Per-block vetting:**
   - **Strict allowlist.** The block's binary must be on the WHITELIST. Exact
     match on the binary name. See [Strict allowlist mode](#strict-allowlist-mode)
     for the full list and how to extend it.
   - **Injection-character scan.** Arguments containing `; & | $ ( ) \``
     are rejected. (Redirect characters are already caught upstream.)
   - **Path traversal.** Component-level check — `..` appearing as a standalone
     path component (`ls ..`, `cat foo/..`, `cat ../../etc/passwd`) is rejected.
   - **Per-binary dangerous flags.** A dictionary blocks the most dangerous
     flags per binary. Key entries:
     - `-c` / `-e` for interpreters — blocks inline code execution
     - `-delete`, `-exec`, `-execdir` for `find` — blocks mass deletion and
       arbitrary command execution via find
     - Write subcommands for package managers (`dnf install`, `pip install`, etc.)
   - **Interpreter script-path gate.** When the binary is a known interpreter
     (`python`, `python3`, `node`), any argument that looks like a file path is
     checked against a list of restricted directories (`/tmp`, `/var/tmp`,
     `/dev/shm`, `~/.commander_workspace`). Scripts dropped into writable or
     temporary directories cannot be executed. Scripts in project directories
     are unaffected.

Reject reasons surface in `stderr` so the model knows exactly why a command
was refused.

### Layer 1b — Process launch gate (`command_gate`, Python)

`lc_start_process` runs every command through the same full gate stack as
`lc_exec_command` — pre-filter pipeline, SSH gate, network exfil gate, and
file integrity check — before any subprocess is created. Compound commands
(`&&`, `||`, `;`) are additionally rejected in process sessions: one atomic
command per session only.

Subprocess creation uses `create_subprocess_exec` with the vetted token list
directly, not `create_subprocess_shell`. There is no shell expansion at launch
time — the model cannot inject shell metacharacters via the process path.

### Layer 2 — File integrity and write protection (Python)

Two independent checks applied to every write operation:

**Shell-level (lc_exec_command):** Any command referencing the server's own
source directory is blocked before execution. A model cannot use shell commands
to overwrite its own safety constraints or blocklists.

**File-tool-level (lc_write_file, lc_edit_block, lc_move_file):** A
`_file_guard()` check runs before every mutating file operation and blocks:

- Writes to the server source directory — same protection as the shell-level check
- Writes to system paths: `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`,
  `/boot`, `/sys`, `/proc`, `/dev`, `/run`

This closes the `lc_write_file` → script execution gap where a model could
write a Python script to a temp directory and execute it via `python3 script.py`
to work around the shell-level protections. System paths and server source are
now protected at the file tool level regardless of which tool is used.

The interpreter script-path gate in Layer 1 adds a second line of defence: even
if a script is written to `/tmp` via some other route, executing it via
`python3 /tmp/script.py` is blocked at the pre-filter before any subprocess is
created.

> **Remaining gap:** the dedicated low-privilege user (see roadmap) is the
> complete architectural fix. Until then, writes to user home subdirectories
> outside the restricted list are not blocked at the file tool level.

### Layer 3 — SSH and network exfil gate (Python)

Two unconditional blocks enforced before any command runs:

- **SSH gate:** `ssh`, `scp`, `sftp`, and `rsync` are blocked. Models cannot
  open outbound tunnels, copy files to remote hosts, or use rsync over SSH.
  These are C2 and exfil vectors regardless of stated intent.

- **Network exfil gate:** `nc`, `netcat`, `ncat`, `socat`, `curl`, and `wget`
  are blocked. Raw TCP/UDP relay and HTTP data transfer tools are disabled at
  the architectural level.

In practice these binaries are also off the WHITELIST, so they fail at Layer 1
first. The dedicated gates remain in place as defence-in-depth — if the
allowlist is ever extended, the SSH and exfil blocks still hold.

Both gates also apply to `lc_start_process` via `command_gate`.

### Layer 4 — Destructive command hard wall (Python)

`lc_exec_command` tokenises every command and scans **the entire pipeline**
before execution — not just the first binary. All segments of a chained
command are checked.

Commands matching destructive patterns (any `rm`, `dd`, `mkfs`, `shred`,
`wipefs`, writes to block devices) are blocked regardless of sudo. A safe
binary earlier in the pipeline (e.g. `cat`, `ls`, `echo`) does not protect
destructive operations in later segments. The model must call
`lc_confirm_destructive` first.

### Layer 5 — Destructive confirmation dialog (`lc_confirm_destructive`)

Before any destructive command can run, the model must call `lc_confirm_destructive`
with the exact command and a plain-English description of what will be destroyed.
This fires an in-app elicitation dialog (or a zenity / kdialog fallback) showing
exactly what will be permanently lost. A one-time token is issued only on
explicit approval.

**A dialog that cannot be shown is not a decline.** MCP clients launch the
server with a clean environment (no `DISPLAY`, `WAYLAND_DISPLAY` or
`XDG_RUNTIME_DIR`), so the server discovers the session's display from
`/run/user/<uid>/wayland-*` and `/tmp/.X11-unix` itself. If no dialog can be
shown at all, or it times out, the tool reports that loudly, issues no token,
and records nothing — only a real click on Cancel goes into the session decline
cache. Claude Desktop / Cowork do not currently support elicitation, so on
those clients the GUI fallback is the path that runs.

**Token normalisation:** Both `lc_confirm_destructive` and the exec path expand
`~` to the real home directory before registering or checking tokens. A model
cannot escape a decline by switching between `~/foo` and `/home/user/foo` —
they normalise to the same string and share the same token and decline record.

**Confirmed token takes priority over decline cache.** If a command was
previously declined and then explicitly re-confirmed, the fresh confirmation
wins. Decline is not permanent if the user actively re-approves — but the model
cannot silently retry without triggering a new dialog.

**Declined = permanently blocked until re-confirmed.** A session-scoped decline
cache prevents the model from re-prompting the user for the same command string
without going back through the confirmation dialog. The model is explicitly told
not to retry or find alternatives.

### Layer 6 — Sudo gate

All `sudo` commands (including confirmed destructive ones) require a fresh
password approval via MCP elicitation, zenity, kdialog, or pkexec. By default
nothing is cached: every sudo call prompts, and `sudo -k` wipes sudo's own
timestamp after each one.

**Optional session cache (off by default).** Set
`LAMSYSTEMS_COMMANDER_SUDO_CACHE=session` in the server's `env` block and a
password entered once is held in server memory and reused for later
**non-destructive** sudo commands, so a read-only scan (`smartctl`, `dmesg`,
`journalctl` …) prompts once instead of every call. Rules:

- Destructive commands never read or fill the cache — they always prompt fresh,
  after the `lc_confirm_destructive` token.
- The cache idles out after `LAMSYSTEMS_COMMANDER_SUDO_CACHE_TTL` seconds
  (default 900), sliding on each use, and is wiped when the server exits.
- It only applies to the password methods (elicit, zenity, kdialog). Under
  pkexec polkit holds the credential and the server never sees a password.
- A cached password sudo rejects is dropped immediately and you are prompted.
- `sudo -k` still runs after every cached command, so sudo's own timestamp is
  never left primed by this server.

The env var must be in the MCP client's config — MCP servers are launched
with a clean environment, so exporting it in your shell does nothing.

Safe sudo commands (`smartctl`, `fdisk`, `dnf`, etc.) bypass the dialog and run
via `sudo -n` using cached credentials — no repeated password prompts for routine
diagnostics.

Because the pre-filter splits compound commands into atomic blocks (Layer 1)
and execution iterates them one at a time, each block requiring sudo gets its
own fresh approval.

---

## Strict allowlist mode

The pre-filter (Layer 1) holds a hard-coded `WHITELIST` of permitted binaries.
Anything not on the list is rejected before reaching the shell. The default
list is curated for an AI-orchestration and model-tuning workflow.

**On the list (summarised; the exact set is generated into the `lc_exec_command` tool description):**

- **Filesystem read:** `ls`, `cat`, `head`, `tail`, `find`, `stat`, `file`,
  `wc`, `grep`, `tree`, `realpath`, `readlink`, `basename`, `dirname`, `pwd`
- **File create / move / link / delete:** `cp`, `mv`, `mkdir`, `touch`, `ln`, `rm`
  — every `rm`, including plain `rm file.txt`, hits the destructive wall
- **Permissions:** `chmod`, `chown`, `chgrp`
- **Text processing:** `sed`, `awk`, `cut`, `sort`, `uniq`, `tr`, `diff`,
  `patch`, `tee`, `cmp`, `comm`, `rev`, `tac`, `paste`, `column`, `nl`
- **Encoding / hashing:** `base64`, `sha256sum`, `sha1sum`, `md5sum`,
  `sha512sum`, `xxd`
- **Archives:** `tar`, `gzip`, `gunzip`, `zip`, `unzip`, `xz`, `unxz`,
  `bzip2`, `bunzip2`, `zstd`
- **System info:** `ps`, `uname`, `hostname`, `whoami`, `id`, `groups`,
  `uptime`, `free`, `df`, `du`, `lsblk`, `lspci`, `lsusb`, `lscpu`, `lsof`,
  `lsmod`, `dmesg`, `vmstat`, `iostat`
- **Network read-only:** `ip`, `ss`, `ping`, `host`, `dig`, `nslookup`,
  `tracepath`, `traceroute`, `mtr`, `arp`
- **Process control:** `kill`, `killall`, `pkill`, `pgrep`, `nice`, `renice`,
  `nohup`, `time`, `timeout`, `watch`
- **Package info (write subcommands blocked):** `dnf`, `rpm`, `pip`, `pip3`, `uv`
- **Project tooling via `uv run`:** `pytest`, `rail`
- **Dev tools:** `git`, `make`, `cmake`, `gcc`, `g++`, `clang`, `clang++`,
  `ld`, `ar`, `nm`, `objdump`, `ldd`, `pkg-config`
- **Language runtimes (`-c` / `-e` blocked):** `python`, `python3`, `node`
- **JS package managers (install / exec blocked):** `npm`, `yarn`, `pnpm`
- **Misc:** `which`, `whereis`, `type`, `echo`, `printf`, `date`, `sleep`,
  `env`, `true`, `false`, `yes`, `seq`, `man`, `less`, `more`

**Deliberately excluded:**

| Binary | Why excluded |
|---|---|
| `dd`, `mkfs.*`, `shred`, `wipefs` | Destructive — irreversible data loss |
| `ssh`, `scp`, `sftp`, `rsync` | Layer 3 SSH gate — exfil / C2 vectors |
| `nc`, `netcat`, `ncat`, `socat`, `curl`, `wget` | Layer 3 network exfil gate |
| `bash`, `sh`, `perl`, `ruby` | Their `-c` / `-e` flags would bypass the whitelist entirely |

`DANGEROUS_FLAGS` entries for `bash`, `sh`, `perl`, and `ruby` exist as
defence-in-depth — if those binaries are ever added to WHITELIST in future,
the `-c` / `-e` block is already in place.

**`find` is on the WHITELIST but gated:** `-delete`, `-exec`, and `-execdir`
are blocked via `DANGEROUS_FLAGS`. Normal use (`find /path -name '*.log'`) works;
mass deletion and arbitrary command execution via find do not.

**`uv` is on the WHITELIST but `uv run` is treated as a wrapper.** `uv run
[flags] <cmd>` is unwrapped and `<cmd>` is vetted exactly as if typed bare —
so `uv run pytest -q` passes, while `uv run bash -c …`, `uv run curl …` and
`uv run python -c …` are rejected the same way the bare forms are, and
`uv run rm -rf …` hits the destructive wall. `uv run -m mod` is vetted as
`python3 -m mod`. Environment-mutating subcommands (`add`, `remove`, `sync`,
`pip install`, `tool …`, `self …`, `cache clean`) and code-injecting run flags
(`--with`, `--with-requirements`, `--with-editable`, `--script`) are blocked.
Note that `uv run` will still auto-sync the project environment on first use
if the lockfile and `.venv` disagree; run `uv sync` yourself if you want that
to be a deliberate step.

### Extending the allowlist

If you trust your own setup and want to add binaries (or remove some), edit
`WHITELIST` and `DANGEROUS_FLAGS` at the top of the pre-filter section in
`src/lamsystems_commander/shell.py`. After editing, re-run the verification
step in the [Verification](#verification) section and the test harness at
`test_prefilter.py` to confirm nothing regressed.

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
    ├── shell.py                  # pre-filter pipeline + WHITELIST + DANGEROUS_FLAGS + sudo gate + destructive wall + scratchpad
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

Run the pre-filter test harness after any change to `WHITELIST`, `DANGEROUS_FLAGS`,
or the pre-filter pipeline itself:

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
