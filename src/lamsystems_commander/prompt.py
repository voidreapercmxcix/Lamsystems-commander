"""Password-prompt strategies for the sudo gate.

Resolution order (auto mode):
    1. MCP elicitation — preferred; client (e.g. LM Studio, Claude Desktop) shows an in-app form
    2. zenity         — GNOME-style native password dialog
    3. kdialog        — KDE-style native password dialog
    4. pkexec         — polkit-handled root elevation (no password through us)
    5. refused        — clear error to the LLM

Override with the env var LAMSYSTEMS_COMMANDER_SUDO_MODE:
    auto | elicit | zenity | kdialog | pkexec | off

`off` disables the sudo path entirely — all sudo commands are refused.

Why these in particular:
    - elicit:  no GUI dependency, no DISPLAY needed, password stays inside the MCP channel
    - zenity:  ships with GNOME, very common on Fedora Workstation
    - kdialog: same idea for KDE Plasma
    - pkexec:  polkit handles its own prompt; we never see the password.
               The command is *re-routed*: `sudo X` becomes `pkexec X`, run as root
               via the polkit agent. This is a strong, well-audited path on Fedora.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import signal
import time
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Sudo passthrough — these binaries skip the approval dialog entirely
# ---------------------------------------------------------------------------
# Read-only diagnostic and package management commands that should never
# require manual approval. They run via `sudo -n` (non-interactive).
# If no cached credentials exist they will fail with a clear error rather
# than hanging waiting for input.
_SUDO_PASSTHROUGH = {
    # Disk diagnostics
    "smartctl", "hdparm", "nvme", "blkid", "lsblk", "fdisk",
    "parted", "lshw", "dmidecode",
    # Hardware info
    "lspci", "lsusb", "sensors", "ipmitool",
    # System info / logs
    "dmesg", "journalctl",
    # Network diagnostics
    "ip", "ss", "netstat", "ethtool",
    # Filesystem / mount (read-only ops)
    "mount", "umount", "fsck",
}

# Package managers: only read-only subcommands are safe to passthrough.
# install/remove/update/upgrade must go through the approval gate.
_PKG_PASSTHROUGH_SUBCOMMANDS: dict[str, set[str]] = {
    "dnf":     {"info", "list", "search", "check-update", "history",
                "repolist", "provides", "deplist", "repoquery"},
    "apt":     {"show", "list", "search", "depends", "rdepends", "policy"},
    "apt-get": {"indextargets"},
    "yum":     {"info", "list", "search", "check-update", "history",
                "repolist", "provides", "deplist"},
    "zypper":  {"info", "list", "search", "repos", "what-provides"},
    "pacman":  {"-Q", "-Qi", "-Ql", "-Qs", "-Si", "-Ss", "-Sl"},
}

# systemctl: only read/query subcommands are safe to passthrough.
# start/stop/enable/disable/mask must go through the approval gate.
_SYSTEMCTL_PASSTHROUGH_SUBCOMMANDS = {
    "status", "list-units", "list-unit-files", "list-timers",
    "list-sockets", "list-jobs", "is-active", "is-enabled",
    "is-failed", "is-system-running", "cat", "show",
    "get-default", "list-dependencies",
}


def _is_passthrough_command(command: str) -> bool:
    """Return True if this sudo command should auto-approve via sudo -n.

    Handles both the flat _SUDO_PASSTHROUGH set and subcommand-aware checks
    for package managers and systemctl.
    """
    binary = _first_binary_after_sudo(command)
    if binary is None:
        return False

    # Flat passthrough set — always safe regardless of subcommand.
    if binary in _SUDO_PASSTHROUGH:
        return True

    # Subcommand-aware: package managers.
    if binary in _PKG_PASSTHROUGH_SUBCOMMANDS:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        skip = {"sudo", "env", "nice", "ionice", "nohup", "time"}
        real_tokens = [t for t in tokens if t not in skip and not t.startswith("-")]
        # real_tokens[0] is the binary; real_tokens[1] would be the subcommand
        if len(real_tokens) >= 2:
            return real_tokens[1] in _PKG_PASSTHROUGH_SUBCOMMANDS[binary]
        return False  # bare `sudo dnf` with no subcommand — send to gate

    # Subcommand-aware: systemctl.
    if binary == "systemctl":
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        skip = {"sudo", "env", "nice", "ionice", "nohup", "time"}
        real_tokens = [t for t in tokens if t not in skip and not t.startswith("-")]
        if len(real_tokens) >= 2:
            return real_tokens[1] in _SYSTEMCTL_PASSTHROUGH_SUBCOMMANDS
        return False

    return False


def _first_binary_after_sudo(command: str) -> Optional[str]:
    """Return the first real binary name after stripping sudo/env prefixes."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    skip = {"sudo", "env", "nice", "ionice", "nohup", "time"}
    for tok in tokens:
        if tok in skip or tok.startswith("-"):
            continue
        return tok.split("/")[-1]
    return None

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class SudoApprovalResult:
    """How the sudo gate decided to handle this command.

    Exactly one of:
        - auto_approved is True   → run `sudo -n` (no dialog, uses cached creds)
        - password is set         → run `sudo -S -p ''` and feed password on stdin
        - use_pkexec is True      → rewrite `sudo` → `pkexec`, no password handled here
        - declined is True        → refuse, with `reason` explaining why
    """
    password: Optional[str] = None
    use_pkexec: bool = False
    auto_approved: bool = False
    declined: bool = False
    reason: str = ""
    method: str = ""  # "passthrough" | "elicit" | "zenity" | "kdialog" | "pkexec" | "off" | "none"


# ---------------------------------------------------------------------------
# Elicitation schema
# ---------------------------------------------------------------------------


class _Password(BaseModel):
    password: str = Field(
        ...,
        description="Your sudo password. Used once for this command and then dropped.",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------


# How long to wait for an elicitation reply before giving up and trying the
# GUI/polkit fallbacks. A client that advertises no elicitation handler (e.g.
# the LamSystems Qt client, capabilities={"tools":{}}) simply never answers, so
# without this bound `auto` mode hangs the whole tool timeout instead of falling
# through to kdialog/pkexec.
_ELICIT_TIMEOUT_S: float = 8.0

# ---------------------------------------------------------------------------
# GUI environment discovery
# ---------------------------------------------------------------------------
# MCP clients (Claude Desktop / Cowork, LM Studio) launch servers with a clean
# environment: no DISPLAY, no WAYLAND_DISPLAY, no XDG_RUNTIME_DIR. Without
# these, zenity/kdialog exit non-zero in 0 seconds with "cannot open display",
# which used to be recorded as a *user decline*. Probe the usual sockets and
# hand every dialog an env that can actually reach the session.
def gui_env() -> Optional[dict]:
    """Environment for launching a GUI dialog, or None if no display is
    reachable. Starts from os.environ and fills in DISPLAY / WAYLAND_DISPLAY /
    XDG_RUNTIME_DIR from the standard socket locations when missing."""
    env = dict(os.environ)
    uid = os.getuid()
    runtime = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if os.path.isdir(runtime):
        env.setdefault("XDG_RUNTIME_DIR", runtime)

    if not env.get("WAYLAND_DISPLAY"):
        try:
            socks = sorted(
                n for n in os.listdir(runtime)
                if n.startswith("wayland-") and not n.endswith(".lock")
            )
        except OSError:
            socks = []
        if socks:
            env["WAYLAND_DISPLAY"] = socks[0]

    if not env.get("DISPLAY"):
        try:
            xs = sorted(
                n for n in os.listdir("/tmp/.X11-unix") if n.startswith("X")
            )
        except OSError:
            xs = []
        if xs:
            env["DISPLAY"] = ":" + xs[0][1:]

    if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
        return env
    return None


def gui_available(binary_name: str) -> bool:
    return shutil.which(binary_name) is not None and gui_env() is not None


# How long a native GUI password / confirm dialog may stay open before we give
# up, CLOSE it, and report "no password entered". Must stay comfortably under
# the MCP client's tools/call ceiling (LamSystems kills the call at 120s) so the
# dialog closes and the command still has time to run before the client abandons
# the request. Generous by default so a human has time to type; override with
# LAMSYSTEMS_COMMANDER_SUDO_DIALOG_TIMEOUT (seconds).
try:
    _SUDO_DIALOG_TIMEOUT_S: float = float(
        os.environ.get("LAMSYSTEMS_COMMANDER_SUDO_DIALOG_TIMEOUT", "90")
    )
except ValueError:
    _SUDO_DIALOG_TIMEOUT_S = 90.0


async def _try_elicit(ctx, command: str,
                      timeout: float = _ELICIT_TIMEOUT_S) -> Optional[SudoApprovalResult]:
    """Ask via MCP elicitation. Returns None if the client doesn't support it,
    raises nothing, or doesn't answer within `timeout` — in every one of those
    cases the caller falls through to the next strategy."""
    if ctx is None:
        return None
    # Only attempt elicitation if the client advertised support for it. A capable
    # client (e.g. LM Studio, Claude Desktop) gets the in-app form with NO timeout - the user may
    # take a while to type. A client that never advertised it (the LamSystems Qt
    # client sends capabilities={"tools":{}}) is skipped IMMEDIATELY, so we fall
    # through to a native dialog with no wait. If the capability can't be read,
    # fall back to a bounded attempt so an unresponsive client can't hang the gate.
    supports_elicit = None
    try:
        _caps = ctx.session.client_params.capabilities
        supports_elicit = getattr(_caps, "elicitation", None) is not None
    except Exception:
        supports_elicit = None
    if supports_elicit is False:
        return None
    try:
        await ctx.info(f"Requesting sudo approval (elicit) for: {command}")
        _elicit = ctx.elicit(
            message=(
                "Sudo approval required.\n\n"
                f"Command:\n  {command}\n\n"
                "Type your password to authorize THIS COMMAND ONLY. "
                "Not cached."
            ),
            schema=_Password,
        )
        if supports_elicit:
            result = await _elicit
        else:
            result = await asyncio.wait_for(_elicit, timeout=timeout)
    except Exception as e:
        # Client doesn't support elicitation, or the SDK raised — fall through.
        try:
            await ctx.warning(f"Elicitation unavailable ({type(e).__name__}); trying GUI fallback")
        except Exception:
            pass
        return None

    if result.action == "accept" and result.data is not None:
        return SudoApprovalResult(password=result.data.password, method="elicit")
    return SudoApprovalResult(
        declined=True,
        reason=f"Elicitation {result.action} by user",
        method="elicit",
    )


async def _dialog_communicate(proc, *, timeout: float):
    """Await proc.communicate() but never longer than `timeout`. On timeout the
    dialog's whole process group is killed -- which CLOSES the window -- and
    (None, None) is returned, so an unanswered dialog can never wedge the serial
    MCP stdio pipe the way an unbounded communicate() would. Relies on the proc
    being started with start_new_session=True so it owns its process group."""
    try:
        return await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError):
            pass
        return None, None


async def _try_gui_dialog(
    binary_name: str,
    argv: list[str],
    *,
    method_label: str,
) -> Optional[SudoApprovalResult]:
    """Common runner for zenity/kdialog. Returns None if the binary is missing
    or no DISPLAY/WAYLAND_DISPLAY is available."""
    if shutil.which(binary_name) is None:
        return None
    env = gui_env()
    if env is None:
        # No graphical session reachable from this process — dialog would just hang.
        return None

    proc = await asyncio.create_subprocess_exec(
        binary_name, *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    stdout, _ = await _dialog_communicate(proc, timeout=_SUDO_DIALOG_TIMEOUT_S)
    if stdout is None:
        # Dialog closed on timeout with no response -- report cleanly instead
        # of blocking the server forever on an unanswered prompt.
        return SudoApprovalResult(
            declined=True,
            reason=(
                f"{method_label} dialog timed out after "
                f"{_SUDO_DIALOG_TIMEOUT_S:.0f}s with no password entered"
            ),
            method=method_label,
        )

    if proc.returncode != 0:
        # User clicked cancel, or the dialog errored.
        return SudoApprovalResult(
            declined=True,
            reason=f"{method_label} dialog cancelled or failed (exit {proc.returncode})",
            method=method_label,
        )

    password = stdout.decode(errors="replace").rstrip("\n")
    if not password:
        return SudoApprovalResult(
            declined=True,
            reason=f"{method_label} returned empty password",
            method=method_label,
        )
    return SudoApprovalResult(password=password, method=method_label)


async def _try_zenity(command: str) -> Optional[SudoApprovalResult]:
    title = "lamsystems-commander — sudo approval"
    # zenity --password ignores --text, so pre-screen with a confirm dialog so the
    # user can SEE the command before typing their password.
    confirm = await _try_zenity_confirm(command, title)
    if confirm is False:
        return SudoApprovalResult(declined=True, reason="User declined the command preview", method="zenity")
    return await _try_gui_dialog(
        "zenity",
        ["--password", f"--title={title}"],
        method_label="zenity",
    )


async def _try_zenity_confirm(command: str, title: str) -> Optional[bool]:
    if shutil.which("zenity") is None:
        return None
    env = gui_env()
    if env is None:
        return None
    proc = await asyncio.create_subprocess_exec(
        "zenity", "--question",
        f"--title={title}",
        f"--text=Authorize this sudo command?\n\n{command}",
        "--ok-label=Approve", "--cancel-label=Decline",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    out, _ = await _dialog_communicate(proc, timeout=_SUDO_DIALOG_TIMEOUT_S)
    if out is None:
        return False  # timed out with no answer -- treat as a decline
    return proc.returncode == 0


async def _try_kdialog(command: str) -> Optional[SudoApprovalResult]:
    return await _try_gui_dialog(
        "kdialog",
        ["--password", f"Authorize this sudo command?\n\n{command}",
         "--title", "lamsystems-commander — sudo approval"],
        method_label="kdialog",
    )


def _can_use_pkexec() -> bool:
    return shutil.which("pkexec") is not None


# ---------------------------------------------------------------------------
# Main entry point — the resolution chain
# ---------------------------------------------------------------------------


async def request_sudo_approval(ctx, command: str, *, allow_passthrough: bool = True) -> SudoApprovalResult:
    """Resolve a sudo approval using the configured mode.

    Honors LAMSYSTEMS_COMMANDER_SUDO_MODE for explicit overrides. Defaults to auto.
    """
    # Passthrough: known safe diagnostic commands and read-only package/service
    # queries skip the dialog entirely. Write operations (dnf install, systemctl
    # start, etc.) are NOT passthrough — they go through the approval gate.
    if allow_passthrough and _is_passthrough_command(command):
        return SudoApprovalResult(auto_approved=True, method="passthrough")

    mode = os.environ.get("LAMSYSTEMS_COMMANDER_SUDO_MODE", "auto").strip().lower()

    if mode == "off":
        return SudoApprovalResult(
            declined=True,
            reason="Sudo is disabled (LAMSYSTEMS_COMMANDER_SUDO_MODE=off).",
            method="off",
        )

    if mode == "elicit":
        r = await _try_elicit(ctx, command)
        if r is None:
            return SudoApprovalResult(
                declined=True,
                reason="Forced elicit mode but client did not support elicitation.",
                method="elicit",
            )
        return r

    if mode == "zenity":
        r = await _try_zenity(command)
        return r or SudoApprovalResult(
            declined=True, reason="zenity unavailable (not installed or no DISPLAY)", method="zenity",
        )

    if mode == "kdialog":
        r = await _try_kdialog(command)
        return r or SudoApprovalResult(
            declined=True, reason="kdialog unavailable (not installed or no DISPLAY)", method="kdialog",
        )

    if mode == "pkexec":
        if not _can_use_pkexec():
            return SudoApprovalResult(
                declined=True, reason="pkexec not installed.", method="pkexec",
            )
        return SudoApprovalResult(use_pkexec=True, method="pkexec")

    # auto: walk the chain.
    r = await _try_elicit(ctx, command)
    if r is not None and not r.declined:
        return r
    if r is not None and r.declined and r.method == "elicit":
        # User actively declined the elicitation — don't fall through, respect that.
        return r

    r = await _try_zenity(command)
    if r is not None and not r.declined:
        return r
    if r is not None and r.declined:
        return r  # user clicked cancel — respect it

    r = await _try_kdialog(command)
    if r is not None and not r.declined:
        return r
    if r is not None and r.declined:
        return r

    if _can_use_pkexec():
        return SudoApprovalResult(use_pkexec=True, method="pkexec")

    return SudoApprovalResult(
        declined=True,
        reason=(
            "No sudo-approval method available. Install one of: zenity, kdialog, "
            "or polkit (pkexec). Or use an MCP client that supports elicitation."
        ),
        method="none",
    )


# ---------------------------------------------------------------------------
# Session sudo-password cache (non-destructive commands only)
# ---------------------------------------------------------------------------
# Opt-in via LAMSYSTEMS_COMMANDER_SUDO_CACHE=session (default off). When on, a
# password entered once through a password method (elicit/zenity/kdialog) is held in
# process memory and reused for subsequent NON-destructive sudo commands within
# an idle TTL, so a read-only scan prompts once instead of on every call.
#
# HARD boundary: destructive commands NEVER use or fill this cache - the caller
# (shell._execute_atomic_block) only consults it when is_destructive is False.
# The cache lives only in RAM, is wiped when the process exits, and slides its
# expiry on each use. It does nothing under pkexec mode (polkit keeps the
# password itself, so the server never sees one to cache) - password methods only.
_SUDO_CACHE: dict = {"password": None, "expires": 0.0}


def sudo_cache_enabled() -> bool:
    return os.environ.get("LAMSYSTEMS_COMMANDER_SUDO_CACHE", "off").strip().lower() in (
        "session", "1", "on", "true", "yes",
    )


def _sudo_cache_ttl() -> float:
    try:
        return float(os.environ.get("LAMSYSTEMS_COMMANDER_SUDO_CACHE_TTL", "900"))
    except (TypeError, ValueError):
        return 900.0


def sudo_cache_get() -> Optional[str]:
    """The cached password if caching is on and it hasn't idled out, else None.
    Reading it slides the idle timer forward."""
    if not sudo_cache_enabled() or _SUDO_CACHE["password"] is None:
        return None
    if time.monotonic() > _SUDO_CACHE["expires"]:
        sudo_cache_clear()
        return None
    _SUDO_CACHE["expires"] = time.monotonic() + _sudo_cache_ttl()
    return _SUDO_CACHE["password"]


def sudo_cache_put(password: str) -> None:
    """Store a password for reuse on non-destructive commands. No-op when
    caching is off or the password is empty."""
    if not sudo_cache_enabled() or not password:
        return
    _SUDO_CACHE["password"] = password
    _SUDO_CACHE["expires"] = time.monotonic() + _sudo_cache_ttl()


def sudo_cache_clear() -> None:
    _SUDO_CACHE["password"] = None
    _SUDO_CACHE["expires"] = 0.0


# ---------------------------------------------------------------------------
# Destructive-confirmation dialog (used by server.lc_confirm_destructive)
# ---------------------------------------------------------------------------
@dataclass
class ConfirmDialogResult:
    """Outcome of a yes/no GUI confirmation.

    outcome is one of:
      "granted"     — user clicked the confirm button
      "declined"    — user clicked cancel / closed the dialog (a real human "no")
      "timeout"     — dialog stayed open past the limit with no answer
      "unavailable" — dialog could not be shown (no binary, no display, crash)
    Only "declined" may be written to the session decline cache."""
    outcome: str
    method: str
    detail: str = ""


_DISPLAY_ERROR_MARKERS = (
    "cannot open display", "could not connect", "unable to init",
    "no protocol specified", "failed to connect", "could not open display",
    "display not found", "qxcbconnection", "could not initialize",
)


async def _run_confirm_dialog(binary: str, argv: list[str], *, method: str) -> ConfirmDialogResult:
    if shutil.which(binary) is None:
        return ConfirmDialogResult("unavailable", method, f"{binary} not installed")
    env = gui_env()
    if env is None:
        return ConfirmDialogResult("unavailable", method, "no DISPLAY / WAYLAND_DISPLAY reachable")
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
    except Exception as e:  # pragma: no cover - exec failure
        return ConfirmDialogResult("unavailable", method, f"launch failed: {type(e).__name__}: {e}")
    out, err = await _dialog_communicate(proc, timeout=_SUDO_DIALOG_TIMEOUT_S)
    if out is None:
        return ConfirmDialogResult("timeout", method, f"no answer after {_SUDO_DIALOG_TIMEOUT_S:.0f}s")
    stderr = (err or b"").decode(errors="replace").strip()
    low = stderr.lower()
    if proc.returncode == 0:
        return ConfirmDialogResult("granted", method, "")
    if any(m in low for m in _DISPLAY_ERROR_MARKERS):
        return ConfirmDialogResult("unavailable", method, f"exit {proc.returncode}: {stderr[:200]}")
    # zenity: 1 = cancel/close, 5 = --timeout expired. kdialog: 1 = no/cancel.
    if proc.returncode == 1:
        return ConfirmDialogResult("declined", method, stderr[:200])
    if proc.returncode == 5:
        return ConfirmDialogResult("timeout", method, "dialog --timeout expired")
    return ConfirmDialogResult("unavailable", method, f"exit {proc.returncode}: {stderr[:200]}")


async def confirm_destructive_gui(message: str) -> ConfirmDialogResult:
    """Try zenity, then kdialog. Returns the first result that is not
    "unavailable"; if both are unavailable, returns the last one so the caller
    can log why."""
    last = ConfirmDialogResult("unavailable", "none", "no GUI dialog tool found")
    r = await _run_confirm_dialog(
        "zenity",
        [
            "--question",
            "--title=⚠️ DESTRUCTIVE OPERATION",
            f"--text={message}\n\nProceed?",
            "--ok-label=CONFIRM — DESTROY",
            "--cancel-label=Cancel",
            "--width=500",
        ],
        method="zenity",
    )
    if r.outcome != "unavailable":
        return r
    last = r
    r = await _run_confirm_dialog(
        "kdialog",
        [
            "--warningyesno", f"{message}\n\nProceed?",
            "--yes-label", "CONFIRM — DESTROY",
            "--no-label", "Cancel",
            "--title", "⚠️ DESTRUCTIVE OPERATION",
        ],
        method="kdialog",
    )
    if r.outcome != "unavailable":
        return r
    r.detail = f"zenity: {last.detail} | kdialog: {r.detail}"
    return r
