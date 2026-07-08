#!/usr/bin/env python3

import asyncio
import codecs
import io
import logging
import os
import re
import shlex
import shutil
import stat
import sys
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import discord

# --------------------------------------------------------------------------
# CONFIGURATION -- edit these for your setup
# --------------------------------------------------------------------------
#
# NOTE: the actual `intents`/`bot` objects used to run this bot are built
# further down (see "DISCORD CLIENT"), right before the @bot.event handlers
# that attach to them. A leftover, entirely-unused first `commands.Bot`
# instance used to be constructed here and then silently thrown away when
# `bot` was reassigned later -- dead weight from an earlier refactor away
# from discord.ext.commands (this file never used its command-decorator
# features; every command is dispatched manually in on_message). Removed
# during the bug-fix review so there's exactly one bot/intents object.

PREFIX = "termuc."
# SECURITY: never hardcode a real token here, and never commit this file
# with a real token in it. This file previously had a live-looking token
# hardcoded in plaintext -- if that was a real bot token, treat it as
# compromised and regenerate it immediately in the Discord Developer
# Portal (Bot -> Reset Token), then set it via an environment variable
# instead, e.g.: export TERMUC_BOT_TOKEN="your-new-token-here"
TOKEN = os.environ.get("TERMUC_BOT_TOKEN", "PUT_YOUR_TOKEN_IN_THE_TERMUC_BOT_TOKEN_ENV_VAR")
CHANNEL_IDS = {1522829979740536943, 1446928600271163546}     # only these channels accept commands (add more IDs as needed)
ALLOWED_ROLES = {"Lesser Termuc Access", "[MOD]"}       # role names that grant access (add more names as needed)
ALLOWED_USERS = {}   # user IDs that grant access (OR'd with role)
SPECIAL_ALLOW_ROLES = {"Termuc Access", "[OWNER]"}   # role names exempt from dangerous-command blocking (add more names as needed)
SPECIAL_ALLOW_USERS = {1190916475339411506}   # user IDs exempt from dangerous-command blocking (add more IDs as needed, OR'd with role)

HOME_DIR = os.path.expanduser("~")
MAX_INLINE_OUTPUT = 1900        # chars before output is sent as a .txt file instead
LIVE_EDIT_INTERVAL = 1.2        # seconds between live message edits (Discord rate-limit safety)
COMMAND_TIMEOUT = 300           # seconds before a running command is considered hung
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024  # safety cap for !download (default Discord non-nitro limit)
LOG_FILE = "bot.log"
DISCORD_MSG_LIMIT = 2000        # Discord's hard message-length cap

# Interactive Terminal Mode (ITM) settings. The rows/cols define both the
# size of the virtual screen the bot renders and the real pty window size
# reported to full-screen programs (nano/vim/htop/less/etc.) via `stty`, so
# keep them small enough that a fully-painted screen plus a short status
# footer always fits comfortably under DISCORD_MSG_LIMIT.
ITM_ROWS = 20
ITM_COLS = 76
ITM_RENDER_INTERVAL = LIVE_EDIT_INTERVAL  # reuse the same Discord-rate-limit-safe cadence

# The prefix used for special-key tokens while inside Interactive Terminal
# Mode (e.g. "/up", "/backspace 50", "/raw <text>"). Change this one
# variable to use something other than "/" -- useful since Discord's client
# pops up its own slash-command autocomplete box whenever a message starts
# with "/", which can make some of these tokens awkward to type. Keep it
# short and free of characters that need shell/regex escaping (e.g. "!!",
# "..", ";"); avoid "!" if PREFIX below is also "!"-based, to keep the two
# unambiguous.
ITM_KEY_PREFIX = "?"

# Dangerous binaries blocked for everyone NOT in SPECIAL_ALLOW.
DANGEROUS_BINARIES = {
    "rm", "rmdir", "mv", "chmod", "chown",
    "su", "sudo", "shutdown", "reboot", "poweroff",
    # Disk/partition/device-level tools that can destroy storage or brick
    # the device outright -- added as part of the layered security review.
    "dd", "mkfs", "wipefs", "fdisk", "parted", "gdisk", "sgdisk",
    "fastboot", "format", "termux-reboot",
}

# Commands that can execute another program supplied as one of their own
# *arguments* rather than as the first word of the shell segment. The
# primary check below (which only looks at the first word of each ;/&/|
# segment) cannot see a dangerous binary hiding inside one of these --
# e.g. `find / -exec rm {} \;`, `xargs rm`, or `sh -c "rm -rf ~"`.
COMMAND_WRAPPERS = {"find", "xargs", "eval", "exec", "sh", "bash", "env", "nohup", "timeout", "watch"}

# Tertiary, last-resort safety net: fixed regex signatures scanned against
# the *raw, untokenized* command text. These exist to catch attempts that
# would defeat the tokenized checks above via quoting, command
# substitution (`$(...)`, backticks), or nested shells.
_TERTIARY_DANGER_PATTERNS = [
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\brm\b[^\n;&|]*--no-preserve-root", re.IGNORECASE), "rm --no-preserve-root"),
    # Catches "rm -rf"/"-fr"/"-Rf" etc. anywhere in the raw text, including
    # inside a quoted string handed to a nested shell (e.g.
    # `sh -c "rm -rf /sdcard"`), which the tokenized layers above can miss
    # since the dangerous binary name is embedded inside a single argument
    # rather than standing alone as its own word.
    (re.compile(r"\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\b", re.IGNORECASE), "rm -rf (recursive force delete)"),
    (re.compile(r"\b(mkfs(\.\w+)?|wipefs|fdisk|parted|gdisk|sgdisk)\b", re.IGNORECASE), "disk/partition formatting tool"),
    (re.compile(r"of\s*=\s*/dev/(block|mmcblk|sd[a-z]|disk)", re.IGNORECASE), "raw write to a block/storage device"),
    (re.compile(r">>?\s*/dev/(block|mmcblk|sd[a-z]|disk)", re.IGNORECASE), "raw write to a block/storage device"),
    (re.compile(r"\bfastboot\s+(erase|format|flash)", re.IGNORECASE), "fastboot erase/format/flash"),
    (re.compile(r"\b(factory\s*reset|wipe\s*data)\b", re.IGNORECASE), "factory reset / wipe data"),
    (re.compile(r"\bkill\s+(-9\s+)?1\b"), "kill of PID 1 (init)"),
]

# Directories non-SPECIAL_ALLOW users may not cd into (or below).
RESTRICTED_CD_ROOTS = [
    "/", "/root", "/etc", "/boot", "/sys", "/proc", "/dev",
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/log",
    os.path.expanduser("~/storage"),
]

# --------------------------------------------------------------------------
# LOGGING
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
log = logging.getLogger("termbot")

# --------------------------------------------------------------------------
# PTY AVAILABILITY (POSIX only -- includes Termux on Android)
# --------------------------------------------------------------------------

try:
    import pty  # noqa: F401
    PTY_AVAILABLE = sys.platform != "win32"
except ImportError:
    PTY_AVAILABLE = False

if PTY_AVAILABLE:
    import pty
    import signal


def _detect_shell() -> str:
    """
    Pick a real, executable shell without hardcoding /bin/bash.

    Termux (and other non-standard POSIX environments) do not have a
    /bin/bash -- their shell lives under $PREFIX/bin/bash instead. We check,
    in order: $SHELL, Termux's $PREFIX/bin/bash, the well-known Termux
    absolute path, then fall back to common Linux/macOS locations, and
    finally to whatever `bash`/`sh` is on PATH.
    """
    candidates = []

    shell_env = os.environ.get("SHELL")
    if shell_env:
        candidates.append(shell_env)

    prefix = os.environ.get("PREFIX")  # set by Termux, e.g. /data/data/com.termux/files/usr
    if prefix:
        candidates.append(os.path.join(prefix, "bin", "bash"))

    candidates.append("/data/data/com.termux/files/usr/bin/bash")  # Termux, explicit
    candidates.append("/bin/bash")
    candidates.append("/usr/bin/bash")
    candidates.append("/usr/local/bin/bash")

    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    # Nothing matched above -- search PATH.
    found = shutil.which("bash") or shutil.which("sh")
    return found or "/bin/sh"


SHELL_PATH = _detect_shell()

# --------------------------------------------------------------------------
# ANSI / VT100 ESCAPE SEQUENCE STRIPPING
# --------------------------------------------------------------------------

# Matches CSI sequences (colors, cursor movement, bracketed-paste markers,
# private-mode toggles like `?2004h`/`?2004l`, etc.), OSC sequences (window
# title changes and similar), and the handful of other common single/2-byte
# escape codes a real terminal emulator would otherwise interpret.
_ANSI_ESCAPE_RE = re.compile(
    r"""
    \x1B
    (?:
        \[ [0-?]* [ -/]* [@-~]      # CSI ... e.g. \x1b[?2004h, \x1b[31m
      | \] .*? (?:\x07|\x1B\\)      # OSC ... terminated by BEL or ST
      | [P_^] .*? (?:\x07|\x1B\\)   # DCS / APC / PM ... terminated by BEL or ST
      | [()*+] .                    # charset designation (G0-G3), e.g. \x1b(B \x1b)0
      | [@-Z\\-_]                   # other 2-byte escapes (e.g. \x1bM, \x1b7)
    )
    """,
    re.VERBOSE | re.DOTALL,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT100 escape sequences and normalize carriage returns."""
    if not text:
        return text
    text = _ANSI_ESCAPE_RE.sub("", text)
    # Collapse CRLF to LF, and drop any remaining lone CRs (used by terminals
    # for in-place redraws like progress bars -- not useful in a Discord log).
    text = text.replace("\r\n", "\n").replace("\r", "")
    return text


# --------------------------------------------------------------------------
# GLOBAL STATE
# --------------------------------------------------------------------------

user_cwd: Dict[int, str] = {}                 # user_id -> current working directory
user_queues: Dict[int, "asyncio.Queue"] = {}  # user_id -> pending command queue
user_workers: Dict[int, "asyncio.Task"] = {}  # user_id -> queue-consumer task
pty_sessions: Dict[int, "PTYSession"] = {}# user_id -> live shell session
user_members: Dict[int, discord.abc.User] = {}  # user_id -> last-seen Discord member (for role checks)

# user_id -> stack of (path, previous_content_or_None) snapshots for termuc.undo.
# previous_content is None if the file did not exist before the edit (in
# which case undo deletes the file). Capped at UNDO_STACK_LIMIT per user.
user_undo_stack: Dict[int, List[Tuple[str, Optional[str]]]] = {}
UNDO_STACK_LIMIT = 20

# Interactive Terminal Mode (ITM) state -- all keyed by user_id so users can
# never see or interfere with each other's sessions/screens/messages.
itm_users: set = set()                          # user_ids currently in ITM
itm_screens: Dict[int, "TerminalScreen"] = {}   # user_id -> virtual screen buffer
itm_messages: Dict[int, discord.Message] = {}   # user_id -> live-updating Discord message
itm_tasks: Dict[int, "asyncio.Task"] = {}       # user_id -> background render/pump task
itm_last_render: Dict[int, str] = {}            # user_id -> last rendered screen text (dedupe edits)


def get_user_cwd(user_id: int) -> str:
    return user_cwd.setdefault(user_id, HOME_DIR)


def set_user_cwd(user_id: int, path: str) -> None:
    user_cwd[user_id] = path


# --------------------------------------------------------------------------
# PERMISSIONS & SAFETY CHECKS
# --------------------------------------------------------------------------

def has_permission(member: discord.abc.User) -> bool:
    """Role OR allow-list grants access."""
    if member.id in ALLOWED_USERS:
        return True
    roles = getattr(member, "roles", None)
    if roles:
        return any(r.name in ALLOWED_ROLES for r in roles)
    return False


def is_special(user_id: int) -> bool:
    if user_id in SPECIAL_ALLOW_USERS:
        return True
    member = user_members.get(user_id)
    if member is None:
        return False
    roles = getattr(member, "roles", None)
    if roles:
        return any(r.name in SPECIAL_ALLOW_ROLES for r in roles)
    return False


def _command_tokens(cmd: str):
    """Split a shell command on ; & | (and && / ||) and return each segment's first word."""
    segments = re.split(r"&&|\|\||[;&|]", cmd)
    tokens = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        try:
            words = shlex.split(seg)
        except ValueError:
            words = seg.split()
        if words:
            tokens.append((os.path.basename(words[0]), words))
    return tokens


def _is_restricted_path(path: str) -> bool:
    try:
        resolved = os.path.realpath(path)
    except Exception:
        return True
    if resolved == "/":
        return True
    for root in RESTRICTED_CD_ROOTS:
        if resolved == root or resolved.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _scan_wrapped_args_for_danger(cmd: str) -> Optional[str]:
    """
    Secondary check: look for a dangerous binary anywhere in the command --
    not just as the first word of a shell segment -- so it's still caught
    when smuggled in as an argument to a wrapper command (e.g.
    `find / -exec rm {} \\;`, `xargs rm -rf`, `sh -c "rm -rf ~"`).
    """
    for name, words in _command_tokens(cmd):
        if name not in COMMAND_WRAPPERS:
            continue
        for w in words[1:]:
            base = os.path.basename(w)
            if base in DANGEROUS_BINARIES:
                return f"Command `{base}` (used as an argument to `{name}`) is blocked for your permission level."
    return None


def _scan_raw_for_danger(cmd: str) -> Optional[str]:
    """
    Tertiary check: scan the raw, untokenized command text for a short list
    of especially hazardous fixed signatures. This is a last-resort net
    that keeps working even if command substitution, quoting, or nested
    shells defeated the tokenized checks above.
    """
    for pattern, label in _TERTIARY_DANGER_PATTERNS:
        if pattern.search(cmd):
            return f"Command contains a blocked pattern ({label})."
    return None


def check_dangerous(cmd: str, cwd: str, user_id: int) -> Optional[str]:
    """
    Return an error string if `cmd` should be blocked for this user, else None.
    SPECIAL_ALLOW users bypass every check here.

    Three layered checks are applied, in order, so that a bypass of one
    doesn't defeat the others:
      1. Primary   -- first word of each ;/&/| segment against
                      DANGEROUS_BINARIES, plus the cd-restriction check.
      2. Secondary -- a dangerous binary hiding as an *argument* to a
                      wrapper command (find -exec, xargs, nested shells).
      3. Tertiary  -- raw-text pattern scan for fixed hazardous signatures
                      (fork bombs, direct block-device writes, disk
                      formatting tools, factory reset, killing init, etc.),
                      immune to the quoting/substitution tricks that could
                      fool layers 1-2.
    """
    if is_special(user_id):
        return None

    # Layer 1: primary.
    for name, words in _command_tokens(cmd):
        if name in DANGEROUS_BINARIES:
            return f"Command `{name}` is blocked for your permission level."
        if name == "cd" and len(words) > 1:
            target = os.path.expanduser(words[1])
            if not os.path.isabs(target):
                target = os.path.join(cwd, target)
            if _is_restricted_path(target):
                return f"Changing into `{words[1]}` is restricted for your permission level."

    # Layer 2: secondary.
    error = _scan_wrapped_args_for_danger(cmd)
    if error:
        return error

    # Layer 3: tertiary.
    error = _scan_raw_for_danger(cmd)
    if error:
        return error

    return None


def check_path_allowed(path: str, user_id: int) -> Optional[str]:
    """Guard file read/write/edit operations against restricted system paths."""
    if is_special(user_id):
        return None
    if _is_restricted_path(os.path.dirname(os.path.realpath(path)) or "/"):
        return "That location is restricted for your permission level."
    return None


def resolve_path(user_id: int, filename: str) -> str:
    cwd = get_user_cwd(user_id)
    filename = os.path.expanduser(filename)
    return filename if os.path.isabs(filename) else os.path.join(cwd, filename)


# --------------------------------------------------------------------------
# DISCORD OUTPUT HELPERS
# --------------------------------------------------------------------------

async def _safe_delete(message: discord.Message) -> None:
    """
    Best-effort delete of a user's input message. Used for Interactive
    Terminal Mode and file-editing commands, where the input message is
    deleted before the bot's response is sent to keep the channel from
    filling up with raw keystrokes/edit commands. Never raises -- a
    missing "Manage Messages" permission (or the message already being
    gone) just means the message stays, and the command still runs.
    """
    try:
        await message.delete()
    except discord.HTTPException as e:
        log.warning(f"Could not delete message {message.id}: {e}")
    except Exception as e:
        log.warning(f"Unexpected error deleting message {message.id}: {e}")


async def reply_or_send(message: discord.Message, *args, **kwargs) -> Optional[discord.Message]:
    """
    Like message.reply(), but falls back to a plain channel.send() if the
    reply fails because the original message no longer exists (it may
    have just been deleted by _safe_delete()).

    ROOT CAUSE (ITM "no output" bug): this used to only catch
    discord.NotFound around the *first* attempt. Any other
    discord.HTTPException (a rate limit / 429, a transient 5xx, etc.)
    propagated straight out uncaught. In cmd_itm_enter, that exception hit
    after `itm_users.add(user_id)` had already run, so the user was left
    registered as "in ITM" (raw keystrokes route straight to the pty --
    which is why key commands still "worked") but with no status message
    ever created and, critically, no `_itm_loop` task ever started -- so
    nothing was ever read, rendered, or sent again for the rest of that
    session. Catching HTTPException broadly here means this function keeps
    its documented contract (always returns the message or None, never
    raises) so callers can react to a real failure instead of the failure
    silently vanishing into a generic log.exception() three call frames
    away.
    """
    try:
        return await message.reply(*args, **kwargs)
    except discord.NotFound:
        try:
            return await message.channel.send(*args, **kwargs)
        except discord.HTTPException as e:
            log.warning(f"Fallback channel.send failed: {e}")
            return None
    except discord.HTTPException as e:
        log.warning(f"reply_or_send: message.reply failed ({e}); trying channel.send instead")
        try:
            return await message.channel.send(*args, **kwargs)
        except discord.HTTPException as e2:
            log.warning(f"Fallback channel.send also failed: {e2}")
            return None


async def safe_edit(msg: discord.Message, content: str) -> bool:
    """Edit a message, swallowing rate-limit / not-found errors instead of crashing a task.

    Returns True if the edit actually went through and False if it was
    swallowed (rate limit, message deleted, etc.) -- callers that track
    "what's currently shown" (e.g. itm_last_render) must only advance that
    state on a True return, otherwise a single dropped edit gets silently
    treated as delivered and is never retried.
    """
    # Discord hard-caps messages at 2000 chars; guard against ever exceeding
    # that even for "live preview" edits (belt-and-braces alongside the
    # length checks performed by callers).
    if len(content) > DISCORD_MSG_LIMIT:
        content = content[: DISCORD_MSG_LIMIT - 20] + "\n...(truncated)```"
    try:
        await msg.edit(content=content)
        return True
    except discord.HTTPException as e:
        log.warning(f"Message edit failed: {e}")
        return False


async def start_cmd_message(
    message: discord.Message, user_id: int, initial_text: str = "```\nRunning...\n```"
) -> discord.Message:
    """
    Send a brand-new command-output message for *this* command invocation.

    ROOT CAUSE ("second !cmd overwrites the first one's output, outside
    ITM"): this used to be `get_or_create_cmd_message`, backed by a
    `cmd_messages` dict that cached a single message *per user* and reused
    (edited) it for every command that user ever ran. That's the right
    thing to do for the live preview/final-result edits *within* one
    command's own run (see run_command_pty/run_command_fallback, which
    call this once and then edit the returned message repeatedly) -- but
    it also meant the very next unrelated command reused that exact same
    message too, so its output overwrote the previous command's result
    before there was any chance to read it. Outside Interactive Terminal
    Mode there's no single "live screen" being maintained -- each `!cmd`
    is its own independent, one-shot thing -- so each one now gets its own
    message, sent as a reply to the triggering message, the same way any
    other one-off bot reply would be.
    """
    return await message.reply(initial_text)


async def deliver_output(msg: discord.Message, text: str, footer: str = "") -> None:
    """Send `text` inline in a code block, or as a .txt attachment if it's too long."""
    text = strip_ansi(text)
    if not text.strip():
        text = "(no output)"
    full = text if not footer else f"{text}\n\n{footer}"
    wrapped = f"```\n{full}\n```"
    if len(wrapped) <= DISCORD_MSG_LIMIT:
        await safe_edit(msg, wrapped)
        return
    buf = io.BytesIO(full.encode("utf-8", errors="ignore"))
    file = discord.File(fp=buf, filename="output.txt")
    await safe_edit(msg, "Output was too long -- see attached file." + (f"\n{footer}" if footer else ""))
    try:
        await msg.reply(file=file)
    except discord.HTTPException as e:
        log.warning(f"Failed to send output file: {e}")


# --------------------------------------------------------------------------
# PTY (INTERACTIVE SHELL) SESSION SUPPORT
# --------------------------------------------------------------------------

class PTYSession:
    """A persistent shell process attached to a pseudo-terminal, one per user."""

    def __init__(self, user_id: int):
        self.user_id = user_id
        self.pid: Optional[int] = None
        self.fd: Optional[int] = None
        self.alive = False
        # True while a command/program launched via run_command_pty is still
        # running in the foreground (i.e. we're waiting for its completion
        # marker). While this is set, subsequent "!cmd" messages from the
        # same user are forwarded straight to the pty as stdin instead of
        # being queued as brand-new commands -- this is what lets
        # interactive programs (python, node, bash, etc.) receive multiple
        # sequential inputs via input()/read/io.read().
        self.busy = False

    def start(self, cwd: str) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            # Child process: replace ourselves with a clean interactive shell.
            try:
                os.chdir(cwd)
            except Exception:
                pass
            env = os.environ.copy()
            env["TERM"] = "xterm"
            env["PS1"] = ""
            try:
                os.execvpe(SHELL_PATH, [SHELL_PATH, "--noprofile", "--norc"], env)
            except Exception:
                # Some minimal shells (e.g. plain `sh`) don't understand
                # bash's --noprofile/--norc flags -- retry with no flags at all.
                try:
                    os.execvpe(SHELL_PATH, [SHELL_PATH], env)
                except Exception:
                    os._exit(1)
        else:
            os.set_blocking(fd, False)
            self.pid = pid
            self.fd = fd
            self.alive = True

    def write(self, data: str) -> None:
        if self.alive and self.fd is not None:
            try:
                os.write(self.fd, data.encode())
            except OSError:
                self.alive = False

    def read_available(self) -> bytes:
        if not self.alive or self.fd is None:
            return b""
        chunks = []
        try:
            while True:
                chunk = os.read(self.fd, 4096)
                if not chunk:
                    # On a non-blocking fd, os.read() only returns b"" for a
                    # genuine EOF (the child's end of the pty has been
                    # closed -- shell exited, crashed, or was killed);
                    # "no data right now" instead raises BlockingIOError,
                    # caught below. This used to just `break` here without
                    # updating `alive`, so a dead shell kept being reported
                    # as alive forever -- which meant the "shell session
                    # ended" recovery paths in run_command_pty and
                    # _itm_loop never fired, and callers kept writing new
                    # commands/keystrokes into a shell that could never run
                    # them again.
                    self.alive = False
                    break
                chunks.append(chunk)
        except BlockingIOError:
            pass
        except OSError:
            self.alive = False
        return b"".join(chunks)

    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            if self.pid:
                os.kill(self.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            if self.fd is not None:
                os.close(self.fd)
        except Exception:
            pass


def get_or_create_pty_session(user_id: int) -> Tuple["PTYSession", bool]:
    """Return (session, is_newly_created)."""
    session = pty_sessions.get(user_id)
    if session is None or not session.alive:
        session = PTYSession(user_id)
        session.start(get_user_cwd(user_id))
        pty_sessions[user_id] = session
        log.info(f"Started new PTY session for user {user_id} (shell={SHELL_PATH})")
        return session, True
    return session, False


def close_all_pty_sessions() -> None:
    for task in list(itm_tasks.values()):
        task.cancel()
    for session in pty_sessions.values():
        session.close()


# --------------------------------------------------------------------------
# INTERACTIVE TERMINAL MODE (ITM) -- VIRTUAL SCREEN EMULATION
# --------------------------------------------------------------------------

class TerminalScreen:
    """
    A minimal VT100/ANSI terminal emulator that turns a raw PTY byte stream
    (cursor movement, screen clears, full-screen redraws, scrolling, the
    alternate screen buffer, etc.) into a plain-text snapshot of "what the
    screen currently looks like".

    This is what lets full-screen programs -- nano, vim/neovim, htop, top,
    less, sqlite3, and similar -- render sensibly as a periodically-updated
    Discord message instead of an unreadable wall of raw escape codes or a
    flood of near-duplicate edits.

    This is intentionally a lightweight, best-effort emulator rather than a
    complete VT100/xterm implementation: it covers cursor addressing, line
    and screen erase, scrolling regions, the alternate screen buffer, and
    the handful of other codes the programs above commonly emit. Anything
    unrecognized is safely ignored rather than corrupting rendering.
    """

    # Params allow digits, ';', ':' (colon sub-params), and the '<' '=' '>' '?'
    # marker bytes used by private/secondary/tertiary sequences (e.g.
    # \x1b[?25h, \x1b[>c). Final byte covers the full CSI final-byte range
    # (@-~) rather than just letters, so exotic-but-valid sequences are
    # matched and fully consumed instead of leaking stray characters.
    _CSI_RE = re.compile(r"\x1b\[([0-9;:<=>?]*)([@-~])")
    _OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
    # DCS / APC / PM strings (e.g. terminfo/termcap queries some editors
    # probe with) -- terminated by ST (\x1b\\) or, non-standard but common,
    # BEL. Swallowed whole so none of their payload leaks onto the screen.
    _DCS_RE = re.compile(r"\x1b[P_^].*?(?:\x07|\x1b\\)", re.DOTALL)

    def __init__(self, rows: int, cols: int):
        self.rows = rows
        self.cols = cols
        self.cur_row = 0
        self.cur_col = 0
        self.scroll_top = 0
        self.scroll_bottom = rows - 1
        self.saved_cursor: Optional[Tuple[int, int]] = None
        self.alt_saved_grid: Optional[list] = None
        self.alt_saved_cursor: Optional[Tuple[int, int]] = None
        self.grid = self._blank_grid()
        # Terminal-query replies (DSR/CPR, Device Attributes, etc.) that the
        # emulator has decided to answer on the child's behalf so that
        # programs like nvim don't stall waiting for a real terminal to
        # respond. Drained by the caller (see take_pending_replies) and
        # written back to the pty after each feed().
        self.pending_replies: List[str] = []
        # A trailing escape sequence that was cut off at the end of the last
        # feed() call (e.g. a big full-screen redraw from nano/vim landed
        # split across two separate pty reads, with the split falling in
        # the middle of a "move cursor"/"clear line" code). Held here and
        # prepended to the next feed() rather than being misread -- without
        # this, the orphaned ESC byte got silently dropped and the rest of
        # the sequence (e.g. "[12;1H") was printed onto the screen as
        # literal text instead of being executed, which is what caused
        # full-screen programs' body content to come out blank/garbled.
        self._pending_esc: str = ""
        # Nano/vim/htop etc. render with UTF-8 box-drawing and other
        # multi-byte characters, and we only ever get a chunk of whatever
        # bytes happened to be available on the pty at poll time (every
        # ~0.2s, or right after a keystroke). A multi-byte character can
        # easily land split across two separate reads -- e.g. the first 2
        # bytes of a 3-byte box-drawing char in one chunk, the last byte in
        # the next. `_safe_feed` used to do a one-shot
        # `data.decode(errors="ignore")` per chunk, which has no memory
        # between calls: a split character's first half decodes to nothing
        # (incomplete sequence, silently dropped) and its second half is a
        # lone continuation byte with no lead byte, which is *also* invalid
        # on its own and gets dropped or misread -- and depending on what
        # bytes end up adjacent after that, the result can look like
        # near-random symbol soup. This is a genuine incremental decoder
        # (see _safe_feed below): it holds any incomplete trailing bytes
        # from one call and stitches them onto the front of the next, so a
        # split character decodes correctly across the boundary instead of
        # turning into garbage.
        self._utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")

    def _blank_grid(self) -> list:
        return [[" "] * self.cols for _ in range(self.rows)]

    def _clamp_row(self, r: int) -> int:
        return max(0, min(self.rows - 1, r))

    def _clamp_col(self, c: int) -> int:
        return max(0, min(self.cols - 1, c))

    # Matches an ESC-introduced sequence that is *syntactically still
    # open* at the end of the buffer -- i.e. every char consumed so far is
    # a valid CSI parameter/intermediate byte, but no final byte has shown
    # up yet because the pty read ended mid-sequence. Used to tell "this
    # is genuinely truncated, wait for more bytes" apart from "this is
    # just an unrecognized/invalid escape, skip past it".
    _CSI_TRUNCATED_RE = re.compile(r"\x1b\[[0-9;:<=>?]*\Z")
    _OSC_TRUNCATED_RE = re.compile(r"\x1b\](?:(?!\x07|\x1b\\).)*\Z", re.DOTALL)
    _DCS_TRUNCATED_RE = re.compile(r"\x1b[P_^](?:(?!\x07|\x1b\\).)*\Z", re.DOTALL)

    def feed(self, data: str) -> None:
        """Feed a chunk of raw pty output into the emulator."""
        if self._pending_esc:
            data = self._pending_esc + data
            self._pending_esc = ""
        i = 0
        n = len(data)
        while i < n:
            ch = data[i]
            if ch == "\x1b":
                m = self._CSI_RE.match(data, i)
                if m:
                    self._handle_csi(m.group(1), m.group(2))
                    i = m.end()
                    continue
                m2 = self._OSC_RE.match(data, i)
                if m2:
                    i = m2.end()
                    continue
                m3 = self._DCS_RE.match(data, i)
                if m3:
                    i = m3.end()
                    continue
                # None of the complete-sequence patterns matched. Before
                # assuming this is just an unrecognized escape to skip
                # past, check whether it's a *truncated* one -- i.e. the
                # pty read ended before the sequence's terminator arrived
                # (very common with the large, single full-screen redraws
                # nano/vim/htop send, which routinely span multiple 4096-
                # byte pty reads). If so, stash the remainder and pick up
                # where we left off on the next feed() instead of dropping
                # the ESC and printing the leftover bytes as literal text.
                tail = data[i:]
                nxt_check = tail[1:2]
                looks_truncated = (
                    self._CSI_TRUNCATED_RE.match(tail) is not None
                    or self._OSC_TRUNCATED_RE.match(tail) is not None
                    or self._DCS_TRUNCATED_RE.match(tail) is not None
                    or nxt_check == ""  # lone trailing ESC
                    or (nxt_check in "()*+" and len(tail) < 3)  # split charset designator
                )
                if looks_truncated and len(tail) < 256:
                    # Cap how long we're willing to wait for the rest of a
                    # sequence, so a genuinely malformed/unsupported escape
                    # can't stall rendering forever.
                    self._pending_esc = tail
                    return
                if i + 1 < n:
                    nxt = data[i + 1]
                    if nxt in "()*+":
                        # Character-set designation for G0-G3 (e.g. \x1b(B,
                        # \x1b)0) is 3 bytes total: ESC, designator, charset
                        # id. Consuming only 2 previously left the charset id
                        # byte (e.g. the "B" in "\x1b(B") to fall through and
                        # be printed as a literal character on screen.
                        i += 3 if i + 2 < n else 2
                        continue
                    elif nxt == "7":
                        self.saved_cursor = (self.cur_row, self.cur_col)
                    elif nxt == "8" and self.saved_cursor:
                        self.cur_row, self.cur_col = self.saved_cursor
                    elif nxt == "c":
                        self.grid = self._blank_grid()
                        self.cur_row = self.cur_col = 0
                    elif nxt == "M":
                        self._reverse_index()
                    # Other lone 2-byte escapes (SS2/SS3, keypad mode
                    # switches \x1b=/\x1b>, etc.) have no visual effect on a
                    # rendered text snapshot and are safely swallowed here.
                    i += 2
                else:
                    i += 1
                continue
            elif ch == "\r":
                self.cur_col = 0
                i += 1
            elif ch == "\n":
                self._index()
                i += 1
            elif ch == "\x08":
                if self.cur_col > 0:
                    self.cur_col -= 1
                i += 1
            elif ch == "\t":
                self.cur_col = min(self.cols - 1, ((self.cur_col // 8) + 1) * 8)
                i += 1
            elif ch in ("\x07", "\x00"):
                i += 1
            elif ord(ch) < 32:
                i += 1
            else:
                self._putc(ch)
                i += 1

    def _putc(self, ch: str) -> None:
        if self.cur_col >= self.cols:
            self.cur_col = 0
            self._index()
        self.grid[self.cur_row][self.cur_col] = ch
        self.cur_col += 1

    def _index(self) -> None:
        """Move down one line, scrolling the scroll region if needed."""
        if self.cur_row == self.scroll_bottom:
            self._scroll_up()
        else:
            self.cur_row = self._clamp_row(self.cur_row + 1)

    def _reverse_index(self) -> None:
        """Move up one line, scrolling down if needed (ESC M)."""
        if self.cur_row == self.scroll_top:
            self._scroll_down()
        else:
            self.cur_row = self._clamp_row(self.cur_row - 1)

    def _scroll_up(self) -> None:
        top, bottom = self.scroll_top, self.scroll_bottom
        self.grid[top:bottom + 1] = self.grid[top + 1:bottom + 1] + [[" "] * self.cols]

    def _scroll_down(self) -> None:
        top, bottom = self.scroll_top, self.scroll_bottom
        self.grid[top:bottom + 1] = [[" "] * self.cols] + self.grid[top:bottom]

    @staticmethod
    def _params(params: str, count: int = 1, default: int = 1) -> list:
        parts = params[1:].split(";") if params.startswith("?") else params.split(";")
        out = []
        for idx in range(count):
            if idx < len(parts) and parts[idx].isdigit():
                out.append(int(parts[idx]))
            else:
                out.append(default)
        return out

    def _handle_csi(self, params: str, final: str) -> None:
        if params.startswith("?"):
            # Private DEC modes -- we only care about alternate-screen toggles;
            # cursor visibility, bracketed paste, etc. have no visual effect
            # on a rendered text snapshot and are safely ignored.
            codes = [c for c in params[1:].split(";") if c]
            if final in ("h", "l") and any(c in ("47", "1047", "1049") for c in codes):
                if final == "h":
                    self.alt_saved_grid = [row[:] for row in self.grid]
                    self.alt_saved_cursor = (self.cur_row, self.cur_col)
                    self.grid = self._blank_grid()
                    self.cur_row = self.cur_col = 0
                else:
                    if self.alt_saved_grid is not None:
                        self.grid = self.alt_saved_grid
                        self.cur_row, self.cur_col = self.alt_saved_cursor or (0, 0)
                        self.alt_saved_grid = None
                    else:
                        self.grid = self._blank_grid()
                        self.cur_row = self.cur_col = 0
            return

        if final == "A":
            self.cur_row = max(self.scroll_top, self.cur_row - self._params(params)[0])
        elif final == "B":
            self.cur_row = min(self.scroll_bottom, self.cur_row + self._params(params)[0])
        elif final in ("C", "a"):
            self.cur_col = self._clamp_col(self.cur_col + self._params(params)[0])
        elif final == "D":
            self.cur_col = self._clamp_col(self.cur_col - self._params(params)[0])
        elif final in ("H", "f"):
            row, col = self._params(params, 2)
            self.cur_row = self._clamp_row(row - 1)
            self.cur_col = self._clamp_col(col - 1)
        elif final == "G":
            self.cur_col = self._clamp_col(self._params(params)[0] - 1)
        elif final == "d":
            self.cur_row = self._clamp_row(self._params(params)[0] - 1)
        elif final == "J":
            self._erase_display(self._params(params, default=0)[0])
        elif final == "K":
            self._erase_line(self._params(params, default=0)[0])
        elif final == "L":
            for _ in range(self._params(params)[0]):
                self.grid.insert(self.cur_row, [" "] * self.cols)
                if len(self.grid) > self.rows:
                    self.grid.pop()
        elif final == "M":
            for _ in range(self._params(params)[0]):
                if self.cur_row < len(self.grid):
                    self.grid.pop(self.cur_row)
                self.grid.append([" "] * self.cols)
        elif final == "P":
            n = self._params(params)[0]
            row = self.grid[self.cur_row]
            del row[self.cur_col:self.cur_col + n]
            row.extend([" "] * (self.cols - len(row)))
        elif final == "X":
            n = self._params(params)[0]
            row = self.grid[self.cur_row]
            for c in range(self.cur_col, min(self.cols, self.cur_col + n)):
                row[c] = " "
        elif final == "@":
            n = self._params(params)[0]
            row = self.grid[self.cur_row]
            for _ in range(n):
                row.insert(self.cur_col, " ")
            del row[self.cols:]
        elif final == "r":
            top, bottom = self._params(params, 2)
            if 1 <= top < bottom <= self.rows:
                self.scroll_top = top - 1
                self.scroll_bottom = bottom - 1
            else:
                self.scroll_top = 0
                self.scroll_bottom = self.rows - 1
        elif final == "s":
            # ANSI.SYS-style save cursor (distinct escape from ESC 7, but
            # editors use them interchangeably -- share the same slot).
            self.saved_cursor = (self.cur_row, self.cur_col)
        elif final == "u":
            if self.saved_cursor:
                self.cur_row, self.cur_col = self.saved_cursor
        elif final == "n":
            # Device Status Report / Cursor Position Report queries. Real
            # terminal emulators answer these on the pty's input side; if we
            # don't, programs like nvim can stall waiting for a reply that
            # will never come. Emulate a reasonable answer instead of
            # leaving the raw query leak into the rendered output.
            code = params.split(";")[0] if params else ""
            if code == "6":
                self.pending_replies.append(f"\x1b[{self.cur_row + 1};{self.cur_col + 1}R")
            elif code == "5":
                self.pending_replies.append("\x1b[0n")
        elif final == "c":
            # Device Attributes queries (primary \x1b[c, secondary
            # \x1b[>c). Answer with a conservative, widely-accepted
            # identification so probing editors don't hang waiting.
            if params.startswith(">"):
                self.pending_replies.append("\x1b[>0;0;0c")
            elif params in ("", "0"):
                self.pending_replies.append("\x1b[?1;2c")
        # 'm' (SGR/colors) and any other unrecognized final byte are
        # intentionally no-ops -- Discord code blocks don't render color,
        # and skipping unknown codes is far safer than mishandling them.

    def take_pending_replies(self) -> str:
        """Drain and return any terminal-query replies queued by _handle_csi."""
        if not self.pending_replies:
            return ""
        out = "".join(self.pending_replies)
        self.pending_replies.clear()
        return out

    def _erase_display(self, mode: int) -> None:
        if mode == 0:
            self._erase_line(0)
            for r in range(self.cur_row + 1, self.rows):
                self.grid[r] = [" "] * self.cols
        elif mode == 1:
            self._erase_line(1)
            for r in range(0, self.cur_row):
                self.grid[r] = [" "] * self.cols
        else:
            self.grid = self._blank_grid()

    def _erase_line(self, mode: int) -> None:
        row = self.grid[self.cur_row]
        if mode == 0:
            for c in range(self.cur_col, self.cols):
                row[c] = " "
        elif mode == 1:
            for c in range(0, min(self.cur_col + 1, self.cols)):
                row[c] = " "
        else:
            self.grid[self.cur_row] = [" "] * self.cols

    def render(self) -> str:
        """Return the current screen contents as plain text."""
        lines = ["".join(row).rstrip() for row in self.grid]
        return "\n".join(lines).rstrip("\n")


def _safe_feed(screen: "TerminalScreen", data: bytes) -> None:
    """Feed raw pty bytes into a TerminalScreen without ever letting a bad
    chunk raise out of the call site.

    ROOT CAUSE (ITM "no output" bug): every place that reads the pty and
    hands bytes to the screen emulator did `screen.feed(data.decode(...))`
    directly, with the read -> feed -> render -> edit sequence in
    `_itm_loop` wrapped in one `try/except` around the *entire* `while`
    loop. If `feed()` ever raised on some byte sequence the hand-rolled
    VT100 emulator doesn't expect, the exception was logged once and the
    whole background polling task ended for good -- but `itm_users` still
    had the user in it, so the bot looked like it had silently frozen with
    no more output for the rest of that ITM session. Centralizing every
    feed() call through this helper means a single malformed chunk is
    dropped (logged, not raised), and reading/rendering/sending keeps
    going.

    ROOT CAUSE (random symbols when typing in ITM): this used to do
    `data.decode(errors="ignore")` right here, decoding each chunk in
    isolation with no memory of a previous chunk. A multi-byte UTF-8
    character (box-drawing borders, etc., which nano/vim/htop use
    constantly) split across two pty reads would have each half decoded on
    its own -- an incomplete lead sequence with no continuation byte, and a
    lone continuation byte with no lead -- both invalid alone, producing
    dropped/garbled characters that looked like random symbol soup,
    especially noticeable since a redraw happens on every keystroke. Now
    each screen keeps its own incremental decoder (see
    TerminalScreen.__init__) that carries any incomplete trailing bytes
    forward to the next chunk, so a split character decodes correctly
    across the read boundary instead of turning into garbage.
    """
    try:
        screen.feed(screen._utf8_decoder.decode(data))
    except Exception:
        log.exception("TerminalScreen.feed() raised on a pty chunk; dropping this chunk and continuing")


# --------------------------------------------------------------------------
# INTERACTIVE TERMINAL MODE (ITM) -- KEYBOARD INPUT TRANSLATION
# --------------------------------------------------------------------------

# Special-key tokens usable in ITM by sending a `/`-prefixed word, e.g.
# "/up", "/esc", "/ctrl+c". Multiple tokens can be sent space-separated in
# one message, e.g. "/ctrl+x /enter". Anything not matching this whole-message
# token grammar is sent as a literal typed line, Enter included.
_ITM_KEY_MAP = {
    "UP": "\x1b[A", "DOWN": "\x1b[B", "RIGHT": "\x1b[C", "LEFT": "\x1b[D",
    "ESC": "\x1b", "ESCAPE": "\x1b",
    "TAB": "\t",
    "ENTER": "\r", "RETURN": "\r",
    # Manual newline insertion (LF, distinct from ENTER's CR) -- lets users
    # insert a line break on demand instead of relying on the automatic
    # \n -> \r conversion applied to typed multi-line text below.
    "NEXTLINE": "\n", "NL": "\n",
    "BACKSPACE": "\x7f", "BS": "\x7f",
    "DEL": "\x1b[3~", "DELETE": "\x1b[3~",
    "HOME": "\x1b[H",
    "END": "\x1b[F",
    "PAGEUP": "\x1b[5~", "PGUP": "\x1b[5~",
    "PAGEDOWN": "\x1b[6~", "PGDN": "\x1b[6~",
    "INSERT": "\x1b[2~", "INS": "\x1b[2~",
    "SPACE": " ",
}
for _i, _letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ", start=1):
    _ITM_KEY_MAP[f"CTRL+{_letter}"] = chr(_i)
    _ITM_KEY_MAP[f"CTRL-{_letter}"] = chr(_i)
    _ITM_KEY_MAP[f"C-{_letter}"] = chr(_i)
del _i, _letter

# "/backspace <n>" (or "/bs <n>") sends <n> literal Backspace keypresses,
# e.g. "/backspace 50" == pressing Backspace 50 times. Bare "/backspace"
# with no count still goes through the normal single-token path below.
_BACKSPACE_COUNT_RE = re.compile(
    rf"^{re.escape(ITM_KEY_PREFIX)}(?:backspace|bs)\s+(\d+)$", re.IGNORECASE
)


def _translate_itm_input(raw: str) -> str:
    """
    Translate one Discord message sent while in ITM into raw bytes for the
    pty.

    - "<prefix>raw <text>" (case-insensitive) sends <text> byte-for-byte
      with no trailing Enter -- useful for building up input across
      multiple messages before pressing Enter or a special key separately
      (e.g. typing `i` to enter vim insert mode, then text, then
      "<prefix>esc").
    - "<prefix>backspace <n>" or "<prefix>bs <n>" sends <n> literal
      Backspace keypresses (e.g. "<prefix>backspace 50" == pressing
      Backspace 50 times). Bare "<prefix>backspace" (no count) is
      unaffected and still goes through the normal single-key-token path
      below.
    - A message made up entirely of space-separated "<prefix>key" tokens
      (e.g. "<prefix>up", "<prefix>ctrl+c", "<prefix>ctrl+x <prefix>enter")
      is translated into the corresponding raw control sequence(s) with
      nothing else appended.
    - "<prefix>nextline" (alias "<prefix>nl") sends a bare newline (LF)
      byte, on its own or combined with other tokens/text in the same
      message (e.g. "<prefix>raw foo<prefix>nlbar" is not valid -- use it
      as its own token, e.g. "<prefix>raw foo" then "<prefix>nl" then
      "<prefix>raw bar"). This is a manual way to insert a line break,
      instead of relying on the automatic \\n -> \\r conversion applied to
      ordinary typed multi-line text below.
    - Anything else is treated as a normal typed line and sent followed by
      Enter (\\r), which is what lets python's input() / lua's io.read()
      and ordinary shell commands work exactly as if typed and confirmed.

    "<prefix>" above is ITM_KEY_PREFIX (default "/") -- every form above
    shifts automatically if that variable is changed.
    """
    p = ITM_KEY_PREFIX
    plen = len(p)
    raw_prefix = f"{p}raw"

    if raw[: plen + 4].lower() == f"{raw_prefix} ".lower():
        return raw[plen + 4 :]
    if raw.strip().lower() == raw_prefix.lower():
        return ""

    m = _BACKSPACE_COUNT_RE.match(raw.strip())
    if m:
        count = min(int(m.group(1)), 4000)  # sane upper bound against runaway floods
        return _ITM_KEY_MAP["BACKSPACE"] * count

    tokens = raw.split()
    if tokens and all(t.startswith(p) and t[plen:].upper() in _ITM_KEY_MAP for t in tokens):
        return "".join(_ITM_KEY_MAP[t[plen:].upper()] for t in tokens)

    text = raw.replace("\r\n", "\n").replace("\n", "\r")
    if not text.endswith("\r"):
        text += "\r"
    return text


# Purely cosmetic startup banner shown once when a user enters ITM. Does not
# affect ITM behavior in any way -- it's just prepended to the first render.
_ITM_BANNER = (
    "╭──────────────────────────────────╮\n"
    "│   🖥️   T E R M U C   ·   I T M    │\n"
    "│      Interactive Terminal Mode    │\n"
    "╰──────────────────────────────────╯"
)


def _render_itm(screen: "TerminalScreen", active: bool = True, banner: bool = False) -> str:
    """Wrap a TerminalScreen snapshot in a Discord code block + short help footer."""
    body = f"```\n{screen.render()}\n```"
    header = f"{_ITM_BANNER}\n" if banner else ""
    if active:
        p = ITM_KEY_PREFIX
        key_names = [
            "up", "down", "left", "right", "esc", "tab", "enter", "backspace",
            "delete", "home", "end", "pgup", "pgdn", "ctrl+<letter>", "nextline/nl",
        ]
        keys_list = " ".join(f"{p}{name}" for name in key_names)
        footer = (
            f"*ITM active -- raw keystrokes go to your shell. `{PREFIX}exititm` to leave. "
            f"Keys: {keys_list}, or {p}raw <text>. "
            f"{p}backspace <n> sends n backspaces, e.g. {p}backspace 50.*"
        )
    else:
        footer = "*(final screen state -- Interactive Terminal Mode closed)*"
    combined = f"{header}{body}\n{footer}"
    if len(combined) > DISCORD_MSG_LIMIT:
        combined = combined[: DISCORD_MSG_LIMIT - 4] + "\n```"
    return combined


async def _itm_loop(user_id: int) -> None:
    """
    Background task: while a user is in ITM, periodically drain their pty
    and, if the rendered screen changed, edit their live terminal message.
    Polls frequently (so keystrokes feel responsive) but only edits Discord
    at most once per ITM_RENDER_INTERVAL to stay well clear of rate limits.
    """
    last_edit = 0.0
    try:
        while user_id in itm_users:
            await asyncio.sleep(0.2)
            # ROOT CAUSE (ITM "no output" bug): this loop body used to run
            # with no per-iteration guard -- only a single try/except
            # wrapped around the entire `while`. Any exception raised while
            # reading/feeding/rendering a single chunk (e.g. an edge case in
            # the hand-rolled VT100 emulator, or a transient Discord API
            # error) was logged once and ended this background task
            # permanently -- but `itm_users` still contained the user, so
            # nothing ever told them ITM had died. From their side it just
            # looked like the terminal had frozen with no more output.
            # Catching per-iteration instead means one bad chunk is logged
            # and skipped, and polling/rendering/sending keeps going.
            try:
                session = pty_sessions.get(user_id)
                screen = itm_screens.get(user_id)
                if session is None or screen is None or not session.alive:
                    break
                data = session.read_available()
                if data:
                    _safe_feed(screen, data)
                    replies = screen.take_pending_replies()
                    if replies:
                        session.write(replies)
                now = time.monotonic()
                if now - last_edit < ITM_RENDER_INTERVAL:
                    continue
                rendered = screen.render()
                if rendered != itm_last_render.get(user_id):
                    msg = itm_messages.get(user_id)
                    delivered = True
                    if msg is not None:
                        delivered = await safe_edit(msg, _render_itm(screen))
                    # Only record this render as "shown" if the edit actually
                    # went through. If safe_edit swallowed a failure (rate
                    # limit, message gone, etc.), leaving itm_last_render stale
                    # means the very next tick will notice the mismatch again
                    # and retry the edit, instead of the update being silently
                    # dropped forever.
                    if delivered:
                        itm_last_render[user_id] = rendered
                        last_edit = now
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(f"ITM render loop iteration failed for user {user_id}; continuing")

        if user_id in itm_users:
            # Session died out from under an active ITM session.
            msg = itm_messages.get(user_id)
            if msg is not None:
                await safe_edit(msg, "```\n[Shell session ended]\n```")
            itm_users.discard(user_id)
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception(f"ITM render loop crashed for user {user_id}")


async def cmd_itm_enter(message: discord.Message, initial_cmd: Optional[str] = None) -> None:
    """
    Enter Interactive Terminal Mode for this user (queued like any other command).

    `initial_cmd`, when given, is written into the shell right after the ITM
    stty setup, before the first screen render -- this is how
    route_fullscreen_to_itm() drops a user straight into a running
    nano/vim/htop/etc. instead of dumping them at a bare prompt they'd then
    have to retype the command into.
    """
    user_id = message.author.id

    if not PTY_AVAILABLE:
        await reply_or_send(message, "🚫 Interactive Terminal Mode requires POSIX pty support, which isn't available on this platform.")
        return
    if user_id in itm_users:
        await reply_or_send(message, "ℹ️ You're already in Interactive Terminal Mode.")
        return

    session, is_new = get_or_create_pty_session(user_id)
    if is_new:
        session.write(
            "stty -echo 2>/dev/null; "
            "bind 'set enable-bracketed-paste off' 2>/dev/null; "
            f"stty cols {ITM_COLS} rows {ITM_ROWS} 2>/dev/null\n"
        )
    else:
        session.write(f"stty cols {ITM_COLS} rows {ITM_ROWS} 2>/dev/null\n")
    await asyncio.sleep(0.3)
    if initial_cmd is not None:
        cwd = get_user_cwd(user_id)
        session.write(f"cd {shlex.quote(cwd)} 2>/dev/null; {initial_cmd}\n")
        # Fullscreen programs need a moment to clear the screen and draw
        # their first frame (htop/vim redrawing a whole alt-screen is
        # slower than a plain shell prompt coming back) -- give this a
        # longer runway than the plain-ITM-entry case before we snapshot
        # "leftover" output below, or the first render users see is often
        # just the shell's echo of the command instead of the program.
        await asyncio.sleep(0.5)

    screen = TerminalScreen(ITM_ROWS, ITM_COLS)
    leftover = session.read_available()
    if leftover:
        _safe_feed(screen, leftover)
        replies = screen.take_pending_replies()
        if replies:
            session.write(replies)

    # ROOT CAUSE (ITM "no output" bug): this used to add the user to
    # `itm_users` (and populate itm_screens/itm_last_render) BEFORE trying
    # to send the status message. If that send failed for any reason other
    # than the triggering message being gone (a rate limit, a transient
    # Discord error), the exception used to propagate out of here and get
    # swallowed three frames away by the queue worker's generic
    # `except Exception: log.exception(...)` -- leaving the user marked as
    # "in ITM" (so their keystrokes were still routed straight to the pty)
    # but with no status message and, because the code never reached the
    # lines below, no `_itm_loop` task ever created to read/render/send
    # anything, ever, for the rest of that session. Now we only commit the
    # ITM state once we actually have a message to show it in.
    status_msg = await reply_or_send(message, _render_itm(screen, banner=True))
    if status_msg is None:
        await reply_or_send(
            message,
            "⚠️ Couldn't start Interactive Terminal Mode (failed to send the terminal message -- "
            "possibly a Discord rate limit). Please try `termuc.itm` again in a moment.",
        )
        log.warning(f"Failed to create ITM status message for user {user_id}; aborting ITM entry")
        return

    itm_users.add(user_id)
    itm_screens[user_id] = screen
    itm_last_render[user_id] = screen.render()
    itm_messages[user_id] = status_msg
    itm_tasks[user_id] = asyncio.create_task(_itm_loop(user_id))
    log.info(f"User {user_id} entered Interactive Terminal Mode")


async def cmd_itm_exit(message: discord.Message) -> None:
    """Leave Interactive Terminal Mode. The underlying pty/shell keeps running."""
    user_id = message.author.id

    if user_id not in itm_users:
        await reply_or_send(message, "ℹ️ You're not currently in Interactive Terminal Mode.")
        return

    itm_users.discard(user_id)
    task = itm_tasks.pop(user_id, None)
    if task is not None:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception(f"Error awaiting cancelled ITM task for user {user_id}")

    session = pty_sessions.get(user_id)
    screen = itm_screens.get(user_id)
    if session is not None and session.alive and screen is not None:
        await asyncio.sleep(0.2)
        data = session.read_available()
        if data:
            _safe_feed(screen, data)
            replies = screen.take_pending_replies()
            if replies:
                session.write(replies)
        msg = itm_messages.get(user_id)
        if msg is not None:
            await safe_edit(msg, _render_itm(screen, active=False))

        # Restore the wide, non-wrapping size used by !cmd's marker-based
        # streaming, and best-effort re-sync the tracked cwd. This line (and
        # the probe below) are simply queued as ordinary input if a
        # foreground program is still running -- harmless, but the cwd sync
        # is only meaningful once you're back at a plain shell prompt.
        marker = f"__ITMPWD_{uuid.uuid4().hex}__"
        session.write("stty cols 1000 rows 1000 2>/dev/null\n")
        session.write(f"printf '\\n{marker}:%s\\n' \"$(pwd)\" 2>/dev/null\n")
        await asyncio.sleep(0.3)
        probe = strip_ansi(session.read_available().decode(errors="ignore"))
        m = re.search(rf"{re.escape(marker)}:(.*)", probe)
        if m:
            new_cwd = m.group(1).strip()
            if new_cwd:
                set_user_cwd(user_id, new_cwd)

    itm_screens.pop(user_id, None)
    itm_messages.pop(user_id, None)
    itm_last_render.pop(user_id, None)

    await reply_or_send(message, "✅ Exited Interactive Terminal Mode. Your shell session keeps running in the background.")
    log.info(f"User {user_id} exited Interactive Terminal Mode")


# --------------------------------------------------------------------------
# COMMAND EXECUTION
# --------------------------------------------------------------------------

async def _recover_wedged_session(session: "PTYSession", user_id: int) -> bool:
    """
    Best-effort recovery after a foreground command times out.

    Sends Ctrl+C to try to interrupt whatever's running, then probes with a
    fresh, unique marker to confirm the shell is genuinely back at a clean
    prompt before letting any more commands through. This is the "flush/
    reset the PTY after timeout" and "verify the shell returns to a clean
    state" step -- without it, `session.busy` could be reset to False (see
    caller) while the actual foreground process was still sitting there
    waiting to eat the next command's bytes as ordinary input/keystrokes.

    Returns True if the shell answered the probe (safe to keep using this
    session), False if it stayed completely silent (caller should close the
    session so the next command starts a brand new shell).
    """
    if not session.alive:
        return False

    session.write("\x03")  # Ctrl+C -- ask whatever's in the foreground to stop
    await asyncio.sleep(0.3)
    session.read_available()  # drain/discard whatever that produced

    probe = f"__RECOVER_{uuid.uuid4().hex}__"
    session.write(f"printf '\\n{probe}\\n' 2>/dev/null\n")

    buf = ""
    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        await asyncio.sleep(0.15)
        if not session.alive:
            return False
        buf += strip_ansi(session.read_available().decode(errors="ignore"))
        if re.search(re.escape(probe), buf):
            return True
    return False


async def run_command_pty(message: discord.Message, raw_cmd: str) -> None:
    """Run a command through the user's persistent PTY shell, streaming live output."""
    user_id = message.author.id
    session, is_new = get_or_create_pty_session(user_id)
    cwd = get_user_cwd(user_id)

    # ROOT CAUSE (on_message / run_command_pty busy race): this used to be
    # set much further down, right before the polling loop, with an
    # `await start_cmd_message(...)` (and, for a brand new
    # session, an `await asyncio.sleep(0.3)` before that) in between. Every
    # `await` is a point where the event loop can switch to a *different*
    # on_message task -- and discord.py dispatches on_message for each
    # incoming message as its own concurrently-scheduled task rather than
    # running them one at a time, so a second "!cmd" arriving milliseconds
    # after the first could have its on_message task run its
    # `session.busy` check while this function was still in that window,
    # see `busy` as still False, and get queued behind this command
    # instead of being forwarded straight into the pty as stdin -- which
    # matters once this command turns out to be a long-running/interactive
    # one, since the queued message then just sits unread until this
    # run_command_pty call finishes (which may be a long time, or never,
    # for something waiting on input). Setting `busy` here, before this
    # function's first `await`, closes that window: by the time control
    # can yield back to the event loop, `session.busy` is already True for
    # any concurrently-scheduled on_message task to see.
    session.busy = True

    if is_new:
        # Best-effort terminal hygiene for a brand new session:
        #  - disable local echo (so our own typed commands aren't echoed back)
        #  - disable bracketed-paste mode (avoids stray \x1b[200~ / \x1b[201~
        #    and the [?2004h/[?2004l sequences some bash builds emit)
        #  - widen the terminal so long commands don't get artificially
        #    line-wrapped by the pty, which would break output parsing
        session.write(
            "stty -echo 2>/dev/null; "
            "bind 'set enable-bracketed-paste off' 2>/dev/null; "
            "stty cols 1000 rows 1000 2>/dev/null\n"
        )
        await asyncio.sleep(0.3)
        session.read_available()  # discard shell startup banner + the above echoes

    marker = f"__DONE_{uuid.uuid4().hex}__"
    # Re-anchor to the tracked cwd every time, run the command, then report
    # the exit code and resulting directory so we can keep cwd in sync even
    # if the user's command itself contained a `cd`.
    #
    # IMPORTANT: the command and the trailing "done marker" printf are
    # wrapped in a `{ ...; }` brace group spanning both physical lines,
    # rather than being sent as two independent lines. A pty's line
    # discipline queues each newline-terminated chunk as soon as it's
    # written, regardless of which process ends up reading it -- so if the
    # marker's printf sat on its own already-complete line, an interactive
    # foreground program started by `raw_cmd` (python, node, bash, anything
    # calling input()/read) could read that queued printf line as if it
    # were the user's first typed input, corrupting the program's input
    # entirely. Because the brace group is syntactically incomplete after
    # the first line, bash's interactive reader buffers (and reads) both
    # physical lines before executing anything, so nothing is left queued
    # in the tty for the child process to steal. `{ ...; }` doesn't fork a
    # subshell, so a `cd` inside raw_cmd still persists afterwards, and `$?`
    # after the closing brace still reflects raw_cmd's own exit status.
    wrapped = (
        "{ " + f"cd {shlex.quote(cwd)} 2>/dev/null; {raw_cmd}" + "\n"
        "}; " + f"printf '\\n{marker}:%d:%s\\n' \"$?\" \"$(pwd)\"" + "\n"
    )
    # ROOT CAUSE (stale/appended output on every !cmd): `wrapped` was built
    # above but this call to actually send it to the shell was missing
    # entirely -- the polling loop below was waiting on a marker that was
    # never written to the pty, so it only ever saw whatever was already
    # sitting in the pty's read buffer from the *previous* command (hence
    # output looking stale, or a later command's output looking like it had
    # a previous command's output appended ahead of it). Nothing after this
    # point works without this write.
    session.write(wrapped)
    status_msg = await start_cmd_message(message, user_id)
    buffer = ""
    last_edit = 0.0
    start = time.monotonic()
    exit_code = "?"
    # `session.busy` is already True at this point (set at the very top of
    # this function, before our first await -- see the comment there). It
    # stays True for the duration of this foreground command so that
    # on_message() knows to forward any further "!cmd" messages from this
    # user directly into the pty as stdin (see on_message), rather than
    # queuing them as new commands behind this still-running one. This is
    # what allows interactive programs to receive unlimited sequential
    # inputs instead of the bot blocking until the process exits.
    try:
        while True:
            await asyncio.sleep(0.15)
            buffer += session.read_available().decode(errors="ignore")

            # Strip escape sequences continuously so marker-matching and the
            # live preview both operate on clean text.
            clean_buffer = strip_ansi(buffer)

            match = re.search(rf"{re.escape(marker)}:(\d+):(.*)", clean_buffer)
            if match:
                exit_code = match.group(1)
                new_cwd = match.group(2).strip()
                if new_cwd:
                    set_user_cwd(user_id, new_cwd)
                clean_buffer = clean_buffer[: match.start()]
                buffer = clean_buffer
                break

            if time.monotonic() - start > COMMAND_TIMEOUT:
                buffer = clean_buffer + "\n[Command timed out]"
                exit_code = "timeout"
                break
            if not session.alive:
                buffer = clean_buffer + "\n[Shell session ended unexpectedly]"
                exit_code = "error"
                break

            now = time.monotonic()
            if now - last_edit > LIVE_EDIT_INTERVAL:
                preview = _strip_echo(clean_buffer, wrapped)[-MAX_INLINE_OUTPUT:]
                await safe_edit(status_msg, f"```\n{preview}\n```")
                last_edit = now
    finally:
        # ROOT CAUSE (session.busy stuck / "termuc.cmd and termuc.itm don't
        # recover after interactive commands"): this used to unconditionally
        # do `session.busy = False` here, whether the command finished
        # normally, timed out, or the shell died. That's correct for a
        # normal completion (the marker was seen, so the shell is
        # definitely back at a clean prompt) and for a dead session (a new
        # one gets created on the next command anyway) -- but NOT for a
        # timeout. A timeout only means *we* gave up waiting for the
        # marker; the actual foreground process (a wedged `nano`, `less`,
        # an infinite loop, anything blocked on input we never sent) is
        # still very likely alive and still attached to the pty as the
        # thing that will receive the *next* command's bytes. Flipping
        # `busy` back to False without checking meant the next "!cmd" got
        # typed straight into that still-running foreground process
        # instead of being executed by the shell -- e.g. it silently
        # inserted "ls" as text into an abandoned nano buffer instead of
        # listing a directory -- which is exactly the "stuck after
        # interactive commands" symptom. Now, on a timeout, we try to
        # interrupt and confirm the shell is actually back at a clean
        # prompt before declaring the session usable again; if it never
        # responds, we tear the session down so the next command starts a
        # brand new shell instead of silently feeding a zombie foreground
        # process.
        if exit_code == "timeout" and session.alive:
            recovered = await _recover_wedged_session(session, user_id)
            if not recovered:
                log.warning(
                    f"PTY session for user {user_id} did not respond after a "
                    "command timeout; closing it so the next command starts fresh"
                )
                session.close()
        session.busy = False

    cleaned = _strip_echo(strip_ansi(buffer), wrapped)
    await deliver_output(status_msg, cleaned, footer=f"Exit code: {exit_code}")


def _strip_echo(buffer: str, wrapped_input: str) -> str:
    """Best-effort removal of the terminal's echo of what we typed."""
    lines = buffer.split("\n")
    # A PTY echoes back the bytes we wrote, which may span the first line(s).
    # Drop leading lines that are clearly just echoed input.
    input_lines = set(l.strip() for l in wrapped_input.strip().split("\n"))
    while lines and lines[0].strip() in input_lines:
        lines.pop(0)
    # Also catch the case where the whole wrapped command echoed back as one
    # unbroken run (e.g. echo wasn't fully disabled) by dropping a leading
    # line that exactly contains the raw command text we sent.
    joined_input = " ".join(wrapped_input.strip().split())
    while lines and " ".join(lines[0].strip().split()) and joined_input.startswith(" ".join(lines[0].strip().split())):
        if not lines[0].strip():
            break
        lines.pop(0)
    return "\n".join(lines).strip("\n")


async def run_command_fallback(message: discord.Message, raw_cmd: str) -> None:
    """Non-PTY fallback: run each command as an isolated subprocess (manual cwd tracking)."""
    user_id = message.author.id
    cwd = get_user_cwd(user_id)

    # Handle `cd` ourselves since a subprocess's cwd change doesn't persist.
    stripped = raw_cmd.strip()
    if stripped == "cd" or stripped.startswith("cd "):
        parts = stripped.split(maxsplit=1)
        target = HOME_DIR if len(parts) == 1 else os.path.expanduser(parts[1])
        if len(parts) > 1 and not os.path.isabs(target):
            target = os.path.abspath(os.path.join(cwd, target))
        if not os.path.isdir(target):
            await start_cmd_message(message, user_id, "```\nDirectory not found.\n```")
            return
        set_user_cwd(user_id, target)
        await start_cmd_message(message, user_id, f"```\nCurrent directory:\n{target}\n```")
        return

    status_msg = await start_cmd_message(message, user_id)
    try:
        proc = await asyncio.create_subprocess_shell(
            raw_cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as e:
        await deliver_output(status_msg, f"Failed to start command: {e}")
        return

    buffer = ""
    last_edit = 0.0
    start = time.monotonic()
    try:
        while True:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                line = b""
            if line:
                buffer += line.decode(errors="ignore")
            elif proc.stdout.at_eof():
                break

            if time.monotonic() - start > COMMAND_TIMEOUT:
                proc.kill()
                buffer += "\n[Command timed out]"
                break

            now = time.monotonic()
            if now - last_edit > LIVE_EDIT_INTERVAL:
                preview = strip_ansi(buffer)[-MAX_INLINE_OUTPUT:]
                await safe_edit(status_msg, f"```\n{preview}\n```")
                last_edit = now

        rc = await proc.wait()
    except Exception as e:
        buffer += f"\n[Error: {e}]"
        rc = "error"

    await deliver_output(status_msg, buffer, footer=f"Exit code: {rc}")


# Programs that take over the whole terminal with an alternate-screen /
# cursor-addressed UI instead of just printing lines and exiting. These
# don't work through the !cmd -> run_command_pty path at all: that path
# polls for a plain-text "done" marker and has no way to feed the program
# keystrokes, so a fullscreen program launched via !cmd just sits there
# consuming the pty until COMMAND_TIMEOUT fires and the bot declares it
# "timed out" -- indistinguishable, from the user's side, from a genuinely
# hung command. Routing these into Interactive Terminal Mode instead gives
# them a real VT100 screen and a way to type into them.
FULLSCREEN_PROGRAMS = {
    "nano", "vim", "vi", "nvim", "pico",
    "htop", "top", "atop",
    "less", "more", "man",
    "tmux", "screen",
    "watch", "mc", "ranger",
    "emacs", "nmtui", "alsamixer",
}


def _is_fullscreen_command(raw_cmd: str) -> bool:
    """
    Best-effort detection of a command whose first pipeline segment invokes
    a known fullscreen program (see FULLSCREEN_PROGRAMS).

    This is a heuristic, not a full shell parse: it only looks at the first
    word of the command up to the first &&, ||, ;, or | -- so `nano f.txt`
    and `cd /tmp && vim x` are caught, but `echo hi && sleep 1 && nano x`
    (fullscreen program not first in the chain) or nano invoked indirectly
    through a wrapper script won't be. Given the failure mode being guarded
    against (a silent hang until COMMAND_TIMEOUT) is purely a UX papercut
    rather than a safety issue, that trade-off is fine -- worst case an
    undetected fullscreen program still just times out as before.
    """
    try:
        first_segment = re.split(r"&&|\|\||[;|]", raw_cmd, maxsplit=1)[0]
        tokens = shlex.split(first_segment)
    except ValueError:
        return False
    if not tokens:
        return False
    return os.path.basename(tokens[0]) in FULLSCREEN_PROGRAMS


async def route_fullscreen_to_itm(message: discord.Message, raw_cmd: str) -> None:
    """
    Entry point for a "!cmd"-style message that _is_fullscreen_command()
    flagged. Drops the user straight into Interactive Terminal Mode with
    the command already launched, rather than running it through
    run_command_pty where it would just sit silently until timeout.
    """
    user_id = message.author.id
    if user_id in itm_users:
        # Already in ITM (e.g. this got queued from before they entered
        # manually, or from a stdin-forward race) -- just forward it as
        # normal input to whatever's already running instead of trying to
        # re-enter a mode they're already in.
        session = pty_sessions.get(user_id)
        if session is not None and session.alive:
            cwd = get_user_cwd(user_id)
            session.write(f"cd {shlex.quote(cwd)} 2>/dev/null; {raw_cmd}\n")
        return
    await reply_or_send(
        message,
        f"🖥️ `{raw_cmd}` looks like a fullscreen program -- entering Interactive Terminal Mode automatically.",
    )
    await cmd_itm_enter(message, initial_cmd=raw_cmd)


async def execute_command(message: discord.Message, raw_cmd: str) -> None:
    user_id = message.author.id
    cwd = get_user_cwd(user_id)

    error = check_dangerous(raw_cmd, cwd, user_id)
    if error:
        log.info(f"Blocked command from {user_id}: {raw_cmd!r} ({error})")
        await message.reply(f"🚫 {error}")
        return

    if PTY_AVAILABLE and _is_fullscreen_command(raw_cmd):
        log.info(f"User {user_id} running fullscreen command via ITM: {raw_cmd!r} (cwd={cwd})")
        try:
            await route_fullscreen_to_itm(message, raw_cmd)
        except Exception:
            log.exception(f"Unhandled error auto-routing fullscreen command for user {user_id}")
            await message.reply("⚠️ An internal error occurred while entering Interactive Terminal Mode.")
        return

    log.info(f"User {user_id} running: {raw_cmd!r} (cwd={cwd})")
    try:
        if PTY_AVAILABLE:
            await run_command_pty(message, raw_cmd)
        else:
            await run_command_fallback(message, raw_cmd)
    except Exception:
        log.exception(f"Unhandled error running command for user {user_id}")
        await message.reply("⚠️ An internal error occurred while running that command.")


# --------------------------------------------------------------------------
# FILE OPERATIONS
# --------------------------------------------------------------------------

def _read_lines(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def _write_lines(path: str, lines: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def _parse_line_range(spec: str) -> Tuple[int, int]:
    """
    Parse a 1-based line-number argument that may be either a single line
    ("10") or an inclusive range ("10-20"), returning a (start, end) tuple
    of 1-based line numbers with start <= end. Raises ValueError on
    anything else, so callers can report a clean error message.
    """
    spec = spec.strip()
    m = re.match(r"^(\d+)-(\d+)$", spec)
    if m:
        start, end = int(m.group(1)), int(m.group(2))
    else:
        start = end = int(spec)  # raises ValueError for non-numeric input
    if start < 1 or end < 1 or end < start:
        raise ValueError("invalid line range")
    return start, end


def _snapshot_file(path: str) -> Optional[str]:
    """Return a file's current text content, or None if it doesn't exist yet."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _push_undo(user_id: int, path: str) -> None:
    """Snapshot `path`'s current content so termuc.undo can restore it later."""
    snapshot = _snapshot_file(path)
    stack = user_undo_stack.setdefault(user_id, [])
    stack.append((path, snapshot))
    if len(stack) > UNDO_STACK_LIMIT:
        stack.pop(0)


async def cmd_read(message: discord.Message, filename: str, start: Optional[str], end: Optional[str]) -> None:
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.isfile(path):
        await message.reply("```\nFile not found.\n```")
        return
    try:
        lines = _read_lines(path)
        if start is not None:
            s = int(start) - 1
            e = int(end) if end is not None else s + 1
            lines = lines[max(s, 0):e]
        text = "\n".join(lines)
        await deliver_output(await message.reply("```\nReading...\n```"), text)
    except Exception as e:
        await message.reply(f"⚠️ Error reading file: {e}")


async def cmd_write(message: discord.Message, filename: str, text: str) -> None:
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        _push_undo(message.author.id, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        await reply_or_send(message, f"✅ Wrote {len(text)} characters to `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error writing file: {e}")


async def cmd_append(message: discord.Message, filename: str, text: str, prepend: bool = False) -> None:
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        existing = ""
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()
        new_content = text + existing if prepend else existing + text
        _push_undo(message.author.id, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        action = "Prepended" if prepend else "Appended"
        await reply_or_send(message, f"✅ {action} to `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error updating file: {e}")


async def cmd_search(message: discord.Message, filename: str, pattern: str) -> None:
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.isfile(path):
        await message.reply("```\nFile not found.\n```")
        return
    try:
        regex = re.compile(pattern)
    except re.error as e:
        await message.reply(f"⚠️ Invalid regex: {e}")
        return
    try:
        lines = _read_lines(path)
        hits = [f"{i+1}: {line}" for i, line in enumerate(lines) if regex.search(line)]
        text = "\n".join(hits) if hits else "(no matches)"
        await deliver_output(await message.reply("```\nSearching...\n```"), text)
    except Exception as e:
        await message.reply(f"⚠️ Error searching file: {e}")


async def cmd_insertline(message: discord.Message, filename: str, line_no: str, text: str) -> None:
    """
    Insert `text` at `line_no`. `line_no` may also be a range like "10-20",
    in which case `text` is inserted as that many consecutive lines starting
    at the range's first position (e.g. "10-20" inserts 11 copies of `text`
    starting at line 10).
    """
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        start, end = _parse_line_range(line_no)
    except ValueError:
        await reply_or_send(message, "⚠️ Invalid line number or range (expected `N` or `N-M`).")
        return
    try:
        count = end - start + 1
        _push_undo(message.author.id, path)
        lines = _read_lines(path) if os.path.isfile(path) else []
        n = max(0, min(start - 1, len(lines)))
        for _ in range(count):
            lines.insert(n, text)
        _write_lines(path, lines)
        if count == 1:
            await reply_or_send(message, f"✅ Inserted line at position {n+1} in `{filename}`.")
        else:
            await reply_or_send(message, f"✅ Inserted {count} line(s) at positions {n+1}-{n+count} in `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error editing file: {e}")


async def cmd_replaceline(message: discord.Message, filename: str, line_no: str, text: str) -> None:
    """Replace `line_no` (or every line in a "10-20" range) with `text`."""
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        start, end = _parse_line_range(line_no)
    except ValueError:
        await reply_or_send(message, "⚠️ Invalid line number or range (expected `N` or `N-M`).")
        return
    try:
        lines = _read_lines(path)
        s, e = start - 1, end - 1
        if not (0 <= s < len(lines)) or not (0 <= e < len(lines)):
            await reply_or_send(message, "⚠️ Line number out of range.")
            return
        _push_undo(message.author.id, path)
        for i in range(s, e + 1):
            lines[i] = text
        _write_lines(path, lines)
        if start == end:
            await reply_or_send(message, f"✅ Replaced line {start} in `{filename}`.")
        else:
            await reply_or_send(message, f"✅ Replaced lines {start}-{end} in `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error editing file: {e}")


async def cmd_deleteline(message: discord.Message, filename: str, line_no: str) -> None:
    """Delete `line_no` (or every line in a "10-20" range, inclusive)."""
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        start, end = _parse_line_range(line_no)
    except ValueError:
        await reply_or_send(message, "⚠️ Invalid line number or range (expected `N` or `N-M`).")
        return
    try:
        lines = _read_lines(path)
        s, e = start - 1, end - 1
        if not (0 <= s < len(lines)) or not (0 <= e < len(lines)):
            await reply_or_send(message, "⚠️ Line number out of range.")
            return
        _push_undo(message.author.id, path)
        del lines[s:e + 1]
        _write_lines(path, lines)
        if start == end:
            await reply_or_send(message, f"✅ Deleted line {start} in `{filename}`.")
        else:
            await reply_or_send(message, f"✅ Deleted lines {start}-{end} in `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error editing file: {e}")


async def cmd_overwrite(message: discord.Message, filename: str, line_no: str, chars_to_replace: str, text: str) -> None:
    """
    Overwrite exactly `chars_to_replace` characters at the start of line
    `line_no` with `text`.

    Usage: !overwrite "file.py" "line" "characters_to_replace" "replacement"

    Example: a line `foobar` with chars_to_replace=3 and text="BAZ" becomes
    `BAZbar` -- the first 3 characters ("foo") are dropped and replaced with
    "BAZ" (the replacement text itself can be any length; it's not padded or
    truncated to match `chars_to_replace`).
    """
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        start, end = _parse_line_range(line_no)
    except ValueError:
        await reply_or_send(message, "⚠️ Invalid line number or range (expected `N` or `N-M`).")
        return
    try:
        chars_count = int(chars_to_replace)
        if chars_count < 0:
            await reply_or_send(message, "⚠️ characters_to_replace must be zero or positive.")
            return
        lines = _read_lines(path)
        s, e = start - 1, end - 1
        if not (0 <= s < len(lines)) or not (0 <= e < len(lines)):
            await reply_or_send(message, "⚠️ Line number out of range.")
            return
        _push_undo(message.author.id, path)
        first_line_actual_count = min(chars_count, len(lines[s]))  # for the single-line report below
        for i in range(s, e + 1):
            line = lines[i]
            n_count = min(chars_count, len(line))  # don't overrun the end of the line
            lines[i] = text + line[n_count:]
        _write_lines(path, lines)
        if start == end:
            await reply_or_send(message, f"✅ Replaced {first_line_actual_count} character(s) at the start of line {start} in `{filename}`.")
        else:
            await reply_or_send(message, f"✅ Replaced the first {chars_count} character(s) of lines {start}-{end} in `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error editing file: {e}")


async def cmd_undo(message: discord.Message) -> None:
    """Undo this user's most recent file edit (write/append/prepend/insertline/
    replaceline/deleteline/overwrite/replace/replaceall)."""
    user_id = message.author.id
    stack = user_undo_stack.get(user_id)
    if not stack:
        await reply_or_send(message, "ℹ️ Nothing to undo.")
        return
    path, snapshot = stack[-1]
    err = check_path_allowed(path, user_id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    try:
        if snapshot is None:
            if os.path.isfile(path):
                os.remove(path)
            await reply_or_send(message, f"✅ Undo: removed `{os.path.basename(path)}` (it did not exist before that edit).")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(snapshot)
            await reply_or_send(message, f"✅ Undo: reverted the last edit to `{os.path.basename(path)}`.")
        stack.pop()
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error undoing last edit: {e}")


async def cmd_copy(message: discord.Message, src: str, dst: str) -> None:
    user_id = message.author.id
    src_path = resolve_path(user_id, src)
    dst_path = resolve_path(user_id, dst)
    err = check_path_allowed(src_path, user_id) or check_path_allowed(dst_path, user_id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    if not os.path.exists(src_path):
        await reply_or_send(message, "```\nSource not found.\n```")
        return
    try:
        if os.path.isdir(src_path):
            shutil.copytree(src_path, dst_path)
        else:
            shutil.copy2(src_path, dst_path)
        await reply_or_send(message, f"✅ Copied `{src}` to `{dst}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error copying: {e}")


async def cmd_move(message: discord.Message, src: str, dst: str) -> None:
    user_id = message.author.id
    src_path = resolve_path(user_id, src)
    dst_path = resolve_path(user_id, dst)
    err = check_path_allowed(src_path, user_id) or check_path_allowed(dst_path, user_id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    if not os.path.exists(src_path):
        await reply_or_send(message, "```\nSource not found.\n```")
        return
    try:
        shutil.move(src_path, dst_path)
        await reply_or_send(message, f"✅ Moved `{src}` to `{dst}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error moving: {e}")


async def cmd_rename(message: discord.Message, src: str, new_name: str) -> None:
    """Rename a file/directory in place. `new_name` is a bare name, not a path."""
    user_id = message.author.id
    src_path = resolve_path(user_id, src)
    dst_path = os.path.join(os.path.dirname(src_path), new_name)
    err = check_path_allowed(src_path, user_id) or check_path_allowed(dst_path, user_id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    if not os.path.exists(src_path):
        await reply_or_send(message, "```\nSource not found.\n```")
        return
    try:
        os.rename(src_path, dst_path)
        await reply_or_send(message, f"✅ Renamed `{src}` to `{new_name}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error renaming: {e}")


async def cmd_replace(message: discord.Message, filename: str, pattern: str, replacement: str, all_matches: bool) -> None:
    """Regex find/replace within a file. termuc.replace touches only the first
    match; termuc.replaceall touches every match."""
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await reply_or_send(message, f"🚫 {err}")
        return
    if not os.path.isfile(path):
        await reply_or_send(message, "```\nFile not found.\n```")
        return
    try:
        regex = re.compile(pattern)
    except re.error as e:
        await reply_or_send(message, f"⚠️ Invalid regex: {e}")
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        new_content, count = regex.subn(replacement, content, count=0 if all_matches else 1)
        if count == 0:
            await reply_or_send(message, "ℹ️ No match found; file unchanged.")
            return
        _push_undo(message.author.id, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        await reply_or_send(message, f"✅ Replaced {count} match(es) in `{filename}`.")
    except Exception as e:
        await reply_or_send(message, f"⚠️ Error replacing text: {e}")


async def cmd_lines(message: discord.Message, filename: str) -> None:
    """Report the line count of a file."""
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.isfile(path):
        await message.reply("```\nFile not found.\n```")
        return
    try:
        count = len(_read_lines(path))
        await message.reply(f"```\n{count} line(s) in {filename}\n```")
    except Exception as e:
        await message.reply(f"⚠️ Error reading file: {e}")


async def cmd_stat(message: discord.Message, filename: str) -> None:
    """Show size, type, permissions, and timestamps for a file or directory."""
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.exists(path):
        await message.reply("```\nPath not found.\n```")
        return
    try:
        st = os.stat(path)
        if os.path.islink(path):
            kind = "symlink"
        elif os.path.isdir(path):
            kind = "directory"
        else:
            kind = "file"
        text = (
            f"Path:        {path}\n"
            f"Type:        {kind}\n"
            f"Size:        {st.st_size} bytes\n"
            f"Permissions: {stat.filemode(st.st_mode)}\n"
            f"Modified:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}\n"
            f"Changed:     {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_ctime))}"
        )
        await message.reply(f"```\n{text}\n```")
    except Exception as e:
        await message.reply(f"⚠️ Error getting file info: {e}")


def _build_tree(path: str, prefix: str, depth: int, max_depth: int, lines: list) -> None:
    if depth > max_depth:
        return
    try:
        entries = sorted(os.listdir(path))
    except Exception:
        return
    entries = [e for e in entries if not e.startswith(".")]
    for i, name in enumerate(entries):
        full = os.path.join(path, name)
        last = i == len(entries) - 1
        connector = "└── " if last else "├── "
        is_dir = os.path.isdir(full)
        lines.append(prefix + connector + name + ("/" if is_dir else ""))
        if is_dir:
            extension = "    " if last else "│   "
            _build_tree(full, prefix + extension, depth + 1, max_depth, lines)


async def cmd_tree(message: discord.Message, dirname: str, max_depth: Optional[int]) -> None:
    """Print a directory tree (hidden entries excluded), default depth 3."""
    user_id = message.author.id
    path = resolve_path(user_id, dirname) if dirname not in (None, "", ".") else get_user_cwd(user_id)
    err = check_path_allowed(path, user_id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.isdir(path):
        await message.reply("```\nNot a directory.\n```")
        return
    depth = max_depth if max_depth and max_depth > 0 else 3
    try:
        lines = [os.path.basename(path.rstrip("/")) or path]
        _build_tree(path, "", 1, depth, lines)
        text = "\n".join(lines)
        await deliver_output(await message.reply("```\nBuilding tree...\n```"), text)
    except Exception as e:
        await message.reply(f"⚠️ Error building tree: {e}")


async def cmd_upload(message: discord.Message) -> None:
    if not message.attachments:
        await message.reply("⚠️ Attach a file to your message to upload it.")
        return
    cwd = get_user_cwd(message.author.id)
    saved = []
    for attachment in message.attachments:
        dest = os.path.join(cwd, attachment.filename)
        err = check_path_allowed(dest, message.author.id)
        if err:
            await message.reply(f"🚫 {err} (`{attachment.filename}`)")
            continue
        try:
            await attachment.save(dest)
            saved.append(attachment.filename)
        except Exception as e:
            await message.reply(f"⚠️ Failed to save `{attachment.filename}`: {e}")
    if saved:
        await message.reply(f"✅ Saved to `{cwd}`: " + ", ".join(f"`{n}`" for n in saved))


async def cmd_download(message: discord.Message, filename: str) -> None:
    path = resolve_path(message.author.id, filename)
    err = check_path_allowed(path, message.author.id)
    if err:
        await message.reply(f"🚫 {err}")
        return
    if not os.path.isfile(path):
        await message.reply("```\nFile not found.\n```")
        return
    size = os.path.getsize(path)
    if size > MAX_DOWNLOAD_BYTES:
        await message.reply(f"⚠️ File is {size} bytes, which exceeds the {MAX_DOWNLOAD_BYTES} byte limit.")
        return
    try:
        await message.reply(file=discord.File(path, filename=os.path.basename(path)))
    except Exception as e:
        await message.reply(f"⚠️ Failed to send file: {e}")


# --------------------------------------------------------------------------
# PER-USER COMMAND QUEUE
# --------------------------------------------------------------------------

def ensure_worker(user_id: int) -> None:
    """Lazily create a serial worker so a user's commands never run concurrently."""
    if user_id not in user_queues:
        user_queues[user_id] = asyncio.Queue()
        user_workers[user_id] = asyncio.create_task(_user_worker(user_id))


async def _user_worker(user_id: int) -> None:
    queue = user_queues[user_id]
    while True:
        job = await queue.get()
        try:
            await job()
        except Exception:
            log.exception(f"Unhandled error in queued job for user {user_id}")
        finally:
            queue.task_done()


async def enqueue(user_id: int, job) -> None:
    ensure_worker(user_id)
    await user_queues[user_id].put(job)


# --------------------------------------------------------------------------
# DISCORD CLIENT
# --------------------------------------------------------------------------

intents = discord.Intents.default()
intents.message_content = True
# Note: intents.members is intentionally NOT enabled -- it's a privileged
# intent that must be toggled on in the Discord Developer Portal, and it
# isn't needed here since message.author.roles is already populated on
# guild message events without it.

bot = discord.Client(intents=intents)

HELP_TEXT = """"
```text
Discord Remote Terminal Bot
============================
Made By Ribi(meeeee)

SHELL COMMANDS
--------------
Commands beginning with `termuc.` are built-in bot commands. Most also have
a short alias, shown in [brackets] below -- e.g. termuc.r works exactly
like termuc.read.

To execute Linux/Termux shell commands, use:
    termuc.cmd <command>

Everything after `termuc.cmd` is sent directly to the shell.

Examples:
    termuc.cmd ls
    termuc.cmd pwd
    termuc.cmd python3 bot.py

FULL COMMAND REFERENCE
-----------------------

-- Shell / session --
termuc.cmd <command>                         [c]
    Run a shell command, or send input to your current foreground program.
termuc.itm                                   [i]
    Enter Interactive Terminal Mode: raw keyboard passthrough to your pty
    so full-screen programs (nano, vim, htop, less, etc.) work properly.
termuc.exititm                               [ei]
    Leave Interactive Terminal Mode. Your shell session keeps running.
termuc.pwd
    Show your current working directory.

-- File transfer --
termuc.upload
    Attach a file to your message to save it into your current directory.
termuc.download <file>                       [dw]
    Download a file from your current directory.

-- Read / write --
termuc.read <file> [start] [end]             [r]
    Show file contents, optionally limited to a line or line range.
termuc.write <file> <text>                   [w]
    Overwrite a file with <text>. Undoable with termuc.undo.
termuc.append <file> <text>                  [a]
    Append <text> to the end of a file. Undoable with termuc.undo.
termuc.prepend <file> <text>                 [pp]
    Prepend <text> to the start of a file. Undoable with termuc.undo.
termuc.search <file> <regex>                 [s]
    List every line in a file matching a regex pattern.
termuc.lines <file>                          [ln]
    Show a file's line count.
termuc.stat <file>                           [st]
    Show size, type, permissions, and timestamps for a file or directory.

-- Line editing (<n> is a line number, or a range like "10-20") --
termuc.insertline <file> <n> <text>          [il]
    Insert <text> at line <n>. With a range, <text> is inserted that many
    times, consecutively, starting at the range's first line.
termuc.replaceline <file> <n> <text>         [rl]
    Replace line <n> (or every line in a range) with <text>.
termuc.deleteline <file> <n>                 [dl]
    Delete line <n> (or every line in a range, inclusive).
termuc.overwrite <file> <n> <count> <text>   [ow]
    Overwrite the first <count> characters of line <n> (or every line in
    a range) with <text>.
termuc.replace <file> <pattern> <repl>       [rp]
    Replace only the first regex match in a file. Undoable with termuc.undo.
termuc.replaceall <file> <pattern> <repl>    [rpa]
    Replace every regex match in a file. Undoable with termuc.undo.
termuc.undo                                  [u]
    Undo your most recent file edit (write/append/prepend/insertline/
    replaceline/deleteline/overwrite/replace/replaceall).

-- File management --
termuc.copy <src> <dst>                      [cp]
    Copy a file or directory.
termuc.move <src> <dst>                      [mv]
    Move a file or directory.
termuc.rename <src> <new_name>               [ren]
    Rename a file or directory in place (<new_name> is a bare name).
termuc.tree [dir] [depth]                    [tr]
    Print a directory tree (hidden entries excluded). [dir] defaults to
    your current directory, [depth] defaults to 3.

-- Help --
termuc.helptermuc                            [ht]
    Show this full command reference.
termuc.help <command>                        [h]
    Show detailed usage for a single command.
```
"""


# --------------------------------------------------------------------------
# SHORT ALIASES & PER-COMMAND HELP
# --------------------------------------------------------------------------

# alias -> canonical command name. Aliases are resolved by _resolve_alias()
# before any other dispatch logic runs, so every existing (and new) command
# above keeps working exactly as before under its full name.
ALIASES: Dict[str, str] = {
    "c": "cmd",
    "r": "read",
    "w": "write",
    "a": "append",
    "pp": "prepend",
    "s": "search",
    "il": "insertline",
    "rl": "replaceline",
    "dl": "deleteline",
    "ow": "overwrite",
    "u": "undo",
    "cp": "copy",
    "mv": "move",
    "ren": "rename",
    "rpa": "replaceall",
    "rp": "replace",
    "ln": "lines",
    "st": "stat",
    "tr": "tree",
    "dw": "download",
    "h": "help",
    "i": "itm",
    "ei": "exititm",
    "ht": "helptermuc",
}

# canonical command name -> detailed usage text for termuc.help <command>.
COMMAND_DETAILS: Dict[str, str] = {
    "cmd": "termuc.cmd <command>\nAlias: termuc.c\nRun a shell command in your persistent session, or send input to a still-running foreground program.",
    "itm": "termuc.itm\nAlias: termuc.i\nEnter Interactive Terminal Mode: raw keyboard passthrough to your pty, for full-screen programs (nano, vim, htop, etc.).",
    "exititm": "termuc.exititm\nAlias: termuc.ei\nLeave Interactive Terminal Mode. Your shell session keeps running in the background.",
    "pwd": "termuc.pwd\nShow your current working directory.",
    "upload": "termuc.upload\nAttach a file to your message to save it into your current directory.",
    "download": "termuc.download <file>\nAlias: termuc.dw\nDownload a file from your current directory.",
    "read": "termuc.read <file> [start] [end]\nAlias: termuc.r\nShow file contents, optionally limited to a line range.",
    "write": "termuc.write <file> <text>\nAlias: termuc.w\nOverwrite a file with <text>. Undoable with termuc.undo.",
    "append": "termuc.append <file> <text>\nAlias: termuc.a\nAppend <text> to the end of a file. Undoable with termuc.undo.",
    "prepend": "termuc.prepend <file> <text>\nAlias: termuc.pp\nPrepend <text> to the start of a file. Undoable with termuc.undo.",
    "search": "termuc.search <file> <regex>\nAlias: termuc.s\nSearch a file for a regex pattern and list matching lines.",
    "insertline": "termuc.insertline <file> <n> <text>\nAlias: termuc.il\n<n> may be a single line (e.g. \"10\") or a range (e.g. \"10-20\"), in which\ncase <text> is inserted that many times, consecutively, starting at the\nfirst line of the range. Undoable with termuc.undo.",
    "replaceline": "termuc.replaceline <file> <n> <text>\nAlias: termuc.rl\n<n> may be a single line or a range (e.g. \"10-20\"); every line in the\nrange is replaced with <text>. Undoable with termuc.undo.",
    "deleteline": "termuc.deleteline <file> <n>\nAlias: termuc.dl\n<n> may be a single line or a range (e.g. \"10-20\"); every line in the\nrange is deleted. Undoable with termuc.undo.",
    "overwrite": "termuc.overwrite <file> <n> <count> <text>\nAlias: termuc.ow\nOverwrite the first <count> characters of line <n> with <text>. <n> may\nbe a range (e.g. \"10-20\") to apply this to every line in the range.\nUndoable with termuc.undo.",
    "undo": "termuc.undo\nAlias: termuc.u\nUndo your most recent file edit (write/append/prepend/insertline/\nreplaceline/deleteline/overwrite/replace/replaceall). One level deep per edit.",
    "copy": "termuc.copy <src> <dst>\nAlias: termuc.cp\nCopy a file or directory.",
    "move": "termuc.move <src> <dst>\nAlias: termuc.mv\nMove a file or directory.",
    "rename": "termuc.rename <src> <new_name>\nAlias: termuc.ren\nRename a file or directory in place. <new_name> is a bare name, not a path.",
    "replace": "termuc.replace <file> <pattern> <replacement>\nAlias: termuc.rp\nReplace only the first regex match in a file. Undoable with termuc.undo.",
    "replaceall": "termuc.replaceall <file> <pattern> <replacement>\nAlias: termuc.rpa\nReplace every regex match in a file. Undoable with termuc.undo.",
    "lines": "termuc.lines <file>\nAlias: termuc.ln\nShow a file's line count.",
    "stat": "termuc.stat <file>\nAlias: termuc.st\nShow size, type, permissions, and timestamps for a file or directory.",
    "tree": "termuc.tree [dir] [depth]\nAlias: termuc.tr\nPrint a directory tree (hidden entries excluded). [dir] defaults to your\ncurrent directory, [depth] defaults to 3.",
    "help": "termuc.help <command>\nAlias: termuc.h\nShow this kind of detailed usage for a specific command.",
    "helptermuc": "termuc.helptermuc\nAlias: termuc.ht\nShow the full command reference.",
}


def _resolve_alias(content: str) -> str:
    """
    If `content` is a termuc.<alias> command, rewrite it to the equivalent
    canonical termuc.<command> form (e.g. "termuc.r file.txt" becomes
    "termuc.read file.txt") so every existing dispatch check below keeps
    working unchanged. Anything that isn't a recognized alias -- including
    raw ITM keystrokes, which never start with PREFIX -- passes through untouched.
    """
    if not content.startswith(PREFIX):
        return content
    rest = content[len(PREFIX):]
    m = re.match(r"^(\S+)(.*)$", rest, re.DOTALL)
    if not m:
        return content
    word, remainder = m.group(1), m.group(2)
    canonical = ALIASES.get(word.lower())
    if canonical is None:
        return content
    return f"{PREFIX}{canonical}{remainder}"


async def cmd_help_detail(message: discord.Message, name: str) -> None:
    """Handle termuc.help <command>: show detailed usage for one command."""
    key = name.strip().lower()
    if key.startswith(PREFIX):
        key = key[len(PREFIX):]
    key = ALIASES.get(key, key)
    detail = COMMAND_DETAILS.get(key)
    if detail:
        await message.reply(f"```text\n{detail}\n```")
    else:
        await message.reply(f"ℹ️ No detailed help found for `{name}`. Use `{PREFIX}helptermuc` to see all commands.")


async def send_help_text(message: discord.Message) -> None:
    """
    Send the full HELP_TEXT. Discord hard-caps messages at 2000 characters,
    and the full command reference now exceeds that, so fall back to a
    .txt attachment (same approach deliver_output uses for long command
    output) instead of letting the reply fail outright.
    """
    if len(HELP_TEXT) <= DISCORD_MSG_LIMIT:
        await message.reply(HELP_TEXT)
        return
    body = HELP_TEXT.strip().strip('"').strip()
    if body.startswith("```text"):
        body = body[len("```text"):]
    if body.endswith("```"):
        body = body[:-3]
    buf = io.BytesIO(body.strip().encode("utf-8", errors="ignore"))
    file = discord.File(fp=buf, filename="termuc_help.txt")
    try:
        await message.reply(
            "📖 Full command reference (too long for a single Discord message) -- see attached file.",
            file=file,
        )
    except discord.HTTPException as e:
        log.warning(f"Failed to send help file: {e}")


@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (PTY support: {PTY_AVAILABLE}, shell: {SHELL_PATH})")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    if message.channel.id not in CHANNEL_IDS:
        return

    content = _resolve_alias(message.content)
    user_id = message.author.id
    user_members[user_id] = message.author

    # Interactive Terminal Mode takes priority over the normal "!"-prefixed
    # command gate below, since raw terminal input (shell commands, typed
    # text for input()/io.read(), etc.) usually won't start with "!". Every
    # message from a user in ITM is routed straight to their pty as raw
    # input instead of being parsed as a bot command, with the sole
    # exception of f"{PREFIX}exititm" itself.
    if user_id in itm_users:
        if not has_permission(message.author):
            # Shouldn't normally happen (ITM can only be entered by a
            # permitted user), but never touch someone's pty without
            # re-checking permission first.
            itm_users.discard(user_id)
            return

        try:
            if content.strip().lower() == f"{PREFIX}exititm":
                await _safe_delete(message)
                await cmd_itm_exit(message)
            else:
                session = pty_sessions.get(user_id)
                if session is None or not session.alive:
                    itm_users.discard(user_id)
                    task = itm_tasks.pop(user_id, None)
                    if task is not None:
                        task.cancel()
                    itm_screens.pop(user_id, None)
                    itm_messages.pop(user_id, None)
                    itm_last_render.pop(user_id, None)
                    await _safe_delete(message)
                    await reply_or_send(message, "⚠️ Your terminal session ended. Interactive Terminal Mode has been closed.")
                else:
                    # Secondary safety net: check_dangerous only ever ran
                    # for `!cmd`, so a user in ITM could otherwise type a
                    # blocked command straight into the live shell and
                    # bypass it entirely. Re-run the same layered checks
                    # here for anything that looks like a plain typed
                    # command line -- skip pure key-token messages (e.g.
                    # "?up", "?ctrl+c") and in-progress "?raw ..." input,
                    # neither of which is a complete shell command.
                    stripped = content.strip()
                    tokens = stripped.split()
                    is_key_tokens = bool(tokens) and all(
                        t.startswith(ITM_KEY_PREFIX) and t[len(ITM_KEY_PREFIX):].upper() in _ITM_KEY_MAP
                        for t in tokens
                    )
                    is_raw_partial = stripped.lower().startswith(f"{ITM_KEY_PREFIX}raw")
                    is_plain_command_line = bool(stripped) and not is_key_tokens and not is_raw_partial
                    if is_plain_command_line:
                        danger = check_dangerous(stripped, get_user_cwd(user_id), user_id)
                        if danger:
                            log.info(f"Blocked ITM input from {user_id}: {stripped!r} ({danger})")
                            await _safe_delete(message)
                            await reply_or_send(message, f"🚫 {danger} (blocked in Interactive Terminal Mode)")
                            return

                    # FIX (ITM "output appends instead of replacing"): a
                    # plain top-level command line should clear the visible
                    # screen first so only *that* command's output is shown,
                    # instead of real-terminal scrollback semantics. Skip
                    # this when a full-screen curses program (nano/htop/
                    # vim/less) currently owns the alternate screen buffer
                    # (screen.alt_saved_grid is not None) -- otherwise every
                    # keystroke sent to it would blank its display.
                    screen_for_reset = itm_screens.get(user_id)
                    if (
                        is_plain_command_line
                        and screen_for_reset is not None
                        and screen_for_reset.alt_saved_grid is None
                    ):
                        screen_for_reset._erase_display(2)
                        screen_for_reset.cur_row = screen_for_reset.cur_col = 0

                    session.write(_translate_itm_input(content))

                    # Force an immediate refresh right after sending input,
                    # instead of only relying on the background _itm_loop's
                    # own poll timing to notice the change. This guarantees
                    # you see the result of what you just typed even if
                    # that loop is delayed for any reason.
                    #
                    # A single 0.2s wait followed by one read_available()
                    # call races the shell: most commands (and anything
                    # that has to fork/exec, hit disk, etc.) simply haven't
                    # produced output yet at the 0.2s mark, so that one
                    # read comes back empty and this "immediate refresh"
                    # silently does nothing. Poll repeatedly instead, for
                    # up to ~1.5s total, and stop as soon as new output
                    # actually shows up.
                    new_data = b""
                    for _ in range(15):  # 15 * 0.1s = ~1.5s max
                        await asyncio.sleep(0.1)
                        if not session.alive:
                            break
                        chunk = session.read_available()
                        if chunk:
                            new_data += chunk
                            break
                    screen2 = itm_screens.get(user_id)
                    if screen2 is not None and session.alive:
                        if new_data:
                            _safe_feed(screen2, new_data)
                            replies2 = screen2.take_pending_replies()
                            if replies2:
                                session.write(replies2)
                        rendered2 = screen2.render()
                        msg2 = itm_messages.get(user_id)
                        if msg2 is not None and rendered2 != itm_last_render.get(user_id):
                            delivered2 = await safe_edit(msg2, _render_itm(screen2))
                            # As in _itm_loop: only record this render as
                            # "shown" if the edit actually succeeded, so a
                            # dropped edit (rate limit, etc.) gets retried
                            # by the next _itm_loop tick instead of being
                            # treated as delivered forever.
                            if delivered2:
                                itm_last_render[user_id] = rendered2
                    await _safe_delete(message)
        except Exception:
            log.exception(f"Error handling ITM input from user {user_id}")
            await _safe_delete(message)
            await reply_or_send(message, "⚠️ An internal error occurred handling your terminal input.")
        return

    if not message.content.startswith(PREFIX):
        return

    if not has_permission(message.author):
        await message.reply("🚫 You don't have permission to use this bot.")
        return

    try:
        if content.strip().lower() == f"{PREFIX}itm":
            session = pty_sessions.get(user_id)
            if PTY_AVAILABLE and session is not None and session.alive and session.busy:
                await message.reply(
                    "⚠️ You have a command running in the foreground right now. "
                    "Wait for it to finish (or keep sending it input via `!cmd`) "
                    "before starting Interactive Terminal Mode."
                )
            else:
                # Delete the "?itm"/"termuc.itm" trigger message itself too
                # -- it's about to be replaced by the live ITM screen.
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message: cmd_itm_enter(m))

        elif content.startswith(f"{PREFIX}cmd "):
            raw_cmd = content[len(f"{PREFIX}cmd "):].strip()
            if not raw_cmd:
                return
            session = pty_sessions.get(user_id)
            if PTY_AVAILABLE and session is not None and session.alive and session.busy:
                # A program launched by a previous !cmd (e.g. python, node,
                # bash, an interactive script using input()/read) is still
                # running in the foreground. Forward this message straight
                # to it as a line of stdin instead of queuing it as a new
                # command -- this is what lets the running program receive
                # multiple sequential inputs. Live output streaming (in
                # run_command_pty) keeps running unaffected and will pick up
                # whatever the program prints in response.
                #
                # Secondary safety net: this bypasses the normal
                # execute_command() -> check_dangerous() path, so re-run the
                # same layered checks here too. This can false-positive on
                # ordinary program input that happens to contain a blocked
                # word (e.g. answering a prompt with a filename like
                # "rm_old.txt") -- an accepted trade-off given the
                # alternative of a completely unchecked shell-input path.
                danger = check_dangerous(raw_cmd, get_user_cwd(user_id), user_id)
                if danger:
                    log.info(f"Blocked stdin-forward from {user_id}: {raw_cmd!r} ({danger})")
                    await message.reply(f"🚫 {danger}")
                    return
                session.write(raw_cmd + "\n")
            else:
                await enqueue(user_id, lambda m=message, c=raw_cmd: execute_command(m, c))

        elif content.strip() == f"{PREFIX}pwd":
            await start_cmd_message(message, user_id, f"```\n{get_user_cwd(user_id)}\n```")

        elif content.strip() == f"{PREFIX}upload" or (content.startswith(f"{PREFIX}upload") and message.attachments):
            # BUGFIX: this used to check the literal "!upload" instead of
            # f"{PREFIX}upload" ("termuc.upload"), so it never matched the
            # command as actually documented/used anywhere else in the bot.
            await enqueue(user_id, lambda m=message: cmd_upload(m))

        elif content.startswith(f"{PREFIX}download "):
            args = shlex.split(content[len(f"{PREFIX}download "):])
            if args:
                await enqueue(user_id, lambda m=message, f=args[0]: cmd_download(m, f))

        elif content.startswith(f"{PREFIX}read "):
            args = shlex.split(content[len(f"{PREFIX}read "):])
            if args:
                filename, start, end = args[0], (args[1] if len(args) > 1 else None), (args[2] if len(args) > 2 else None)
                await enqueue(user_id, lambda m=message, f=filename, s=start, e=end: cmd_read(m, f, s, e))

        elif content.startswith(f"{PREFIX}write "):
            parts = content[len(f"{PREFIX}write "):].split(maxsplit=1)
            if parts:
                filename, text = parts[0], (parts[1] if len(parts) > 1 else "")
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, t=text: cmd_write(m, f, t))

        elif content.startswith(f"{PREFIX}append "):
            parts = content[len(f"{PREFIX}append "):].split(maxsplit=1)
            if parts:
                filename, text = parts[0], (parts[1] if len(parts) > 1 else "")
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, t=text: cmd_append(m, f, t, False))

        elif content.startswith(f"{PREFIX}prepend "):
            parts = content[len(f"{PREFIX}prepend "):].split(maxsplit=1)
            if parts:
                filename, text = parts[0], (parts[1] if len(parts) > 1 else "")
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, t=text: cmd_append(m, f, t, True))

        elif content.startswith(f"{PREFIX}search "):
            parts = content[len(f"{PREFIX}search "):].split(maxsplit=1)
            if len(parts) == 2:
                filename, pattern = parts
                await enqueue(user_id, lambda m=message, f=filename, p=pattern: cmd_search(m, f, p))

        elif content.startswith(f"{PREFIX}insertline "):
            parts = content[len(f"{PREFIX}insertline "):].split(maxsplit=2)
            if len(parts) >= 2:
                filename, line_no, text = parts[0], parts[1], (parts[2] if len(parts) > 2 else "")
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, n=line_no, t=text: cmd_insertline(m, f, n, t))

        elif content.startswith(f"{PREFIX}replaceline "):
            parts = content[len(f"{PREFIX}replaceline "):].split(maxsplit=2)
            if len(parts) >= 2:
                filename, line_no, text = parts[0], parts[1], (parts[2] if len(parts) > 2 else "")
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, n=line_no, t=text: cmd_replaceline(m, f, n, t))

        elif content.startswith(f"{PREFIX}deleteline "):
            parts = content[len(f"{PREFIX}deleteline "):].split(maxsplit=1)
            if len(parts) == 2:
                filename, line_no = parts
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, f=filename, n=line_no: cmd_deleteline(m, f, n))

        elif content.startswith(f"{PREFIX}overwrite "):
            # Syntax: !overwrite "file" "line" "characters_to_replace" "replacement"
            parts = content[len(f"{PREFIX}overwrite "):].split(maxsplit=3)
            if len(parts) >= 3:
                filename, line_no, chars_to_replace = parts[0], parts[1], parts[2]
                text = parts[3] if len(parts) > 3 else ""
                await _safe_delete(message)
                await enqueue(
                    user_id,
                    lambda m=message, f=filename, n=line_no, c=chars_to_replace, t=text: cmd_overwrite(m, f, n, c, t),
                )

        elif content.strip() == f"{PREFIX}undo":
            await _safe_delete(message)
            await enqueue(user_id, lambda m=message: cmd_undo(m))

        elif content.startswith(f"{PREFIX}copy "):
            args = shlex.split(content[len(f"{PREFIX}copy "):])
            if len(args) >= 2:
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, s=args[0], d=args[1]: cmd_copy(m, s, d))

        elif content.startswith(f"{PREFIX}move "):
            args = shlex.split(content[len(f"{PREFIX}move "):])
            if len(args) >= 2:
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, s=args[0], d=args[1]: cmd_move(m, s, d))

        elif content.startswith(f"{PREFIX}rename "):
            args = shlex.split(content[len(f"{PREFIX}rename "):])
            if len(args) >= 2:
                await _safe_delete(message)
                await enqueue(user_id, lambda m=message, s=args[0], d=args[1]: cmd_rename(m, s, d))

        elif content.startswith(f"{PREFIX}replaceall "):
            parts = content[len(f"{PREFIX}replaceall "):].split(maxsplit=2)
            if len(parts) == 3:
                filename, pattern, replacement = parts
                await _safe_delete(message)
                await enqueue(
                    user_id,
                    lambda m=message, f=filename, p=pattern, r=replacement: cmd_replace(m, f, p, r, True),
                )

        elif content.startswith(f"{PREFIX}replace "):
            parts = content[len(f"{PREFIX}replace "):].split(maxsplit=2)
            if len(parts) == 3:
                filename, pattern, replacement = parts
                await _safe_delete(message)
                await enqueue(
                    user_id,
                    lambda m=message, f=filename, p=pattern, r=replacement: cmd_replace(m, f, p, r, False),
                )

        elif content.startswith(f"{PREFIX}lines "):
            args = shlex.split(content[len(f"{PREFIX}lines "):])
            if args:
                await enqueue(user_id, lambda m=message, f=args[0]: cmd_lines(m, f))

        elif content.startswith(f"{PREFIX}stat "):
            args = shlex.split(content[len(f"{PREFIX}stat "):])
            if args:
                await enqueue(user_id, lambda m=message, f=args[0]: cmd_stat(m, f))

        elif content.strip() == f"{PREFIX}tree" or content.startswith(f"{PREFIX}tree "):
            rest = content[len(f"{PREFIX}tree"):].strip()
            args = shlex.split(rest) if rest else []
            dirname = args[0] if len(args) >= 1 else "."
            depth = None
            if len(args) >= 2:
                try:
                    depth = int(args[1])
                except ValueError:
                    depth = None
            await enqueue(user_id, lambda m=message, d=dirname, dep=depth: cmd_tree(m, d, dep))

        elif content.strip() == f"{PREFIX}help":
            await message.reply(f"ℹ️ Usage: `{PREFIX}help <command>` -- e.g. `{PREFIX}help replaceline`.")

        elif content.startswith(f"{PREFIX}help "):
            args = shlex.split(content[len(f"{PREFIX}help "):])
            if args:
                await cmd_help_detail(message, args[0])

        elif content.strip() == f"{PREFIX}helptermuc":
            await send_help_text(message)

    except Exception:
        log.exception(f"Error dispatching command from user {user_id}")
        await message.reply("⚠️ An internal error occurred handling that command.")


@bot.event
async def on_close():
    # NOTE: discord.py does not guarantee this event fires on every shutdown
    # path -- the `finally` block around bot.run() below is what actually
    # guarantees PTY child processes get cleaned up.
    close_all_pty_sessions()


if __name__ == "__main__":
    try:
        bot.run(TOKEN)
    finally:
        close_all_pty_sessions()