#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""newrole-batch: run many commands under an SELinux role that requires
`newrole` (PAM password prompt), authenticating exactly once.

Modes
  local   run on the machine where `newrole` lives (needs a real login user)
  ssh     run on a remote host: this file is streamed over ssh stdin, nothing
          is written to the target's disk, password never touches argv/env
  serve   internal JSON-lines protocol (used by `ssh`, usable as a library
          back end); line 1 = JSON config, line 2 = raw password,
          then one JSON request per line.

Requirements: Python >= 3.6, standard library only (no packages to install).

Design notes
  * One pty, one `newrole`, one persistent shell inside the new context.
    Every command is shipped base64-encoded and framed by a per-session
    random marker, so quoting/newlines/binary-ish output cannot desync it.
  * The password is sent exactly once and is never retried: a wrong password
    costs one PAM failure (pam_faillock safe), then we abort.
  * After login the actual SELinux context is read back from
    /proc/self/attr/current and compared with what was requested; mismatch
    aborts (fail closed).
  * Password only travels by file(0600)/fd/stdin/tty prompt. Never argv/env.
    Python cannot guarantee memory zeroisation; we wipe our bytearray, disable
    core dumps and ptrace-style access (PR_SET_DUMPABLE=0) as best effort.
"""
import argparse
import base64
import ctypes
import errno
import fcntl
import getpass
import hashlib
import json
import os
import pty
import pwd
import re
import resource
import select
import shlex
import signal
import stat
import subprocess
import sys
import syslog
import termios
import time

VERSION = "1.0.0"

EXIT_OK, EXIT_CMDFAIL, EXIT_USAGE, EXIT_AUTH, EXIT_SESSION, EXIT_TIMEOUT = 0, 1, 2, 3, 4, 5

NEWROLE = "/usr/bin/newrole"
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CHUNK = 2400                      # b64 chars per tty line (tty canonical limit is 4095)
PROMPT_RE = re.compile(rb"[Pp]assword[^\r\n]{0,40}: ?$")

# Bootstrap a controller streams over a bare `python3 -c SERVE_BOOT serve` invocation: it reads
# one base64 line (this whole file) from stdin and execs it, so `serve()` below then reads the
# cfg/password lines that follow. Used for the first hop (RemoteSession) and for every further
# hop opened with NewroleSession.nest()/RemoteSession.nest().
SERVE_BOOT = "import sys,base64;exec(base64.b64decode(sys.stdin.buffer.readline()))"


class NewroleError(Exception):
    pass


class AuthError(NewroleError):
    pass


class ContextError(NewroleError):
    pass


class SessionDead(NewroleError):
    def __init__(self, msg, partial=b""):
        NewroleError.__init__(self, msg)
        self.partial = partial


class CommandTimeout(NewroleError):
    pass


class NestEnded(NewroleError):
    """The nested ssh job already finished (its completion marker was consumed), so the pty
    is back in its normal settings and there is nothing left to abort or drain."""


class _Timeout(Exception):
    pass


def raise_event_error(ev):
    """Raise the exception matching an {"event": "error"} reply from a serve() peer."""
    exc = {"auth": AuthError, "context": ContextError, "timeout": CommandTimeout}.get(
        ev.get("kind"), NewroleError)
    raise exc(ev.get("message"))


def remote_command(python, path):
    """Shell text run by ssh on the target to start serve(); both parts are quoted."""
    if path:
        return "%s %s serve" % (shlex.quote(python), shlex.quote(path))
    return "%s -c %s serve" % (shlex.quote(python), shlex.quote(SERVE_BOOT))


def harden_process():
    """Best-effort: no core dumps, not dumpable/ptrace-able, private umask."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)      # PR_SET_DUMPABLE = 0
    except Exception:
        pass
    os.umask(0o077)


def wipe(ba):
    if isinstance(ba, bytearray):
        for i in range(len(ba)):
            ba[i] = 0


class Audit(object):
    """syslog (authpriv) trail: session start/end, auth failures, command hashes."""

    def __init__(self, mode="hash", enabled=True):
        self.mode, self.enabled = mode, enabled
        if enabled:
            syslog.openlog("newrole-batch", syslog.LOG_PID, syslog.LOG_AUTHPRIV)

    def log(self, msg, prio=syslog.LOG_INFO):
        if self.enabled:
            try:
                syslog.syslog(prio, msg.replace("\n", " ")[:900])
            except Exception:
                pass

    def command(self, idx, cmd):
        if self.mode == "none":
            return
        if self.mode == "full":
            self.log("cmd[%d]: %s" % (idx, cmd))
        else:
            self.log("cmd[%d] sha256=%s len=%d" % (
                idx, hashlib.sha256(cmd.encode("utf-8", "replace")).hexdigest()[:16], len(cmd)))


class NewroleSession(object):
    def __init__(self, role, password, type=None, level=None, newrole=NEWROLE,
                 auth_timeout=30.0, max_output=64 * 1024 * 1024, audit=None):
        self.role, self.type, self.level = role, type, level
        self.newrole, self.auth_timeout, self.max_output = newrole, auth_timeout, max_output
        self.password = password if isinstance(password, bytearray) else bytearray(password)
        self.audit = audit or Audit(enabled=False)
        self.pid = self.fd = None
        self.buf = bytearray()
        self.nonce = base64.b16encode(os.urandom(8)).decode().lower()
        self.n = 0
        self._seq = 0
        self.truncated = False
        self.alive = False
        self.context = None
        self.exit_status = None
        self._nested_child = None        # a NestedSession opened via .nest(), closed before us

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        self._check_newrole()
        argv = [self.newrole, "-r", self.role]
        if self.type:
            argv += ["-t", self.type]
        if self.level:
            argv += ["-l", self.level]
        argv += ["--", "-c", "exec /bin/bash --noprofile --norc /dev/stdin"]
        try:
            pw = pwd.getpwuid(os.getuid())
            home, name = pw.pw_dir, pw.pw_name
        except KeyError:
            home, name = "/", str(os.getuid())
        env = {"PATH": SAFE_PATH, "LANG": "C", "TERM": "dumb", "HOME": home,
               "USER": name, "LOGNAME": name}
        self.audit.log("start user=%s role=%s type=%s level=%s" % (name, self.role, self.type, self.level))
        pid, fd = pty.fork()
        if pid == 0:                                # child: fresh session, pty is ctty
            try:
                a = termios.tcgetattr(0)
                a[3] &= ~(termios.ECHO | termios.ECHONL)
                a[1] &= ~termios.ONLCR
                termios.tcsetattr(0, termios.TCSANOW, a)
                os.execve(argv[0], argv, env)
            except OSError as e:                    # surfaces in the parent as newrole's output
                os.write(2, ("cannot execute %s: %s\n" % (argv[0], e)).encode())
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        try:
            self._authenticate()
            self.alive = True                       # run_raw() needs it for the context check
            self._verify_context()
        except BaseException:
            self.close(force=True)
            raise
        return self

    def _check_newrole(self):
        try:
            st = os.stat(self.newrole)
        except OSError as e:
            raise NewroleError("cannot use %s: %s" % (self.newrole, e))
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise NewroleError("%s is not root-owned / is group-or-world writable" % self.newrole)

    def _authenticate(self):
        deadline = time.monotonic() + self.auth_timeout
        try:
            self._expect_prompt(deadline)
            self.buf.clear()
            self._write(bytes(self.password) + b"\n")
            wipe(self.password)
            # The frame is queued in the tty until the shell starts reading. Resend rarely, and
            # never while a password prompt is showing: a re-prompt (failed PAM conversation)
            # would swallow the frame as a second password guess and count against faillock.
            self._write(self._frame_cmd("true", "S1"))
            next_send = time.monotonic() + 5.0
            while True:
                if time.monotonic() > deadline:
                    raise AuthError("timed out waiting for shell after password")
                try:
                    self._collect("S1", min(deadline, time.monotonic() + 1.0))
                    break
                except _Timeout:
                    if PROMPT_RE.search(self.buf):
                        raise AuthError("newrole re-prompted for a password (wrong password?)")
                    if time.monotonic() >= next_send:
                        self._write(self._frame_cmd("true", "S1"))
                        next_send = time.monotonic() + 5.0
            # second, fresh sync: discard duplicates from the resends above
            self._write(self._frame_cmd("true", "S2"))
            self._collect("S2", deadline)
        except SessionDead as e:
            txt = self._text(e.partial or bytes(self.buf)).strip()
            raise AuthError("newrole exited during authentication: %s" % (txt or "no output"))
        except _Timeout:
            raise AuthError("timed out during authentication")
        finally:
            wipe(self.password)

    def _expect_prompt(self, deadline):
        while not PROMPT_RE.search(bytes(self.buf)):
            if not self._wait_readable(deadline):
                raise AuthError("no password prompt from newrole: %s" % self._text(bytes(self.buf)).strip())
            self._pump()

    def _verify_context(self):
        out, rc, _ = self.run_raw('read -r -d "" c </proc/$$/attr/current; printf "%s" "$c"', 15)
        ctx = self._text(out).strip().rstrip("\x00")
        parts = ctx.split(":")
        if len(parts) < 3 or parts[1] != self.role or (self.type and parts[2] != self.type):
            raise ContextError("landed in context %r, wanted role=%s type=%s" % (ctx, self.role, self.type))
        self.context = ctx
        self.audit.log("authenticated context=%s" % ctx)

    def close(self, force=False):
        if self._nested_child is not None:
            self._nested_child.close()
        if self.fd is None:
            return
        try:
            if self.alive and not force:
                try:
                    os.write(self.fd, b"exit\n")
                except OSError:
                    pass
                self._reap(3.0)
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            self._reap(1.0)
            if self.pid and self.exit_status is None:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except OSError:
                    pass
                self._reap(1.0)
            self.alive = False
            wipe(self.password)
            self.audit.log("end role=%s commands=%d" % (self.role, self.n))

    def _reap(self, timeout):
        end = time.monotonic() + timeout
        while self.pid and self.exit_status is None:
            try:
                p, st = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.exit_status = -1
                return
            if p:
                self.exit_status = st
                return
            if time.monotonic() > end:
                return
            time.sleep(0.05)

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.close()

    # ---------------------------------------------------------------- commands
    def run(self, cmd, timeout=None, isolate=False, stderr=False, answers=None):
        """Run `cmd` (any shell text) in the role. Returns dict(rc, out, truncated[, err]).

        stderr=True   capture stderr separately into res["err"] (default: merged into "out")
        answers       [(prompt_regex, password), ...]: when a prompt matching the regex shows up
                      (e.g. sudo's "[sudo] password for"), the password is typed once and the
                      prompt text is removed from the output.
        """
        self.n += 1
        self.audit.command(self.n, cmd)
        out, rc, err = self.run_raw(cmd, timeout, isolate, stderr, answers)
        res = {"rc": rc, "out": self._text(out), "truncated": self.truncated}
        if stderr:
            res["err"] = self._text(base64.b64decode(err)) if err else ""
        self.truncated = False
        return res

    def run_raw(self, cmd, timeout=None, isolate=False, stderr=False, answers=None):
        if not self.alive:
            raise SessionDead("session not started or already terminated")
        self._seq += 1
        name = "C%d" % self._seq
        t0 = time.monotonic()
        self._write(self._frame_cmd(cmd, name, isolate, stderr))
        deadline = t0 + timeout if timeout else None
        try:
            out, rc, err = self._collect(name, deadline, answers)
        except _Timeout:
            self.alive = False                      # SIGINT also hits newrole; treat as dead
            try:
                os.write(self.fd, b"\x03")
            except OSError:
                pass
            raise CommandTimeout("timeout after %ss (session terminated)" % timeout)
        except SessionDead as e:
            self.alive = False
            st = self.exit_status
            why = ("exit code %d" % os.WEXITSTATUS(st) if st is not None and os.WIFEXITED(st)
                   else "status %s" % st)
            raise SessionDead("shell exited (%s) while running command" % why, e.partial)
        return out, rc, err

    def _frame_cmd(self, cmd, name, isolate=False, stderr=False):
        b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
        lines = ["__c=''"]
        for i in range(0, len(b64), CHUNK):
            lines.append("__c=\"$__c\"'%s'" % b64[i:i + CHUNK])
        body = 'eval "$(printf %s "$__c" | base64 -d)"'
        run = ("( %s )" if isolate else "{ %s; }") % body
        pre = post = ""
        if stderr:
            pre = '__e=$(mktemp) || __e=/dev/null; '
            run += ' 2>"$__e"'
            post = '__eb=$(base64 -w0 <"$__e" 2>/dev/null); rm -f "$__e"; '
        lines.append("%s%s </dev/null; __rc=$?; %sunset __c __e; stty -echo -onlcr 2>/dev/null; "
                     "printf '\\n%%s%%s:%%d:%%s\\n' 'NRB%s' '%s' \"$__rc\" \"$__eb\"; unset __eb"
                     % (pre, run, post, self.nonce, name))
        return ("\n".join(lines) + "\n").encode("ascii")

    # ---------------------------------------------------------------- io
    def _text(self, b):
        return bytes(b).decode("utf-8", "replace")

    def _wait_readable(self, deadline):
        while True:
            t = 1.0 if deadline is None else max(0.0, min(1.0, deadline - time.monotonic()))
            r, _, _ = select.select([self.fd], [], [], t)
            if r:
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False

    def _pump(self):
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return 0
        except OSError as e:
            if e.errno == errno.EIO:
                self._reap(1.0)
                raise SessionDead("pty closed", bytes(self.buf))
            raise
        if not data:
            self._reap(1.0)
            raise SessionDead("pty EOF", bytes(self.buf))
        self.buf += data
        cap = self.max_output
        if len(self.buf) > cap + 4096:
            self.truncated = True
            del self.buf[cap:len(self.buf) - 2048]
        return len(data)

    def _write(self, data, stall_timeout=30.0):
        off = 0
        last_progress = time.monotonic()
        while off < len(data):
            if time.monotonic() - last_progress > stall_timeout:
                raise SessionDead("write to pty stalled for %ss" % stall_timeout, bytes(self.buf))
            r, w, _ = select.select([self.fd], [self.fd], [], 5.0)
            if r:
                self._pump()
            if w:
                try:
                    off += os.write(self.fd, data[off:off + 2048])
                    last_progress = time.monotonic()
                except BlockingIOError:
                    pass
                except OSError as e:
                    if e.errno == errno.EIO:
                        raise SessionDead("pty closed while writing", bytes(self.buf))
                    raise

    def _collect(self, name, deadline, answers=None):
        pat = re.compile(rb"\nNRB" + self.nonce.encode() + re.escape(name.encode()) + rb":(\d+):([A-Za-z0-9+/=]*)\n")
        pending = [(re.compile(r.encode() if isinstance(r, str) else r), pw) for r, pw in (answers or [])]
        start = 0
        answered_at = []
        while True:
            m = pat.search(self.buf, start)
            if m:
                rc = int(m.group(1))                # read before mutating the buffer
                err = m.group(2)
                out = bytes(self.buf[:m.start()])
                del self.buf[:m.end()]
                # the program prints a newline after reading the (unechoed) answer: drop it too
                for pos in reversed(answered_at):
                    for nl in (b"\r\n", b"\n"):
                        if out[pos:pos + len(nl)] == nl:
                            out = out[:pos] + out[pos + len(nl):]
                            break
                return out, rc, err
            if deadline is not None and time.monotonic() >= deadline:
                raise _Timeout()
            if self._wait_readable(min(deadline, time.monotonic() + 1.0) if deadline else None):
                n = self._pump()
                for item in list(pending):
                    pm = item[0].search(self.buf, max(0, len(self.buf) - 1024))
                    if pm:
                        pending.remove(item)
                        del self.buf[pm.start():pm.end()]
                        answered_at.append(pm.start())
                        pw = item[1]
                        self._write((pw if isinstance(pw, bytes) else pw.encode()) + b"\n")
                start = max(0, len(self.buf) - n - len(name) - len(self.nonce) - 16)

    # ---------------------------------------------------------------- nesting (jump host)
    # These let a second `newrole` session be opened on host B by running `ssh` as a plain
    # foreground command *inside this session's own role shell on host A* — so B is reached
    # through A's already-authenticated, already-audited context, the same way a sysadmin
    # would do it by hand: ssh A, newrole, ssh B, newrole. The pty is switched to raw mode for
    # the duration so B's JSON-lines protocol (any length, any byte) passes through untouched;
    # a random marker printed after `ssh` exits tells us when control is back with A's shell.
    def nest(self, host, cfg, password, ssh="ssh", ssh_opts=(), remote_python="python3",
             remote_path=None, auth_timeout=30.0):
        """Open a NewroleSession on `host`, reached via ssh run inside this role shell.
        Returns a NestedSession with the same run()/close() interface. Only one nested
        session may be open on a given session at a time (close it before opening another).
        Chaining a third hop from a NestedSession is not supported."""
        if self._nested_child is not None:
            raise NewroleError("a nested session is already open; close it first")
        child = NestedSession(self, host, cfg, password, ssh, ssh_opts, remote_python,
                              remote_path, auth_timeout)
        child.start()
        self._nested_child = child
        return child

    def _nest_donepat(self, nonce):
        return re.compile(rb"\nNRBNEST" + nonce.encode() + rb":(\d+)\n")

    def nest_open(self, host, ssh="ssh", ssh_opts=(), remote_python="python3", remote_path=None):
        """Type the shell command that puts this pty in raw mode and execs `ssh host ...`
        as a foreground job of the current shell. Blocks until raw mode is confirmed active
        (so the caller can safely start writing handshake bytes next) and returns the marker
        nonce to watch for when that ssh job finishes."""
        argv = [ssh, "-T"] + list(ssh_opts) + ["--", host, remote_command(remote_python, remote_path)]
        cmdline = " ".join(shlex.quote(a) for a in argv)
        nonce = base64.b16encode(os.urandom(8)).decode().lower()
        # set +e: a nonzero ssh exit must never skip our completion marker, even if the
        # user's shell has `set -e` active. We restore -echo -onlcr (this session's own
        # standing settings, set once in start() and otherwise never touched) rather than
        # `stty sane`, which would re-enable echo/canonical mode on the persistent shell for
        # every command after the nested session closes.
        line = ("(set +e; stty raw -echo -ixon -icrnl -inlcr 2>/dev/null; "
                "printf '%%s\\n' 'NRBNESTREADY%s'; %s; __rc=$?; "
                "stty -echo -onlcr 2>/dev/null; printf '\\n%%s:%%d\\n' 'NRBNEST%s' \"$__rc\"); unset __rc\n"
                % (nonce, cmdline, nonce))
        self._write(line.encode())
        # Wait for the READY marker: confirms raw mode is active and we're about to exec ssh,
        # so nest_handshake()'s writes can never land on the ordinary canonical/echoing prompt.
        readypat = re.compile(re.escape(("NRBNESTREADY" + nonce).encode()) + rb"\r?\n")
        deadline = time.monotonic() + 10.0
        while True:
            m = readypat.search(self.buf)
            if m:
                del self.buf[:m.end()]
                break
            if not self._wait_readable(deadline):
                raise NewroleError("nested ssh command did not start")
            self._pump()
        return nonce

    def nest_handshake(self, cfg, password, script_b64=None):
        """Feed the nested serve()'s bootstrap: [script] then cfg then password, exactly
        what it would read if reached directly (so B's own serve() needs no special-casing)."""
        if script_b64 is not None:
            self._write(script_b64 + b"\n")
        self._write(json.dumps(cfg).encode() + b"\n")
        self._write(bytes(password) + b"\n")
        wipe(password)

    def nest_send(self, obj):
        self._write(json.dumps(obj).encode() + b"\n")

    def nest_read_event(self, nonce, deadline):
        """Read one JSON line from the nested child (its 'ready'/'error', or a command
        reply) — or raise if the nested ssh job ends first (e.g. connection refused)."""
        donepat = self._nest_donepat(nonce)
        while True:
            m = donepat.search(self.buf)
            if m:
                msg = bytes(self.buf[:m.start()]).strip()
                del self.buf[:m.end()]
                raise NestEnded("nested connection ended before a reply arrived%s" %
                                   (": %s" % self._text(msg) if msg else ""))
            nl = self.buf.find(b"\n")
            if nl != -1:
                line = bytes(self.buf[:nl])
                del self.buf[:nl + 1]
                text = self._text(line).strip()
                if not text:
                    continue
                try:
                    return json.loads(text)
                except ValueError:
                    continue      # stray ssh/bash banner line before the real JSON
            if deadline is not None and time.monotonic() > deadline:
                raise NewroleError("timed out waiting for nested session")
            if not self._wait_readable(deadline):
                raise NewroleError("timed out waiting for nested session")
            self._pump()

    def nest_abort(self, nonce, timeout=10.0):
        """Best-effort recovery after a failed nested handshake: ask the peer to close, wait for
        the ssh job's completion marker (which restores the pty's cooked settings). If that never
        arrives the pty is left raw, so the session is marked dead rather than reused."""
        try:
            self.nest_send({"op": "close"})
            self.nest_drain(nonce, timeout)
        except NewroleError:
            self.alive = False

    def nest_drain(self, nonce, timeout):
        """Discard everything until the nested job's completion marker (used on error, or
        after sending it a close, when we don't care about anything it still prints)."""
        donepat = self._nest_donepat(nonce)
        deadline = time.monotonic() + timeout
        while True:
            m = donepat.search(self.buf)
            if m:
                del self.buf[:m.end()]
                return int(m.group(1))
            if len(self.buf) > 4096:
                del self.buf[:len(self.buf) - 2048]
            if time.monotonic() > deadline:
                raise NewroleError("nested session did not close within %ss" % timeout)
            if not self._wait_readable(deadline):
                raise NewroleError("nested session did not close within %ss" % timeout)
            self._pump()

    def nest_proxy(self, rd, outb, nonce):
        """Blind byte relay between a controller stream (rd/outb, binary) and this session's
        own pty, until the nested job's completion marker appears. Used by serve() so a
        controller talking to A can drive B's JSON protocol transparently through A's pty.
        Returns the nested ssh job's exit status.

        `rd` is a buffered io.BufferedReader (serve()'s stdin): earlier rd.readline() calls
        may have pulled more bytes out of the kernel pipe than they returned, leaving extra
        bytes sitting in rd's own internal buffer where select()/read on the raw fd can't see
        them. rd.peek() drains that safely (it never blocks and never signals EOF either way,
        so an empty peek() is not meaningful on its own). Once the buffer is confirmed empty,
        select() on the raw fd is used to tell "no data yet" apart from real EOF/data before
        read1() (on a non-blocking fd, both an empty pipe *and* EOF return b'' from read1() --
        they're only distinguishable by asking select() first).

        B's JSON replies must reach the controller promptly and whole (it reads them with
        readline()), so every byte confirmed not to be part of the completion marker is
        flushed immediately -- never held back by a fixed amount "just in case", only by the
        actual, computed overlap with an in-progress marker match. The marker starts with a
        bare "\n", which every ordinary JSON reply line also ends with, so a 1-byte "possible
        partial marker" match is the norm, not the exception, and it would otherwise withhold
        exactly the newline the controller's readline() is waiting for. Rather than hold it
        indefinitely on the (practically never true, for same-host pty I/O) chance that the
        rest of a real marker is still in flight, a short idle grace period flushes it anyway
        once nothing new has arrived for a moment.
        """
        donepat = self._nest_donepat(nonce)
        mark = ("\nNRBNEST" + nonce).encode()
        rfd = rd.fileno()
        flags = fcntl.fcntl(rfd, fcntl.F_GETFL)
        fcntl.fcntl(rfd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        held_since = None
        try:
            while True:
                pending = rd.peek(65536)
                if pending:
                    self._write(rd.read(len(pending)))
                    continue
                r, _, _ = select.select([self.fd, rfd], [], [], 0.2)
                if rfd in r:
                    chunk = rd.read1(65536)
                    if chunk == b"":
                        raise SessionDead("controller disconnected while nested")
                    if chunk:
                        self._write(chunk)
                if self.fd in r:
                    self._pump()
                    m = donepat.search(self.buf)
                    if m:
                        if m.start():
                            outb.write(bytes(self.buf[:m.start()]))
                        rc = int(m.group(1))
                        del self.buf[:m.end()]
                        outb.flush()
                        return rc
                # No full marker: flush everything except a trailing suffix that could still
                # grow into one (longest overlap with the marker's own start, checked longest
                # first) -- unless that held-back tail has sat unchanged for a moment, in which
                # case nothing is actually still arriving to complete it, so flush it too.
                buf = bytes(self.buf)
                keep = 0
                for n in range(min(len(buf), len(mark)), 0, -1):
                    if buf[-n:] == mark[:n]:
                        keep = n
                        break
                if keep and held_since is None:
                    held_since = time.monotonic()
                elif not keep:
                    held_since = None
                if keep and held_since is not None and time.monotonic() - held_since > 0.3:
                    keep = 0
                    held_since = None
                if len(buf) > keep:
                    cut = len(buf) - keep
                    outb.write(buf[:cut])
                    del self.buf[:cut]
                    outb.flush()
        finally:
            fcntl.fcntl(rfd, fcntl.F_SETFL, flags)


class NestedSession(object):
    """A newrole session on a second host, opened in-process by running `ssh` inside the
    role shell of an already-authenticated NewroleSession (the jump/bastion pattern). Same
    run()/close() interface as NewroleSession and RemoteSession."""

    def __init__(self, parent, host, cfg, password, ssh="ssh", ssh_opts=(), remote_python="python3",
                 remote_path=None, auth_timeout=30.0):
        self.parent, self.host, self.cfg = parent, host, cfg
        self.password = password if isinstance(password, bytearray) else bytearray(password)
        self.ssh, self.ssh_opts = ssh, list(ssh_opts)
        self.remote_python, self.remote_path = remote_python, remote_path
        self.auth_timeout = auth_timeout
        self.context = self.nonce = None
        self._open = False

    def start(self):
        script_b64 = None
        if not self.remote_path:
            with open(os.path.realpath(__file__), "rb") as f:
                script_b64 = base64.b64encode(f.read())
        self.nonce = self.parent.nest_open(self.host, self.ssh, self.ssh_opts,
                                           self.remote_python, self.remote_path)
        self.parent.nest_handshake(self.cfg, self.password, script_b64)
        try:
            ev = self.parent.nest_read_event(self.nonce, time.monotonic() + self.auth_timeout)
        except NestEnded:
            raise
        except NewroleError:
            self.parent.nest_abort(self.nonce)
            raise
        if ev.get("event") == "error":
            try:
                self.parent.nest_drain(self.nonce, 10.0)
            except NewroleError:
                self.parent.alive = False
            raise_event_error(ev)
        if ev.get("event") != "ready":
            self.parent.nest_abort(self.nonce)
            raise NewroleError("unexpected first message from nested session: %r" % ev)
        self.context = ev.get("context")
        self._open = True
        return self

    def run(self, cmd, timeout=None, isolate=False, stderr=False, answers=None):
        if not self._open:
            raise SessionDead("nested session not started")
        req = {"cmd": cmd, "timeout": timeout, "isolate": isolate, "stderr": stderr,
               "answers": [[r, pw if isinstance(pw, str) else pw.decode()] for r, pw in (answers or [])]}
        self.parent.nest_send(req)
        deadline = time.monotonic() + (timeout + 10 if timeout else 3600)
        r = self.parent.nest_read_event(self.nonce, deadline)
        if r.get("event") == "error":
            raise_event_error(r)
        return r

    def close(self):
        if self._open:
            try:
                self.parent.nest_send({"op": "close"})
                self.parent.nest_drain(self.nonce, 10.0)
            except NewroleError:
                pass
            self._open = False
        self.parent._nested_child = None

    def __enter__(self):
        if not self._open:
            self.start()
        return self

    def __exit__(self, *a):
        self.close()


# -------------------------------------------------------------------- remote


class RemoteSession(object):
    """Same run() interface, but the NewroleSession lives on an ssh target."""

    def __init__(self, host, cfg, password, ssh="ssh", ssh_opts=(), remote_python="python3", remote_path=None,
                 ssh_env=None):
        self.host, self.cfg, self.password = host, cfg, password
        self.ssh, self.ssh_opts, self.remote_python, self.remote_path = ssh, list(ssh_opts), remote_python, remote_path
        self.proc = None
        self._rbuf = bytearray()
        self.context = None
        self.ssh_env = ssh_env          # extra env for the ssh client only (e.g. SSH_ASKPASS)
        self._nested = False            # True for a session returned by .nest(): shares proc
        self._parent = None
        self._nested_child = None
        self._started = False           # a .nest()-returned child is already started; `with`
                                        # on it must not call start() again

    def start(self):
        remote = remote_command(self.remote_python, self.remote_path)
        argv = [self.ssh, "-T"] + self.ssh_opts + ["--", self.host, remote]
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     env=dict(os.environ, **self.ssh_env) if self.ssh_env else None)
        w = self.proc.stdin
        if not self.remote_path:
            with open(os.path.realpath(__file__), "rb") as f:
                w.write(base64.b64encode(f.read()) + b"\n")
        w.write(json.dumps(self.cfg).encode() + b"\n")
        w.write(bytes(self.password) + b"\n")
        w.flush()
        wipe(self.password)
        try:
            ev = self._read(time.monotonic() + self.cfg.get("auth_timeout", 30.0) + 30.0)
            if ev.get("event") == "error":
                raise_event_error(ev)
            if ev.get("event") != "ready":
                raise NewroleError("unexpected first message: %r" % ev)
        except BaseException:
            self._finish()
            raise
        self.context = ev.get("context")
        self._started = True
        return self

    def _readline(self, deadline):
        """One line from the ssh pipe, honouring `deadline`. Keeps its own buffer: select() on
        the fd can't see lines already pulled into a BufferedReader (two replies arriving in one
        read would leave the second invisible and time out)."""
        fd = self.proc.stdout.fileno()
        while b"\n" not in self._rbuf:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([fd], [], [], left)[0]:
                    raise CommandTimeout("no reply from remote within the allowed time")
            chunk = os.read(fd, 65536)
            if not chunk:
                line = bytes(self._rbuf)
                self._rbuf.clear()
                return line
            self._rbuf += chunk
        i = self._rbuf.index(b"\n") + 1
        line = bytes(self._rbuf[:i])
        del self._rbuf[:i]
        return line

    def _read(self, deadline=None):
        line = self._readline(deadline)
        if not line:
            rc = self._finish()
            raise SessionDead("remote closed connection (ssh exit %s)" % rc)
        try:
            return json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            raise NewroleError("garbled reply from remote: %r" % line[:200])

    def run(self, cmd, timeout=None, isolate=False, stderr=False, answers=None):
        req = {"cmd": cmd, "timeout": timeout, "isolate": isolate, "stderr": stderr,
               "answers": [[r, pw if isinstance(pw, str) else pw.decode()] for r, pw in (answers or [])]}
        try:
            self.proc.stdin.write(json.dumps(req).encode() + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise SessionDead("remote connection lost")
        # the remote enforces `timeout` itself; this is only a backstop for a hung connection
        r = self._read(time.monotonic() + timeout + 15 if timeout else None)
        if r.get("event") == "error":
            raise_event_error(r)
        return r

    def nest(self, host, cfg, password, ssh="ssh", ssh_opts=(), remote_python="python3", remote_path=None):
        """Open a newrole session on a second host `host`, reached by running `ssh` *inside
        this session's own role shell* on its host — the same ssh-A/newrole/ssh-B/newrole
        sequence as NewroleSession.nest(), just driven through this connection's pipe instead
        of a local pty. Returns a RemoteSession sharing the same ssh connection; only one may
        be open at a time (nest the returned session again for a third hop)."""
        if self._nested_child is not None:
            raise NewroleError("a nested session is already open on this connection; close it first")
        pw = password if isinstance(password, bytearray) else bytearray(password)
        cfg = dict(cfg, nested=True)        # tells the far serve() that "unnest" means exit
        req = {"op": "nest", "host": host, "ssh": ssh, "ssh_opts": list(ssh_opts),
               "remote_python": remote_python, "remote_path": remote_path}
        try:
            w = self.proc.stdin
            w.write(json.dumps(req).encode() + b"\n")
            if not remote_path:
                with open(os.path.realpath(__file__), "rb") as f:
                    w.write(base64.b64encode(f.read()) + b"\n")
            w.write(json.dumps(cfg).encode() + b"\n")
            w.write(bytes(pw) + b"\n")
            w.flush()
        except (BrokenPipeError, OSError):
            raise SessionDead("remote connection lost")
        finally:
            wipe(pw)
        ev = self._read(time.monotonic() + cfg.get("auth_timeout", 30.0) + 30.0)
        if ev.get("event") == "error":
            raise_event_error(ev)
        if ev.get("event") != "ready":
            raise NewroleError("unexpected reply to nest: %r" % ev)
        child = RemoteSession.__new__(RemoteSession)
        child.host, child.cfg, child.password, child.ssh_env = host, cfg, None, None
        child.ssh, child.ssh_opts, child.remote_python, child.remote_path = ssh, list(ssh_opts), remote_python, remote_path
        child.proc, child.context, child._rbuf = self.proc, ev.get("context"), self._rbuf
        child._nested, child._parent, child._nested_child = True, self, None
        child._started = True
        self._nested_child = child
        return child

    def _finish(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            return self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
            return -1

    def close(self):
        if self._nested_child is not None:
            self._nested_child.close()
        if self._nested:
            # "unnest" (not "close"): if the far end already exited on its own (timeout, dead
            # shell) the relay is gone and this line reaches *our* serve(), which ignores it;
            # a "close" there would terminate the outer session.
            try:
                self.proc.stdin.write(b'{"op":"unnest"}\n')
                self.proc.stdin.flush()
                deadline = time.monotonic() + 15.0
                while self._read(deadline).get("event") != "unnested":
                    pass
            except Exception:
                pass
            if self._parent is not None:
                self._parent._nested_child = None
            return
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.write(b'{"op":"close"}\n')
                self.proc.stdin.flush()
            except Exception:
                pass
            self._finish()

    def __enter__(self):
        if not self._started:
            self.start()
        return self

    def __exit__(self, *a):
        self.close()


def serve():
    """Remote end: stdin is a binary pipe; stdout carries JSON lines only."""
    harden_process()
    rd, out = sys.stdin.buffer, sys.stdout

    def emit(o):
        out.write(json.dumps(o) + "\n")
        out.flush()

    cfg = json.loads(rd.readline().decode())
    pw = bytearray(rd.readline().rstrip(b"\r\n"))
    audit = Audit(cfg.get("audit", "hash"), cfg.get("syslog", True))
    sess = NewroleSession(cfg["role"], pw, cfg.get("type"), cfg.get("level"),
                          cfg.get("newrole") or NEWROLE, cfg.get("auth_timeout", 30.0),
                          cfg.get("max_output", 64 * 1024 * 1024), audit)
    try:
        sess.start()
    except AuthError as e:
        audit.log("AUTH FAILURE role=%s: %s" % (cfg["role"], e), syslog.LOG_WARNING)
        emit({"event": "error", "kind": "auth", "message": str(e)})
        return EXIT_AUTH
    except ContextError as e:
        audit.log("CONTEXT MISMATCH: %s" % e, syslog.LOG_WARNING)
        emit({"event": "error", "kind": "context", "message": str(e)})
        return EXIT_AUTH
    except Exception as e:
        emit({"event": "error", "kind": "session", "message": "%s: %s" % (type(e).__name__, e)})
        return EXIT_SESSION
    emit({"event": "ready", "context": sess.context})
    try:
        for line in iter(rd.readline, b""):
            try:
                req = json.loads(line.decode())
            except ValueError:
                emit({"event": "error", "message": "bad request"})
                continue
            op = req.get("op")
            if op == "close" or (op == "unnest" and cfg.get("nested")):
                break
            if op == "unnest":
                continue                    # stale: the nested peer already ended on its own
            if op == "nest":
                nonce = None
                try:
                    nonce = sess.nest_open(req["host"], req.get("ssh", "ssh"), req.get("ssh_opts") or [],
                                           req.get("remote_python", "python3"), req.get("remote_path"))
                    script_b64 = None
                    if not req.get("remote_path"):
                        script_b64 = rd.readline().rstrip(b"\r\n")
                    ncfg = json.loads(rd.readline().decode())
                    npw = bytearray(rd.readline().rstrip(b"\r\n"))
                    sess.nest_handshake(ncfg, npw, script_b64)
                    ev = sess.nest_read_event(nonce, time.monotonic() + float(ncfg.get("auth_timeout", 30.0)))
                except Exception as e:
                    if nonce is not None and not isinstance(e, NestEnded):
                        sess.nest_abort(nonce)
                    msg = str(e) if isinstance(e, NewroleError) else "%s: %s" % (type(e).__name__, e)
                    emit({"event": "error", "message": "nest failed: %s" % msg})
                    if not sess.alive:
                        break
                    continue
                emit(ev)
                if ev.get("event") == "error":
                    try:
                        sess.nest_drain(nonce, 10.0)
                    except NewroleError:
                        pass
                    continue
                out.flush()
                rc = sess.nest_proxy(rd, sys.stdout.buffer, nonce)
                emit({"event": "unnested", "rc": rc})
                continue
            t0 = time.monotonic()
            try:
                res = sess.run(req["cmd"], req.get("timeout"), bool(req.get("isolate")),
                               bool(req.get("stderr")), req.get("answers"))
                res["duration"] = round(time.monotonic() - t0, 3)
                emit(res)
            except NewroleError as e:
                emit({"event": "error", "kind": "timeout" if isinstance(e, CommandTimeout) else "session",
                      "message": str(e)})
                if not sess.alive:
                    break
    finally:
        sess.close()
    return EXIT_OK


# ----------------------------------------------------------------------- CLI
def read_password(a, role):
    if a.password_file:
        with open(a.password_file, "rb") as f:
            st = os.fstat(f.fileno())               # check the file we actually opened
            if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                sys.exit("password file must be owned by you with mode 0600/0400")
            return bytearray(f.readline().rstrip(b"\r\n"))
    if a.password_fd is not None:
        data = b""
        while not data.endswith(b"\n"):
            c = os.read(a.password_fd, 1)
            if not c:
                break
            data += c
        return bytearray(data.rstrip(b"\r\n"))
    if a.password_stdin:
        return bytearray(sys.stdin.buffer.readline().rstrip(b"\r\n"))
    return bytearray(getpass.getpass("newrole password (role %s): " % role).encode())


def gather_commands(a):
    cmds = list(a.command or [])
    if a.commands_file:
        with open(a.commands_file) as f:
            cmds += [l.rstrip("\n") for l in f if l.strip() and not l.lstrip().startswith("#")]
    if a.script:
        with open(a.script) as f:
            cmds.append(f.read())
    return cmds


def batch(sess, cmds, a):
    worst = EXIT_OK
    for i, c in enumerate(cmds, 1):
        try:
            r = sess.run(c, a.timeout, a.isolate)
        except NewroleError as e:
            sys.stderr.write("newrole-batch: [%d] %s\n" % (i, e))
            if a.json:
                print(json.dumps({"index": i, "cmd": c, "rc": None, "error": str(e)}))
            return EXIT_TIMEOUT if isinstance(e, CommandTimeout) else EXIT_SESSION
        if a.json:
            r.update({"index": i, "cmd": c})
            print(json.dumps(r))
        else:
            sys.stdout.write(r["out"] + ("" if r["out"].endswith("\n") or not r["out"] else "\n"))
            sys.stdout.flush()
        if r["rc"]:
            worst = EXIT_CMDFAIL
            sys.stderr.write("newrole-batch: [%d] rc=%d: %s\n" % (i, r["rc"], c.splitlines()[0][:100] if c else ""))
            if a.stop_on_error:
                break
    return worst


def main(argv=None):
    harden_process()
    p = argparse.ArgumentParser(prog="newrole_batch.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="mode")
    sub.add_parser("serve")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-r", "--role", required=True)
    common.add_argument("-t", "--type")
    common.add_argument("-l", "--level")
    common.add_argument("-c", "--command", action="append", help="command to run (repeatable)")
    common.add_argument("--commands-file", help="one command per line (# comments ok)")
    common.add_argument("--script", help="whole file executed as ONE command")
    common.add_argument("--isolate", action="store_true", help="run each command in a subshell (no state leaks)")
    common.add_argument("--stop-on-error", action="store_true")
    common.add_argument("--timeout", type=float, help="per-command seconds (a timeout ends the session)")
    common.add_argument("--json", action="store_true", help="one JSON object per command")
    common.add_argument("--audit", choices=["none", "hash", "full"], default="hash",
                        help="syslog authpriv record of commands (default: sha256 prefix only)")
    common.add_argument("--no-syslog", action="store_true")
    common.add_argument("--auth-timeout", type=float, default=30.0)
    common.add_argument("--max-output", type=int, default=64 * 1024 * 1024)
    pw = common.add_mutually_exclusive_group()
    pw.add_argument("--password-file")
    pw.add_argument("--password-fd", type=int)
    pw.add_argument("--password-stdin", action="store_true")
    sub.add_parser("local", parents=[common])
    s = sub.add_parser("ssh", parents=[common])
    s.add_argument("host", help="[user@]host")
    s.add_argument("--ssh", default="ssh")
    s.add_argument("--ssh-opt", action="append", default=[], help="extra ssh argument (repeatable), e.g. -i")
    s.add_argument("--remote-python", default="python3")
    s.add_argument("--remote-path", help="use a pre-installed copy instead of streaming this file")
    p.add_argument("--version", action="version", version=VERSION)
    a = p.parse_args(argv)
    if a.mode is None:
        p.print_usage(sys.stderr)
        return EXIT_USAGE
    if a.mode == "serve":
        return serve()
    cmds = gather_commands(a)
    if not cmds:
        sys.stderr.write("no commands given (-c / --commands-file / --script)\n")
        return EXIT_USAGE
    pw_ba = read_password(a, a.role)
    cfg = {"role": a.role, "type": a.type, "level": a.level, "audit": a.audit,
           "syslog": not a.no_syslog, "auth_timeout": a.auth_timeout, "max_output": a.max_output}
    try:
        if a.mode == "local":
            sess = NewroleSession(a.role, pw_ba, a.type, a.level, auth_timeout=a.auth_timeout,
                                  max_output=a.max_output, audit=Audit(a.audit, not a.no_syslog))
        else:
            sess = RemoteSession(a.host, cfg, pw_ba, a.ssh, a.ssh_opt, a.remote_python, a.remote_path)
        with sess:
            return batch(sess, cmds, a)
    except (AuthError, ContextError) as e:
        sys.stderr.write("newrole-batch: authentication/context failure: %s\n" % e)
        return EXIT_AUTH
    except NewroleError as e:
        sys.stderr.write("newrole-batch: %s\n" % e)
        return EXIT_SESSION
    finally:
        wipe(pw_ba)


if __name__ == "__main__":
    sys.exit(main())
