"""Offline tests: NewroleSession against a fake `newrole` (a bash script on a pty).

Run with: python3 -m pytest tests/test_session.py
No SELinux, ssh or root needed. The real-host checks live in tests/run-tests.sh.
"""
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import newrole_batch as nb  # noqa: E402

FAKE = """#!/bin/bash
printf 'Password: '
read -rs p
echo
if [ "$p" != secret ]; then
    echo "incorrect password"
    exit 1
fi
shift 2
[ "$1" = -- ] && shift
exec /bin/bash "$@" 2>&1
"""

REPROMPT = """#!/bin/bash
printf 'Password: '
read -rs p
echo
printf 'Password: '
sleep 30
"""


@pytest.fixture
def fake(tmp_path, monkeypatch):
    def make(text=FAKE):
        path = tmp_path / "newrole"
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)
    monkeypatch.setattr(nb.NewroleSession, "_check_newrole", lambda self: None)
    monkeypatch.setattr(nb.NewroleSession, "_verify_context",
                        lambda self: setattr(self, "context", "test:ctx"))
    return make


def session(fake, pw=b"secret", text=FAKE, **kw):
    return nb.NewroleSession("r_r", bytearray(pw), newrole=fake(text), **kw)


def test_run_and_state(fake):
    with session(fake) as s:
        assert s.run("echo hi") == {"rc": 0, "out": "hi\n", "truncated": False}
        s.run("cd /")
        assert s.run("pwd")["out"] == "/\n"
        assert s.run("cd /tmp; pwd", isolate=True)["rc"] == 0
        assert s.run("pwd")["out"] == "/\n"


def test_exit_code_quotes_and_no_trailing_newline(fake):
    with session(fake) as s:
        assert s.run("false")["rc"] == 1
        assert s.run('printf "%s" "a\\"b \\$x"')["out"] == 'a"b $x'


def test_stderr_separate(fake):
    with session(fake) as s:
        r = s.run("echo o; echo e >&2; exit 3", stderr=True, isolate=True)
        assert (r["rc"], r["out"], r["err"]) == (3, "o\n", "e\n")


def test_large_command_and_output(fake):
    with session(fake) as s:
        assert s.run("echo %s | wc -c" % ("A" * 60000))["out"].strip() == "60001"
        assert len(s.run("head -c 3000000 /dev/zero | tr '\\0' x")["out"]) == 3000000


def test_truncation_keeps_marker(fake):
    with session(fake, max_output=10000) as s:
        r = s.run("head -c 200000 /dev/zero | tr '\\0' x; echo end")
        assert r["truncated"] and r["out"].endswith("end\n") and len(r["out"]) < 20000
        assert s.run("echo after")["out"] == "after\n"


def test_timeout_terminates_session(fake):
    with session(fake) as s:
        with pytest.raises(nb.CommandTimeout):
            s.run("sleep 20", timeout=1)
        with pytest.raises(nb.SessionDead):
            s.run("echo x")


def test_shell_exit_raises_session_dead(fake):
    with session(fake) as s:
        with pytest.raises(nb.SessionDead):
            s.run("exit 3")


def test_wrong_password_is_auth_error(fake):
    with pytest.raises(nb.AuthError, match="incorrect password"):
        session(fake, pw=b"nope").start()


def test_reprompt_is_auth_error(fake):
    with pytest.raises(nb.AuthError):
        session(fake, text=REPROMPT, auth_timeout=8).start()


def test_answers_prompt_and_strips_it(fake):
    cmd = ("printf 'Password for x: ' >/dev/tty; read -rs p </dev/tty; echo >/dev/tty; "
           "echo got=$p")
    with session(fake) as s:
        r = s.run(cmd, answers=[(r"Password for x: ?", "pw1")])
        assert r["out"] == "got=pw1\n"


def test_password_wiped(fake):
    pw = bytearray(b"secret")
    nb.NewroleSession("r_r", pw, newrole=fake()).start().close()
    assert pw == bytearray(len(pw))


def test_missing_newrole_is_newrole_error(tmp_path):
    with pytest.raises(nb.NewroleError):
        nb.NewroleSession("r_r", bytearray(b"x"), newrole=str(tmp_path / "nope")).start()


def test_exec_failure_message_reaches_caller(tmp_path, monkeypatch):
    bad = tmp_path / "newrole"
    bad.write_text("not executable")
    monkeypatch.setattr(nb.NewroleSession, "_check_newrole", lambda self: None)
    with pytest.raises(nb.AuthError, match="cannot execute"):
        nb.NewroleSession("r_r", bytearray(b"x"), newrole=str(bad)).start()


def test_password_file_must_be_private(tmp_path):
    f = tmp_path / "pw"
    f.write_text("secret\n")
    f.chmod(0o644)
    args = type("A", (), {"password_file": str(f), "password_fd": None, "password_stdin": False})()
    with pytest.raises(SystemExit):
        nb.read_password(args, "r_r")
    f.chmod(0o600)
    assert nb.read_password(args, "r_r") == bytearray(b"secret")


def test_remote_command_is_quoted():
    assert "'; rm" not in nb.remote_command("python3", None)
    assert nb.remote_command("python3", "/a b/x.py") == "python3 '/a b/x.py' serve"
