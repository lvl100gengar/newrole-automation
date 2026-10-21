"""One suite, two backends (see conftest.py): offline fake `newrole` by default, plus a real
host when NRB_TARGET is set.

  python3 -m pytest tests               # offline
  cp tests/.env.example tests/.env      # fill in NRB_TARGET etc., then the same command
                                        # also runs everything below against the real host

Tests taking `backend` run on every enabled backend; tests taking `real` need a real host;
tests using `make_session("fake")` / `fake_*` only make sense offline.
"""
import os
import signal
import subprocess
import sys
import time

import pytest

import newrole_batch as nb
from conftest import REAL, ROOT, ssh_args


# ------------------------------------------------------------- shared (both backends)
def test_run_and_state(session):
    r = session.run("echo hi")
    assert (r["rc"], r["out"], r["truncated"]) == (0, "hi\n", False)
    session.run("cd /etc")
    assert session.run("pwd")["out"] == "/etc\n"


def test_isolate_hides_state(session):
    session.run("cd /etc")
    assert session.run("cd /tmp; pwd", isolate=True)["out"] == "/tmp\n"
    assert session.run("pwd")["out"] == "/etc\n"


def test_exit_code(session):
    assert session.run("true")["rc"] == 0
    assert session.run("false")["rc"] == 1


def test_quotes_newlines_and_no_trailing_newline(session):
    assert session.run('printf "%s" "a\\"b \\$x"')["out"] == 'a"b $x'
    assert session.run("printf 'a\\nb\\n'")["out"] == "a\nb\n"


def test_stderr_separate(session):
    r = session.run("echo o; echo e >&2; exit 3", stderr=True, isolate=True)
    assert (r["rc"], r["out"], r["err"]) == (3, "o\n", "e\n")


def test_large_command(session):
    assert session.run("echo %s | wc -c" % ("A" * 60000))["out"].strip() == "60001"


def test_large_output(session):
    assert len(session.run("head -c 3000000 /dev/zero | tr '\\0' x")["out"]) == 3000000


def test_many_commands_one_session(session):
    for i in range(1, 301):
        out = session.run("echo n=%d" % i)["out"]
    assert out == "n=300\n"


def test_command_cannot_eat_the_stream(session):
    session.run("cat")                      # would swallow later input if stdin weren't /dev/null
    assert session.run("echo ok")["out"] == "ok\n"


def test_answers_prompt_and_strips_it(session):
    cmd = ("printf 'Password for x: ' >/dev/tty; read -rs p </dev/tty; echo >/dev/tty; "
           "echo got=$p")
    r = session.run(cmd, answers=[(r"Password for x: ?", "pw1")])
    assert r["out"] == "got=pw1\n"


def test_timeout_terminates_session(session):
    with pytest.raises(nb.CommandTimeout):
        session.run("sleep 20", timeout=1)
    with pytest.raises(nb.NewroleError):
        session.run("echo x")


def test_shell_exit_raises_session_dead(session):
    with pytest.raises(nb.SessionDead):
        session.run("exit 3")


def test_wrong_password_is_auth_error(backend, make_session):
    if backend == "real" and not REAL.allow_lockout:
        pytest.skip("counts toward pam_faillock; set NRB_ALLOW_LOCKOUT=1")
    with pytest.raises(nb.AuthError):
        make_session(backend, password=b"definitely-wrong").start()
    with make_session(backend) as s:                    # and a normal login still works
        assert s.run("echo ok")["out"] == "ok\n"


def test_password_wiped(backend, make_session):
    s = make_session(backend)
    pw = s.password
    with s:
        pass
    assert pw == bytearray(len(pw))


# ------------------------------------------------------------------- fake only
def test_truncation_keeps_marker(make_session):
    with make_session("fake", max_output=10000) as s:
        r = s.run("head -c 200000 /dev/zero | tr '\\0' x; echo end")
        assert r["truncated"] and r["out"].endswith("end\n") and len(r["out"]) < 20000
        assert s.run("echo after")["out"] == "after\n"


def test_reprompt_is_auth_error(tmp_path, monkeypatch):
    path = tmp_path / "newrole"
    path.write_text("#!/bin/bash\nprintf 'Password: '\nread -rs p\necho\n"
                    "printf 'Password: '\nsleep 30\n")
    path.chmod(0o700)
    monkeypatch.setattr(nb.NewroleSession, "_check_newrole", lambda self: None)
    with pytest.raises(nb.AuthError):
        nb.NewroleSession("r_r", bytearray(b"x"), newrole=str(path), auth_timeout=8).start()


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
    with pytest.raises(nb.UsageError):
        nb.read_password(args, "r_r")
    f.chmod(0o600)
    assert nb.read_password(args, "r_r") == bytearray(b"secret")
    f.write_text("\n")
    with pytest.raises(nb.UsageError, match="empty"):
        nb.read_password(args, "r_r")


def test_cli_usage_errors_exit_2_without_traceback(tmp_path, capsys):
    pw = tmp_path / "pw"
    pw.write_text("x\n")
    pw.chmod(0o600)
    base = ["local", "-r", "r_r", "--password-file", str(pw)]
    assert nb.main(base + ["--commands-file", str(tmp_path / "nope")]) == nb.EXIT_USAGE
    assert "nope" in capsys.readouterr().err
    assert nb.main(["local", "-r", "r_r", "-c", "id", "--password-file", str(tmp_path / "nope")]) == nb.EXIT_USAGE
    assert nb.main(["local", "-r", "r_r"]) == nb.EXIT_USAGE


def test_commands_keep_command_line_order(tmp_path):
    cf, sf = tmp_path / "cmds", tmp_path / "s.sh"
    cf.write_text("# c\nb\n")
    sf.write_text("d\n")
    a = nb.argparse.Namespace(sources=[("c", "a"), ("f", str(cf)), ("c", "c"), ("s", str(sf))])
    assert nb.gather_commands(a) == ["a", "b", "c", "d\n"]


def test_audit_splits_long_messages(monkeypatch):
    seen = []
    monkeypatch.setattr(nb.syslog, "syslog", lambda prio, m: seen.append(m))
    nb.Audit("full", True).log("x" * 2000)
    assert len(seen) == 3 and seen[0].startswith("[part 1/3]")
    assert sum(m.count("x") for m in seen) == 2000


def test_remote_command_is_quoted():
    assert nb.remote_command("python3", "/a b/x.py") == "python3 '/a b/x.py' serve"
    assert "'; rm" not in nb.remote_command("python3", None)


def fake_ssh(tmp_path, body):
    path = tmp_path / "fakessh"
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o700)
    return str(path)


READY = """echo '{"event": "ready", "context": "test:ctx"}'\n"""


def test_ssh_exiting_before_login_is_session_dead_not_broken_pipe(tmp_path):
    ssh = fake_ssh(tmp_path, "exit 255\n")
    with pytest.raises(nb.SessionDead, match="before login"):
        nb.RemoteSession("h", {"role": "r_r"}, bytearray(b"x"), ssh=ssh).start()


def test_cli_ssh_failure_exits_4_without_traceback(tmp_path):
    ssh = fake_ssh(tmp_path, "exit 255\n")
    pw = tmp_path / "pw"
    pw.write_text("x\n")
    pw.chmod(0o600)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "newrole_batch.py"), "ssh", "h", "--ssh", ssh,
                        "--password-file", str(pw), "-r", "r_r", "-c", "id"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == nb.EXIT_SESSION
    assert "Traceback" not in r.stderr and "before login" in r.stderr


def test_remote_run_before_start_is_session_dead():
    with pytest.raises(nb.SessionDead):
        nb.RemoteSession("h", {"role": "r_r"}, bytearray(b"x")).run("id")


def test_remote_backstop_timeout_kills_the_connection(tmp_path, monkeypatch):
    """A reply that arrives after the backstop must not be read as the next command's answer."""
    monkeypatch.setattr(nb, "REPLY_GRACE", 0.2)
    ssh = fake_ssh(tmp_path, READY + """read -r _; read -r _; read -r _; sleep 1
echo '{"rc": 0, "out": "late", "err": "", "truncated": false, "duration": 0}'
cat >/dev/null\n""")
    s = nb.RemoteSession("h", {"role": "r_r"}, bytearray(b"x"), ssh=ssh, remote_path="/x").start()
    with pytest.raises(nb.CommandTimeout):
        s.run("first", timeout=0.1)
    with pytest.raises(nb.SessionDead):
        s.run("second")
    s.close()


def test_cli_ctrl_c_exits_130_cleanly(tmp_path):
    ssh = fake_ssh(tmp_path, READY + "cat >/dev/null\n")        # ready, then never answers
    pw = tmp_path / "pw"
    pw.write_text("x\n")
    pw.chmod(0o600)
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "newrole_batch.py"), "ssh", "h", "--ssh", ssh,
                          "--password-file", str(pw), "-r", "r_r", "-c", "sleep 100"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    p.send_signal(signal.SIGINT)
    _out, err = p.communicate(timeout=30)
    assert p.returncode == nb.EXIT_INTERRUPT
    assert "Traceback" not in err and "interrupted" in err


# ------------------------------------------------------------------- real host only
def cli(real, secrets, *args, **kw):
    """Run the CLI in ssh mode against the real host; returns CompletedProcess."""
    opts, env = ssh_args(secrets)
    argv = [sys.executable, os.path.join(ROOT, "newrole_batch.py"), "ssh", real.target]
    for o in opts:
        argv.append("--ssh-opt=" + o)
    argv += ["--password-file", kw.pop("pwfile", secrets["pwfile"])]
    if "-r" not in args:
        argv += ["-r", real.role]
    return subprocess.run(argv + list(args), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=120, env=dict(os.environ, **(env or {})))


def test_real_lands_in_requested_role(real, make_session):
    with make_session("real") as s:
        assert s.context.split(":")[1] == real.role


def test_real_cli_exit_codes(real, secrets):
    assert cli(real, secrets, "-c", "true").returncode == 0
    assert cli(real, secrets, "-c", "false").returncode == 1
    assert cli(real, secrets, "--timeout", "2", "-c", "sleep 20").returncode == 5
    assert cli(real, secrets, "-c", "exit 3").returncode == 4
    assert cli(real, secrets, "-r", "nosuch_r", "-c", "id").returncode == 3
    assert cli(real, secrets, "-t", "nosuch_t", "-c", "id").returncode == 3


def test_real_cli_json_keeps_output_exact(real, secrets):
    r = cli(real, secrets, "--json", "-c", "printf x")
    assert r.stdout.startswith('{"rc": 0, "out": "x"')


def test_real_cli_state_commands_file_and_script(real, secrets, tmp_path):
    assert cli(real, secrets, "-c", "cd /etc", "-c", "pwd").stdout == "/etc\n"
    many = tmp_path / "many"
    many.write_text("".join("echo n=%d\n" % i for i in range(1, 301)))
    assert cli(real, secrets, "--commands-file", str(many)).stdout.splitlines()[-1] == "n=300"
    big = tmp_path / "big.sh"
    big.write_text("echo %s | wc -c\n" % ("A" * 60000))
    assert cli(real, secrets, "--script", str(big)).stdout.strip() == "60001"


def test_real_cli_loose_password_file_refused(real, secrets, tmp_path):
    loose = tmp_path / "loose"
    with open(secrets["pwfile"], "rb") as f:
        loose.write_bytes(f.read())
    loose.chmod(0o644)
    assert cli(real, secrets, "-c", "id", pwfile=str(loose)).returncode != 0


def test_real_cli_wrong_password_exits_3_once(real, secrets, tmp_path):
    if not real.allow_lockout:
        pytest.skip("counts toward pam_faillock; set NRB_ALLOW_LOCKOUT=1")
    bad = tmp_path / "bad"
    bad.write_text("definitely-wrong\n")
    bad.chmod(0o600)
    r = cli(real, secrets, "-c", "id", pwfile=str(bad))
    assert r.returncode == 3
    assert (r.stdout + r.stderr).count("incorrect password") == 1      # no retry loop
    assert cli(real, secrets, "-c", "echo ok").stdout == "ok\n"        # account still usable


def test_real_nesting(real, secrets, make_session):
    """ssh A, newrole, ssh B (from A's role shell), newrole, then back on A."""
    if not real.nest_host:
        pytest.skip("set NRB_NEST_HOST to exercise nesting")
    import example
    pw = real.get_password()
    with make_session("real") as a:
        helper = None
        opts, ssh = ["-oLogLevel=ERROR", "-oBatchMode=yes"], "ssh"
        if real.nest_key:
            opts += ["-i", real.nest_key, "-oIdentitiesOnly=yes"]
        else:
            helper, ssh = example.make_askpass_ssh(a, pw.decode())
            opts = ["-oLogLevel=ERROR", "-oPubkeyAuthentication=no", "-oNumberOfPasswordPrompts=1"]
        try:
            with a.nest(real.nest_host, {"role": real.role}, bytearray(pw), ssh=ssh,
                        ssh_opts=opts) as b:
                assert b.run("echo nested-ok", timeout=10)["out"] == "nested-ok\n"
                with pytest.raises(nb.CommandTimeout):
                    b.run("sleep 20", timeout=2)
            assert a.run("echo back-on-a", timeout=10)["out"] == "back-on-a\n"
        finally:
            if helper:
                a.run("rm -rf '%s'" % helper)


def test_source_is_ascii_and_py2_safe():
    """The file is exec()ed on targets that may only have python 2.7: no non-ASCII source, no
    py3-only constructs that cannot even be parsed there."""
    with open(nb.__file__.replace(".pyc", ".py"), "rb") as f:
        src = f.read()
    src.decode("ascii")
    for banned in (b"super()", b"sys.stdin.buffer", b"BlockingIOError", b"ChildProcessError", b"BrokenPipeError",
                   b" rb\"", b"(rb\"", b".clear()", b"time.monotonic()", b"shlex.quote"):
        assert banned not in src, banned
