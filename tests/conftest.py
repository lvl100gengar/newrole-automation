"""Test configuration: one suite, two interchangeable backends.

  fake  NewroleSession against a fake `newrole` (bash on a pty). Offline, the default.
  real  RemoteSession against a real SELinux host over ssh. Enabled by setting NRB_TARGET.

Settings come from the environment or from a .env file (tests/.env, then ./.env); real
environment variables win. See tests/.env.example. NRB_BACKEND=fake|real|both overrides
which backends run (default: fake, plus real when NRB_TARGET is set).
"""
import os
import shlex
import stat
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))
import newrole_batch as nb

FAKE_NEWROLE = """#!/bin/bash
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
FAKE_PASSWORD = b"secret"


def _load_dotenv():
    """KEY=VALUE lines; '#' comments, optional 'export ', optional quotes. Never overrides
    variables already in the environment. Relative *_FILE / *_KEY paths resolve against the
    .env file's directory."""
    for path in (os.path.join(HERE, ".env"), os.path.join(ROOT, ".env")):
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip().replace("export ", "", 1).strip()
                val = val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                    val = val[1:-1]
                if key.endswith(("_FILE", "_KEY")) and val:
                    val = os.path.expanduser(val)
                    if not os.path.isabs(val):
                        val = os.path.join(os.path.dirname(path), val)
                os.environ.setdefault(key, val)


_load_dotenv()


class Real:
    """Settings for the real-host backend, all from NRB_* variables."""

    def __init__(self):
        e = os.environ.get
        self.target = e("NRB_TARGET")
        self.role = e("NRB_ROLE", "sysadm_r")
        self.key = e("NRB_SSH_KEY") and os.path.expanduser(e("NRB_SSH_KEY"))
        self.password = e("NRB_PASSWORD")
        self.pwfile = e("NRB_PASSWORD_FILE")
        self.extra_ssh_opts = shlex.split(e("NRB_SSH_OPTS", ""))
        self.nest_host = e("NRB_NEST_HOST")
        self.nest_key = e("NRB_NEST_KEY")       # path ON the target; omit for password auth
        self.remote_python = e("NRB_REMOTE_PYTHON", "python3")   # interpreter on the target
        self.allow_lockout = e("NRB_ALLOW_LOCKOUT") == "1"

    def get_password(self):
        if self.password:
            return self.password.encode()
        if self.pwfile:
            with open(self.pwfile, "rb") as f:
                return f.readline().rstrip(b"\r\n")
        pytest.fail("real backend needs NRB_PASSWORD or NRB_PASSWORD_FILE")


REAL = Real()


def _backends():
    choice = os.environ.get("NRB_BACKEND") or ("both" if REAL.target else "fake")
    out = []
    if choice in ("fake", "both"):
        out.append("fake")
    if choice in ("real", "both"):
        if not REAL.target:
            raise pytest.UsageError("NRB_BACKEND=%s needs NRB_TARGET" % choice)
        out.append("real")
    return out


def pytest_generate_tests(metafunc):
    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", _backends())


@pytest.fixture
def real():
    if not REAL.target:
        pytest.skip("set NRB_TARGET to test against a real host")
    return REAL


@pytest.fixture(scope="session")
def secrets(tmp_path_factory):
    """Private (0600) password file + ssh-askpass helper for the real backend."""
    if not REAL.target:
        return None
    d = tmp_path_factory.mktemp("nrb-secrets")
    d.chmod(0o700)
    pwfile = d / "pw"
    pwfile.write_bytes(REAL.get_password() + b"\n")
    pwfile.chmod(0o600)
    askpass = d / "askpass"
    askpass.write_text("#!/bin/sh\ncat %s\n" % shlex.quote(str(pwfile)))
    askpass.chmod(0o700)
    return {"pwfile": str(pwfile), "askpass": str(askpass)}


def ssh_args(secrets):
    """(ssh options, extra environment for the ssh client) for the real backend."""
    opts = ["-oLogLevel=ERROR"] + REAL.extra_ssh_opts
    if REAL.key:
        return opts + ["-i", REAL.key, "-oIdentitiesOnly=yes", "-oBatchMode=yes"], None
    env = {"SSH_ASKPASS": secrets["askpass"], "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "none"}
    return opts + ["-oPubkeyAuthentication=no", "-oNumberOfPasswordPrompts=1"], env


@pytest.fixture
def make_session(request, tmp_path, monkeypatch):
    """make_session(backend, password=None, **cfg) -> unstarted session (use as `with`).
    cfg keys (max_output, auth_timeout, type, level) go to whichever backend is used."""
    def make(backend, password=None, **cfg):
        if backend == "fake":
            path = tmp_path / "newrole"
            path.write_text(FAKE_NEWROLE)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            monkeypatch.setattr(nb.NewroleSession, "_check_newrole", lambda self: None)
            monkeypatch.setattr(nb.NewroleSession, "_verify_context",
                                lambda self: setattr(self, "context", "test:ctx"))
            return nb.NewroleSession("r_r", bytearray(password or FAKE_PASSWORD),
                                     newrole=str(path), **cfg)
        secrets = request.getfixturevalue("secrets")
        opts, env = ssh_args(secrets)
        return nb.RemoteSession(REAL.target, dict(cfg, role=REAL.role),
                                bytearray(password or REAL.get_password()),
                                ssh_opts=opts, ssh_env=env, remote_python=REAL.remote_python)
    return make


@pytest.fixture
def session(backend, make_session):
    with make_session(backend) as s:
        yield s
