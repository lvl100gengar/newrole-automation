#!/usr/bin/env python3
"""Example: log in to a remote host as USER, enter a SELinux role with newrole (password
typed automatically, once), then:
   1. run a command and get its output
   2. run a command and get stdout and stderr separately (+ exit code)
   3. run a command that asks for a SECOND password (sudo) and answer it automatically
   4. (if --nest-host is given) SSH from *inside that role shell* into a second host and
      newrole there too -- ssh A, newrole, ssh B, newrole -- then come back to A

Usage:
    NRB_PASSWORD='...' ./example.py user@192.0.2.10 [--key ~/.ssh/id_rsa] [--role sysadm_r]
    NRB_PASSWORD='...' ./example.py user@A --key ~/.ssh/id_rsa \\
        --nest-host user@B --nest-key /path/to/key/as/found/on/A

--nest-key is a path *on host A* (the nested ssh runs inside A's own shell, so it needs a
key A can already reach, e.g. one A uses to manage downstream hosts). Omit it to use password
auth for the inner hop instead: the demo then drops a short-lived askpass helper (holding the
password, mode 0700) into a temp dir under $HOME on A, because ssh on A prompts on A's tty
and the nested handshake would otherwise be typed into that prompt. It is removed afterwards.

The same password is used for ssh (if no --key), for newrole, and for sudo in this demo.
Requires only newrole_batch.py (one directory up) and the stock ssh client.
"""
import argparse
import base64
import os
import shlex
import sys

# SSH_ASKPASS support: ssh runs *this script* to ask for the ssh password; we answer from the
# environment of that one child process, so the password never lands in argv or on disk.
if os.environ.get("NRB_ASKPASS_MODE"):
    print(os.environ["NRB_SSH_PASSWORD"])
    sys.exit(0)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from newrole_batch import RemoteSession, NewroleError, AuthError  # noqa: E402


def make_askpass_ssh(sess, password):
    """On host A (inside the role shell) create an ssh wrapper that answers ssh's password
    prompt via SSH_ASKPASS. Returns (temp_dir, wrapper_path). $HOME is used because /tmp is
    often noexec; chcon gives the helpers a type the confined ssh may execute (best effort)."""
    r = sess.run('umask 077; mktemp -d -p "$HOME" nrb-askpass.XXXXXX')
    if r["rc"]:
        raise NewroleError("cannot create helper dir on host: %s" % r["out"].strip())
    d = r["out"].strip()
    files = {
        "ap": "#!/bin/sh\nprintf '%%s\\n' %s\n" % shlex.quote(password),
        "ssh": "#!/bin/sh\nexec setsid env SSH_ASKPASS=%s/ap DISPLAY=none ssh \"$@\"\n" % d,
    }
    cmds = ["echo %s | base64 -d > %s/%s" % (base64.b64encode(t.encode()).decode(), d, n)
            for n, t in files.items()]
    cmds += ["chmod 700 %s/ap %s/ssh" % (d, d), "chcon -t bin_t %s/ap %s/ssh 2>/dev/null; true" % (d, d)]
    sess.run("; ".join(cmds))
    return d, d + "/ssh"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="user@host")
    ap.add_argument("--role", default="sysadm_r")
    ap.add_argument("--key", help="ssh private key (otherwise ssh password auth is used)")
    ap.add_argument("--nest-host", help="[user@]host reachable FROM the target, for step 4")
    ap.add_argument("--nest-key", help="private key path ON the target, used for the inner hop")
    a = ap.parse_args()
    password = os.environ.get("NRB_PASSWORD")
    if not password:
        sys.exit("set NRB_PASSWORD in the environment")

    ssh_opts, ssh_env = ["-oLogLevel=ERROR"], None
    if a.key:
        ssh_opts += ["-i", a.key, "-oIdentitiesOnly=yes", "-oBatchMode=yes"]
    else:                                   # password login for ssh itself, via askpass
        ssh_opts += ["-oPubkeyAuthentication=no", "-oNumberOfPasswordPrompts=1"]
        ssh_env = {"SSH_ASKPASS": os.path.abspath(__file__), "SSH_ASKPASS_REQUIRE": "force",
                   "NRB_ASKPASS_MODE": "1", "NRB_SSH_PASSWORD": password, "DISPLAY": "none"}

    cfg = {"role": a.role}                  # add "type": "sysadm_t" / "level": ... if you need them
    sess = RemoteSession(a.target, cfg, bytearray(password.encode()),
                         ssh_opts=ssh_opts, ssh_env=ssh_env)
    try:
        with sess:                          # ssh + newrole + password prompt happen here, once
            print("logged in, context:", sess.context)

            # 1. plain command, output merged (like a terminal would show it)
            r = sess.run("id -Z; hostname")
            print("\n[1] rc=%d output:\n%s" % (r["rc"], r["out"]))

            # 2. stdout and stderr separately. isolate=True runs it in a subshell, so the
            #    `exit 3` yields rc=3 instead of ending the whole persistent session.
            r = sess.run("echo to-stdout; echo to-stderr >&2; ls /nonexistent; exit 3",
                         stderr=True, isolate=True)
            print("[2] rc=%d\n    stdout=%r\n    stderr=%r\n" % (r["rc"], r["out"], r["err"]))

            # 3. command that prompts for another password: sudo. The regex says which prompt to
            #    answer; the password is typed once and the prompt is stripped from the output.
            r = sess.run("sudo -k; sudo id -un", stderr=True,
                         answers=[(r"\[sudo\] password for \w+: ?", password)])
            print("[3] rc=%d\n    stdout=%r\n    stderr=%r" % (r["rc"], r["out"], r["err"]))

            # 4. ssh A, newrole, (from A) ssh B, newrole: a second newrole session on a
            #    second host, reached by running ssh *inside this role shell on A*, not as a
            #    separate connection from the controller -- so B is reached through A's
            #    already-authenticated, already-audited context, same as a sysadmin typing
            #    it by hand at A's prompt. sess.nest() does the ssh + password handshake once
            #    and returns a session with the exact same run() interface.
            if a.nest_host:
                helper_dir = None
                nest_opts = ["-oLogLevel=ERROR", "-oBatchMode=yes"]
                nest_ssh = "ssh"
                if a.nest_key:
                    nest_opts += ["-i", a.nest_key, "-oIdentitiesOnly=yes"]
                else:                       # password auth for the inner hop, via a temp askpass
                    helper_dir, nest_ssh = make_askpass_ssh(sess, password)
                    nest_opts = ["-oLogLevel=ERROR", "-oPubkeyAuthentication=no",
                                 "-oNumberOfPasswordPrompts=1"]
                try:
                    with sess.nest(a.nest_host, {"role": a.role}, bytearray(password.encode()),
                                   ssh=nest_ssh, ssh_opts=nest_opts) as nested:
                        print("\n[4] nested into %s, context: %s" % (a.nest_host, nested.context))
                        r = nested.run("id -Z; hostname")
                        print("    on B: rc=%d output:\n%s" % (r["rc"], r["out"]))
                    # back on A automatically once the `with` block above closes B's session
                    r = sess.run("echo back on A; hostname")
                    print("    back on A: rc=%d output:\n%s" % (r["rc"], r["out"]))
                finally:
                    if helper_dir:
                        sess.run("rm -rf %s" % shlex.quote(helper_dir))
    except AuthError as e:
        sys.exit("login failed (wrong password / role not allowed): %s" % e)
    except NewroleError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
