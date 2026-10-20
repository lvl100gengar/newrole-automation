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
key A can already reach, e.g. one A uses to manage downstream hosts) -- omit it to use
--nest-password-is-same (password auth for the inner hop instead, if A allows it).

The same password is used for ssh (if no --key), for newrole, and for sudo in this demo.
Requires only newrole_batch.py (one directory up) and the stock ssh client.
"""
import argparse
import os
import sys

# SSH_ASKPASS support: ssh runs *this script* to ask for the ssh password; we answer from the
# environment of that one child process, so the password never lands in argv or on disk.
if os.environ.get("NRB_ASKPASS_MODE"):
    print(os.environ["NRB_SSH_PASSWORD"])
    sys.exit(0)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from newrole_batch import RemoteSession, NewroleError, AuthError  # noqa: E402


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
                nest_opts = ["-oLogLevel=ERROR", "-oBatchMode=yes"]
                if a.nest_key:
                    nest_opts += ["-i", a.nest_key, "-oIdentitiesOnly=yes"]
                with sess.nest(a.nest_host, {"role": a.role}, bytearray(password.encode()),
                               ssh_opts=nest_opts) as nested:
                    print("\n[4] nested into %s, context: %s" % (a.nest_host, nested.context))
                    r = nested.run("id -Z; hostname")
                    print("    on B: rc=%d output:\n%s" % (r["rc"], r["out"]))
                # back on A automatically once the `with` block above closes B's session
                r = sess.run("echo back on A; hostname")
                print("    back on A: rc=%d output:\n%s" % (r["rc"], r["out"]))
    except AuthError as e:
        sys.exit("login failed (wrong password / role not allowed): %s" % e)
    except NewroleError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
