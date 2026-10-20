# newrole-batch

Run many commands in an SELinux role that requires `newrole` + a PAM password prompt,
authenticating **once** per batch. Single file, Python ≥ 3.6, **standard library only**
(nothing to download or vendor; works on the stock el7 and el9 `python3`).

## Use

```bash
# from a controller, over ssh (script is streamed over ssh stdin; nothing is written on the target)
./newrole_batch.py ssh user@host --ssh-key ~/.ssh/id_rsa \
    --password-file ./pw -r sysadm_r \
    -c 'id -Z' -c 'systemctl status sshd' --commands-file cmds.txt --script setup.sh --json

# directly on the target (as the logged-in user)
./newrole_batch.py local -r sysadm_r -t sysadm_t -c 'semodule -l | wc -l'
```

| option | meaning |
|---|---|
| `-r/-t/-l` | role / type / MLS level passed to `newrole` |
| `-c CMD` (repeatable), `--commands-file F` (one per line), `--script F` (whole file = one command) | what to run, in command-line order |
| `--ssh-key F`, `--ssh-opt=X` (repeatable; use the `=` form for values starting with `-`) | ssh login key / extra ssh arguments |
| `--isolate` | each command in a subshell (default: one persistent shell, so `cd`/vars carry over) |
| `--stop-on-error`, `--timeout S`, `--json` | control / output |
| `--password-file F` (must be 0600, yours) / `--password-fd N` / `--password-stdin` / tty prompt | password sources. **Never argv or env.** |
| `--audit none\|hash\|full` | syslog(authpriv) record of commands; default logs a sha256 prefix only |
| `--remote-path P` | use a pre-installed copy on the target instead of streaming |

Exit codes: `0` ok · `1` a command returned non-zero · `2` usage (bad options, missing/unsafe password or command file) · `3` auth/context failure ·
`4` session/connection died (including ssh failing before login) · `5` timeout · `130` interrupted (Ctrl-C;
the session is closed cleanly).

Python example (`examples/example.py`): ssh login with a password or key, output, separate stdout/stderr,
and a command that needs a second password (`sudo`) answered automatically:

```python
with RemoteSession("user@host", {"role": "sysadm_r"}, bytearray(pw), ssh_opts=[...]) as s:
    s.run("id -Z")                                              # {'rc', 'out'}  (stderr merged)
    s.run("ls /nope", stderr=True, isolate=True)                # {'rc', 'out', 'err'}
    s.run("sudo id -un", answers=[(r"\[sudo\] password for \w+: ?", pw)])   # typed once, prompt stripped
```

Library use: `NewroleSession(...)` (on the target) and `RemoteSession(...)` (over ssh) both expose
`run(cmd, timeout, isolate) -> {rc, out, truncated}`, so later commands can depend on earlier results.

**Nesting** (`.nest()`): ssh A, newrole, then *from inside A's role shell* ssh B, newrole — reaching
a second host through the first one's already-authenticated, already-audited session, the same way a
sysadmin would do it by hand, rather than as a second, independent connection from the controller:

```python
with RemoteSession("user@A", {"role": "sysadm_r"}, pwA, ssh_opts=[...]) as a:
    a.run("...")                                          # commands on A
    with a.nest("user@B", {"role": "sysadm_r"}, pwB, ssh_opts=[...]) as b:
        b.run("...")                                      # commands on B, same run()/stderr/answers
    a.run("...")                                           # back on A once the nested `with` exits
```
`ssh_opts` for `.nest()` describe how **A** reaches B (e.g. a key path on A's own filesystem, not the
controller's) — A runs that `ssh` command itself, inside its role shell. `.nest()` on the object
`.nest()` returns opens a third hop, and so on; only one nested session may be open at a time per
level (close it, or exit its `with` block, before opening another at that level). Also available as
`NewroleSession.nest(...)` for the `local` mode / in-process case.

## How it works / security properties

* One pty → one `newrole` → one persistent `bash` in the new context. Commands are base64-framed with a
  per-session random marker, so quoting, newlines, 60 KB+ commands and 20 MB+ output don't desync it.
  Commands run with `</dev/null`, so a stray `cat` can't swallow the stream. stderr is merged with stdout (pty).
* **Password is sent once, never retried.** A wrong password = exactly one PAM failure, so `pam_faillock`
  can't be tripped by the tool. A re-prompt or early exit aborts (exit 3).
* **Fails closed:** the real context is read from `/proc/$$/attr/current` after login and must match `-r`/`-t`.
* Password never appears in argv, env, ssh command line, disk, or logs. Sent to the target on ssh
  stdin. Process sets `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, umask 077, wipes its `bytearray` copy. Python can't guarantee zeroisation of every transient copy.
* `newrole` is invoked by absolute path, checked root-owned/not writable, with a scrubbed environment.
* Shell is non-interactive (`bash --noprofile --norc /dev/stdin`): no profile, `TMOUT`, history or prompt.

## Security warnings / responsible use

* **Authorized use only.** This tool types a real account's password into `newrole`/PAM prompts. Use it only on
  systems and accounts you are authorized to administer. It does not bypass authentication, it is not a
  password-guessing tool, and it deliberately never retries a failed password.
* **You are handing it a credential.** Anything that can read the process (same uid, root, a debugger) or the
  password file can read the password. Keep `--password-file` 0600 on an encrypted disk, never commit it, and
  delete it when finished. Prefer a short-lived or dedicated account. The "no copies in memory" and wiping
  measures are best-effort only.
* **Commands are run with your privileges.** Whatever you pass to `-c`, `--commands-file` or `--script` runs in
  the elevated role, so review untrusted command files first and never build commands from untrusted input
  (shell injection). `--stop-on-error` is off by default: a failed step does not stop later ones.
* **Output may contain secrets.** Command output goes to stdout/`--json`; redirecting it to files, CI logs or
  tickets can leak whatever the commands print. `--audit full` also writes complete command text (long commands are split over several syslog lines) (including any
  secrets you embedded in it) to syslog; the default logs only a hash prefix.
* **`answers=` passwords** (e.g. for sudo) travel as ordinary Python strings and are not wiped.
* **Host keys.** Over ssh, do not disable host key checking via `--ssh-opt`. Doing so lets a man-in-the-middle
  capture the password.
* **`SSH_ASKPASS` in the test suite** exposes the password to a helper script for the duration of a test run;
  only use the real-host tests against hosts and accounts you own, and note that the wrong-password tests
  count towards `pam_faillock` and can lock the account.
* **Not independently audited.** Treat the security properties above as design intent, not a guarantee, and
  review the code before using it in a sensitive environment. Report vulnerabilities privately to the
  maintainer rather than in a public issue.
* Provided "as is", without warranty; you are responsible for complying with your organisation's policies.

## Limits (by design)

* `newrole` changes the **SELinux role**, not the uid: commands run as the login user in `sysadm_t`. Root-only
  operations still need `sudo`/su inside the batch (and its own auth).
* A timeout sends Ctrl-C to the pty's foreground group, which also takes down `newrole`; the session is
  ended and the remaining commands are not run (exit 5). Use per-command `timeout N cmd` inside the batch to
  keep the session alive.
* `exit` / a shell crash inside a command ends the session (exit 4). `set -e`/`set -u` in persistent mode
  persist; use `--isolate` to avoid that.
* Passwords containing a newline are unsupported.

## Tests

One pytest suite, two interchangeable backends (`tests/conftest.py`):

```
pip install -r requirements-dev.txt
python3 -m pytest tests            # offline: NewroleSession against a fake `newrole` on a pty
```

To also run everything against a real SELinux host, copy `tests/.env.example` to `tests/.env`
(git-ignored) and fill in `NRB_TARGET`, `NRB_PASSWORD_FILE` (or `NRB_PASSWORD`) and optionally
`NRB_SSH_KEY`; without a key, ssh logs in with the same password via `SSH_ASKPASS`. Environment
variables override the file. With a target set, the shared tests run on both backends and the
real-only tests (SELinux context, CLI exit codes, `--commands-file`/`--script`, nesting with
`NRB_NEST_HOST`) are enabled. The wrong-password tests count toward `pam_faillock` and need
`NRB_ALLOW_LOCKOUT=1` against a real host.

## License

MIT, see [LICENSE](LICENSE).
