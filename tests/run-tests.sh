#!/bin/bash
# Integration tests against a real target. Needs key-based ssh to the unprivileged user.
#   TARGET=user@192.0.2.10 SSH_KEY=~/.ssh/id_rsa PWFILE=./pw ROLE=sysadm_r tests/run-tests.sh
# PWFILE: mode 0600, one line, the user's password. WARNING: runs one deliberately wrong-password attempt.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${TARGET:?set TARGET=user@host}; PWFILE=${PWFILE:?set PWFILE}; ROLE=${ROLE:-sysadm_r}
SSH_KEY=${SSH_KEY:-}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
nr() { python3 "$HERE/newrole_batch.py" ssh "$TARGET" ${SSH_KEY:+--ssh-opt=-i --ssh-opt="$SSH_KEY"} \
         --ssh-opt=-oBatchMode=yes --ssh-opt=-oLogLevel=ERROR --password-file "$PWFILE" -r "$ROLE" "$@"; }
pass=0; fail=0
check() { # check "name" expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1 (expected '$2', got '$3')"; fi; }

check "lands in requested role"      "staff_u:$ROLE" "$(nr -c 'id -Z' | cut -d: -f1,2)"
check "state persists across cmds"   "/etc"          "$(nr -c 'cd /etc' -c pwd)"
check "--isolate hides state"        "$(nr --isolate -c pwd)" "$(nr --isolate -c 'cd /etc' -c pwd)"
check "exit code propagates (rc=1)"  "1"             "$(nr -c false 2>/dev/null; echo $?)"
check "quotes/newlines/\$ survive"   'a"b $HOME
c'                                                    "$(nr -c 'printf "%s\n" "a\"b \$HOME" ; echo c' | sed "s|/home/[a-z]*|\$HOME|")"
check "no trailing newline kept"     '{"rc": 0, "out": "x"'  "$(nr --json -c 'printf x' | cut -d, -f1-2)"
python3 -c "print('echo ' + 'A'*60000 + ' | wc -c')" > "$T/big.sh"
check "60 KB command"                "60001"         "$(nr --script "$T/big.sh")"
check "20 MB output"                 "20000000"      "$(nr --json -c 'head -c 20000000 /dev/zero | tr "\0" x' | python3 -c 'import sys,json;print(len(json.loads(sys.stdin.readline())["out"]))')"
seq 1 300 | sed 's/^/echo n=/' > "$T/many"
check "300 cmds, single auth"        "n=300"         "$(nr --commands-file "$T/many" | tail -1)"
check "command can't eat the stream" "ok"            "$(nr -c 'cat' -c 'echo ok' | tail -1)"
check "timeout => exit 5"            "5"             "$(nr --timeout 2 -c 'sleep 20' >/dev/null 2>&1; echo $?)"
check "dead shell => exit 4"         "4"             "$(nr -c 'exit 3' >/dev/null 2>&1; echo $?)"
check "bad role => exit 3"           "3"             "$(nr -r nosuch_r -c id >/dev/null 2>&1; echo $?)"
check "wrong type => exit 3"         "3"             "$(nr -t nosuch_t -c id >/dev/null 2>&1; echo $?)"
printf 'definitely-wrong\n' > "$T/bad"; chmod 600 "$T/bad"
check "wrong password => exit 3"     "3"             "$(nr --password-file "$T/bad" -c id >/dev/null 2>&1; echo $?)"
check "...and no retry loop"         "1"             "$(nr --password-file "$T/bad" -c id 2>&1 | grep -c 'incorrect password')"
chmod 644 "$T/bad"
check "loose pw file refused"        "1"             "$(nr --password-file "$T/bad" -c id >/dev/null 2>&1; [ $? -ne 0 ] && echo 1)"
check "recovers after bad attempt"   "ok"            "$(nr -c 'echo ok')"

# Nesting (ssh A, newrole, ssh B *from A's role shell*, newrole): needs a key A can already
# reach on its own filesystem for the inner hop. NEST_HOST/NEST_KEY are paths/hosts as seen
# FROM the target, not from here -- optional; skipped (not failed) if unset.
if [ -n "${NEST_HOST:-}" ] && [ -n "${NEST_KEY:-}" ]; then
  out=$(PYTHONPATH="$HERE" PW="$(cat "$PWFILE")" python3 - "$TARGET" "$ROLE" "$NEST_HOST" "$NEST_KEY" "$SSH_KEY" <<'EOF'
import sys, os
from newrole_batch import RemoteSession
target, role, nest_host, nest_key, ssh_key = sys.argv[1:6]
pw = bytearray(os.environ["PW"].encode())
outer = (["-i", ssh_key, "-oIdentitiesOnly=yes"] if ssh_key else []) + ["-oBatchMode=yes", "-oLogLevel=ERROR"]
inner = ["-i", nest_key, "-oIdentitiesOnly=yes", "-oBatchMode=yes", "-oStrictHostKeyChecking=no", "-oLogLevel=ERROR"]
with RemoteSession(target, {"role": role}, pw, ssh_opts=outer) as a:
    with a.nest(nest_host, {"role": role}, bytearray(os.environ["PW"].encode()), ssh_opts=inner) as b:
        print(b.run("echo nested-ok", timeout=10)["out"].strip())
    print(a.run("echo back-on-a", timeout=10)["out"].strip())
EOF
)
  check "nest: ssh A, newrole, ssh B, newrole" "nested-ok
back-on-a" "$out"
else
  echo "skip - nesting (set NEST_HOST and NEST_KEY to exercise it)"
fi

echo; echo "passed=$pass failed=$fail"; [ $fail -eq 0 ]
