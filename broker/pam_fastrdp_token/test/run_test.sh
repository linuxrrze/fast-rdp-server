#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Functional test of pam_fastrdp_token. Usage: run_test.sh path/to/pam_fastrdp_token.so path/to/harness
set -eu
MOD=$(readlink -f "$1"); HARNESS=$(readlink -f "$2")
T=$(mktemp -d); trap 'kill $FAKE 2>/dev/null || true; rm -rf "$T"' EXIT
python3 "$(dirname "$0")/fake_broker.py" "$T/token.sock" > "$T/fake.log" &
FAKE=$!
while ! grep -q ready "$T/fake.log" 2>/dev/null; do sleep 0.1; done
mkdir "$T/pam.d"
# The next module sees PAM_AUTHTOK like pam_sss would (libpam wipes it before returning to the app).
printf '#!/bin/sh\ncat > %s/seen; printf "\\n" >> %s/seen\n' "$T" "$T" > "$T/capture.sh"; chmod +x "$T/capture.sh"
cat > "$T/pam.d/fastrdp-test" <<EOT
auth [success=ok ignore=1 default=die] $MOD socket=$T/token.sock timeout=2
auth optional pam_exec.so quiet expose_authtok $T/capture.sh
auth required pam_permit.so
EOT
fail=0
check() { # user secret expected  ("seen=" is what the next module received)
  rm -f "$T/seen"
  rc=$("$HARNESS" "$T/pam.d" "$1" "$2" | cut -d" " -f1)
  got="$rc seen=$(cat "$T/seen" 2>/dev/null || echo '-')"
  if [ "$got" = "$3" ]; then echo "ok   $1 $2 -> $got"; else echo "FAIL $1 $2 -> $got (want $3)"; fail=1; fi
}
check alice fastrdp1:good "rc=0 seen=RealPassw0rd"
check alice fastrdp1:nopw "rc=0 seen=-"   # pam_sss skipped
check alice fastrdp1:bad  "rc=7 seen=-"
check bob   fastrdp1:good "rc=7 seen=-"
check alice plainpassword "rc=7 seen=-"
exit $fail
