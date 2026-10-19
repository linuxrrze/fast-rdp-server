#!/bin/bash
# On a deployed fastrdp host (as root): benchmark one user's running Wayland session
# directly on its loopback back-end and through the proxy, to isolate proxy cost.
#   sudo tests/perf/compare-host.sh USER 'PASSWORD' [seconds]
# The user must already have a gnome/plasma session (log in once). Root may reach
# back-end ports (nftables exempts root). Use a test account in
# fastrdp_mfa_exempt_groups, or approve the push for the proxied run.
# Start load inside the session first, e.g. `perfload video` (tests/perf/rdpbench).
set -euo pipefail
USER_NAME=$1
PASSWORD=$2
SECS=${3:-30}
BENCH=${RDPBENCH:-$(dirname "$0")/rdpbench/rdpbench}
read -r PORT RDP_USER RDP_PASS BACKEND < <(python3 - "$USER_NAME" <<'PY'
import json, sys
for s in json.load(open("/var/lib/fastrdp/sessions.json")):
    if s["user"] == sys.argv[1] and s["backend"] in ("gnome", "plasma") and s["port"]:
        print(s["port"], s["rdp_user"], s["rdp_password"], s["backend"]); break
else:
    sys.exit("no running gnome/plasma session for " + sys.argv[1])
PY
)
echo "== direct: $BACKEND back-end on 127.0.0.1:$PORT"
"$BENCH" --host 127.0.0.1 --port "$PORT" --user "$RDP_USER" --password "$RDP_PASS" \
    --sec nla --seconds "$SECS" --json "direct-$USER_NAME.json" | tail -1
echo "== proxied: $(hostname -f):3389"
"$BENCH" --host "$(hostname -f)" --port 3389 --user "$USER_NAME" --password "$PASSWORD" \
    --sec nla --seconds "$SECS" --shell "fastrdp:$BACKEND" --json "proxy-$USER_NAME.json" | tail -1
