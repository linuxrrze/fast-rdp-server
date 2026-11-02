#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# tests/annotate.sh COMMAND [ARGS...]: runs a test script or make target unchanged; in
# GitHub Actions each failure line also becomes an error annotation: "FAIL ..." (tests/lib.sh
# and the e2e scripts), unittest's "FAIL: ..." / "ERROR: ..." and the exception after it, and
# make's "*** ... Error N". Annotations are readable through the API without login, the job
# log only with admin rights.
set -o pipefail
name=$(basename "$1")
"$@" 2>&1 | awk -v n="$name" '
    { print; fflush() }
    /^(FAIL[ :]|ERROR: |[A-Za-z.]*(Error|Exception): |make(\[[0-9]+\])?: \*\*\*)/ &&
    ENVIRON["GITHUB_ACTIONS"] == "true" {
        gsub(/%/, "%25"); gsub(/\r/, "%0D")
        print "::error title=" n "::" $0; fflush()
    }'
