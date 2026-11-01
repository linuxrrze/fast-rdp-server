#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# tests/annotate.sh SCRIPT [ARGS...]: runs a test script unchanged; in GitHub Actions each
# "FAIL ..." line also becomes an error annotation. Annotations are readable through the
# API without login, the job log only with admin rights.
set -o pipefail
name=$(basename "$1")
"$@" 2>&1 | awk -v n="$name" '
    { print; fflush() }
    /^FAIL / && ENVIRON["GITHUB_ACTIONS"] == "true" {
        gsub(/%/, "%25"); gsub(/\r/, "%0D")
        print "::error title=" n "::" $0; fflush()
    }'
