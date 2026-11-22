#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

command -v python3 >/dev/null 2>&1 || exit $ksft_skip

DIR="$(dirname "$(readlink -f "$0")")"
exec python3 "$DIR/userland_test.py" "$@"
