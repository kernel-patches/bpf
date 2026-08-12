#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Init code and data are freed after boot, so a klp relocation against them can
# never resolve.  Such a patch must be rejected.

. "$(dirname "$0")/lib.sh"

setup
build_pair init_reference.c
run_diff 255

diff_log | grep -q "can't patch or reference init code/data" ||
	fail "expected rejection, got: $(diff_log | tail -1)"

pass "reference to init data rejected"
