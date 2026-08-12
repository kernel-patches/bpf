#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Data added by the patch has no counterpart in the running kernel and must be
# carried into the livepatch.

. "$(dirname "$0")/lib.sh"

setup
build_pair new_data.c
run_diff

assert_patched target
out_symbols | grep -q 'klp_new_data' ||
	fail "new data was not carried into the patch"

pass "new data carried into the patch"
