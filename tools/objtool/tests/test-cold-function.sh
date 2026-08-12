#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Both halves of a split function belong to the patch; carrying only the hot
# part leaves the cold path branching into unpatched code.

. "$(dirname "$0")/lib.sh"

setup

split_flag=-freorder-blocks-and-partition
cc_supports "$split_flag" || split_flag=

build_pair cold_function.c $split_flag

nm "$workdir/orig.o" 2>/dev/null | grep -qE 'target\.cold' ||
	skip "compiler did not split the function into a cold part"

run_diff

assert_patched target
out_symbols | grep -qE 'target\.cold' ||
	fail "cold half was not carried into the patch"

pass "cold half carried into the patch with its parent"
