#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# As for static branches, a static call key owned by a module must be rejected
# while a vmlinux-owned one is accepted.

. "$(dirname "$0")/lib.sh"

setup
build_pair static_call.c

readelf -S -W "$workdir/orig.o" 2>/dev/null | grep -q '.static_call_sites' ||
	skip "fixture produced no .static_call_sites on this arch"

run_diff
assert_patched target

rm -f "$workdir/.checksummed" "$workdir/out.o"
build_pair static_call.c -DMODNAME='"klp_testmod"'
run_diff 255

diff_log | grep -q 'unsupported static call key __SCK__klp_test_call' ||
	fail "expected rejection, got: $(diff_log | tail -1)"

pass "module-owned static call key rejected, vmlinux-owned accepted"
