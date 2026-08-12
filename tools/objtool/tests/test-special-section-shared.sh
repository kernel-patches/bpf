#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Only the patched function's special section entry may be extracted.

. "$(dirname "$0")/lib.sh"

setup
build_pair special_section_shared.c

readelf -S -W "$workdir/orig.o" 2>/dev/null | grep -q '.smp_locks' ||
	skip "fixture produced no special section on this arch"

run_diff

assert_patched     target
assert_not_patched other
assert_section     ".smp_locks"

entries="$(out_relocs | awk '/rela.smp_locks/,/^$/' | grep -c 'target')"
[ "$entries" = 1 ] || fail "expected one .smp_locks entry, found $entries"

out_relocs | awk '/rela.smp_locks/,/^$/' | grep -q 'other' &&
	fail "the untouched function's entry was dragged in"

pass "only the patched function's entry extracted"
