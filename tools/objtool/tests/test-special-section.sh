#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# A special section belonging to a patched function must be extracted even
# without annotations and with a symbol already at offset 0.

. "$(dirname "$0")/lib.sh"

setup
build_pair special_section.c

nm "$workdir/orig.o" 2>/dev/null | grep -q 'sl_marker' ||
	skip "fixture produced no special section on this arch"

run_diff

assert_patched target
assert_section ".smp_locks"

pass "special section extracted despite a symbol at offset 0"
