#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# .klp.symid must not reference symbols in sections the vmlinux link discards.

. "$(dirname "$0")/lib.sh"

setup

$CC $FIXTURE_CFLAGS -DFUNC_NAME=use_a -o "$workdir/a.o" \
	"$FIXTURES_DIR/symid_discarded.c" 2>/dev/null || skip "fixture does not build here"
$CC $FIXTURE_CFLAGS -DFUNC_NAME=use_b -o "$workdir/b.o" \
	"$FIXTURES_DIR/symid_discarded.c" 2>/dev/null || skip "fixture does not build here"

# --klp-symids only runs on a file named vmlinux.o
partial_link "$workdir/vmlinux.o" "$workdir/a.o" "$workdir/b.o" ||
	skip "partial link unavailable"

"$OBJTOOL" --klp-symids --link "$workdir/vmlinux.o" ||
	fail "objtool --klp-symids failed"

symids="$(readelf -r -W "$workdir/vmlinux.o" 2>/dev/null |
	  awk '/rela.klp.symid/,/^$/')"

# Without this the test would also pass if symid generation stopped entirely.
echo "$symids" | grep -q 'dup_normal' ||
	fail "no symid for the duplicate in a live section"

echo "$symids" | grep -q 'dup_discarded' &&
	fail "symid emitted for a symbol in discarded section .exitcall.exit"

pass "no symids for symbols in discarded sections"
