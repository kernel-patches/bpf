#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Correlating ThinLTO-promoted locals requires demangling the .llvm.<hash>
# suffix, and the resulting klp relocation must name the original symbol: that
# is the one in the running kernel's kallsyms.

. "$(dirname "$0")/lib.sh"

setup

find_thinlto_toolchain || skip "no matching clang/lld pair for a ThinLTO link"

build_thinlto()		# $1 output object, $2 extra flags
{
	$THIN_CC -flto=thin -O2 -ffunction-sections -fdata-sections $2 \
		-c "$FIXTURES_DIR/thinlto_local.c" -o "$workdir/tu_a.o" 2>/dev/null || return 1
	$THIN_CC -flto=thin -O2 -ffunction-sections -fdata-sections $2 -DTU_B \
		-c "$FIXTURES_DIR/thinlto_local.c" -o "$workdir/tu_b.o" 2>/dev/null || return 1
	"$THIN_LD" -r "$workdir/tu_a.o" "$workdir/tu_b.o" -o "$1" 2>/dev/null || return 1
}

build_thinlto "$workdir/orig.o" ""           || skip "ThinLTO build failed"
build_thinlto "$workdir/patched.o" -DPATCHED || skip "ThinLTO build failed"

orig_sym="$(nm "$workdir/orig.o"    2>/dev/null | grep -o 'counter\.llvm\.[0-9]*' | head -1)"
new_sym="$( nm "$workdir/patched.o" 2>/dev/null | grep -o 'counter\.llvm\.[0-9]*' | head -1)"

[ -n "$orig_sym" ] && [ -n "$new_sym" ] ||
	skip "ThinLTO did not promote the local symbol here"

# Equal hashes would make plain name matching work, testing nothing.
[ "$orig_sym" != "$new_sym" ] ||
	skip "ThinLTO hash did not change between builds"

run_diff
assert_patched target

out_symbols | grep -q "\.klp\.sym\.vmlinux\.$orig_sym," ||
	fail "expected a klp relocation naming $orig_sym"
out_symbols | grep -q "\.klp\.sym\.vmlinux\.$new_sym," &&
	fail "klp relocation names $new_sym, which the running kernel does not have"

pass "ThinLTO-mangled local correlated across differing hashes"
