#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# A changed function without an ftrace call site can't be livepatched:
# klp_enable_patch() fails with "failed to find location for function".
# klp diff must reject it instead.

. "$(dirname "$0")/../lib.sh"

# mcount_entry <function>: orig.o has an __mcount_loc entry for it.
mcount_entry()
{
	in_relocs "$orig_obj" | awk '/rela__mcount_loc/,/^$/' |
		awk -v f="$1" '$5 == f || $5 == ".text." f' | grep -q .
}

# check <expected exit status> <-DPATCH_... flags>
check()
{
	local expect="$1"; shift

	setup
	build_pair notrace_target.c "$@"

	assert_input_symbol outlined
	assert_input_symbol notrace_fn
	has_input_symbol "$orig_obj" inlined &&
		fail "inlined() was emitted out of line; the fixture tests nothing"
	mcount_entry traced ||
		fail "no __mcount_loc entry for traced(); the fixture tests nothing"
	mcount_entry inlined_user ||
		fail "no __mcount_loc entry for inlined_user(); the fixture tests nothing"
	mcount_entry outlined &&
		fail "outlined() has a __mcount_loc entry; it should be notrace"
	mcount_entry notrace_fn &&
		fail "notrace_fn() has a __mcount_loc entry; it should be notrace"

	run_diff "$expect"
}

rejected()
{
	local n

	n="$(diff_log | grep -c "error: objtool: $1: no ftrace call site, can't patch")"
	[ "$n" = 1 ] ||
		fail "expected '$1' rejected once, found $n: $(diff_log | tail -2)"
}

check 255 -DPATCH_OUTLINED
rejected outlined
cleanup

check 255 -DPATCH_NOTRACE
rejected notrace_fn
cleanup

check 255 -DPATCH_OUTLINED -DPATCH_NOTRACE
rejected outlined
rejected notrace_fn
cleanup

# Fully inlined: the traceable caller gets patched.
check 0 -DPATCH_INLINED
assert_patched inlined_user
assert_not_patched traced
cleanup

check 0 -DPATCH_TRACED
assert_patched traced
assert_not_patched inlined_user
cleanup

pass "changed function without an ftrace call site rejected"
