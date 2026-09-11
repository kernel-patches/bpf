// SPDX-License-Identifier: GPL-2.0
/*
 * An extension program standing in for fr_callee() of
 * progs/exceptions_cleanup_shapes.c, which carries an exception cleanup
 * table. This one deliberately does not: the point is that a frame belonging
 * to a program with no table can sit below one with a landing pad, and that
 * bpf_throw() ends its walk there rather than reading a spill that was never
 * made.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern void bpf_throw(u64 cookie) __ksym;

/* Must match progs/exceptions_cleanup_shapes.c. */
#define THROW_COOKIE		0x100

SEC("freplace/fr_callee")
__u64 new_fr_callee(__u64 x)
{
	bpf_throw(THROW_COOKIE);
	return 0;
}

char _license[] SEC("license") = "GPL";
