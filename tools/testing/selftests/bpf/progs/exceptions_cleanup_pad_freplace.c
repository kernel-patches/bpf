// SPDX-License-Identifier: GPL-2.0
/*
 * An extension program standing in for pad_callee() of
 * progs/exceptions_cleanup_shapes.c, which is called from inside a landing
 * pad. The subprogram it replaces cannot throw, which is what let the pad
 * calling it past the verifier; this one throws, and does so while an
 * exception is already in flight.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern void bpf_throw(u64 cookie) __ksym;

/* See progs/exceptions_cleanup_freplace.c: this object is small enough to
 * hold no 4-byte integer of its own, and libbpf needs one for the .ksyms
 * placeholder variables.
 */
int btf_int_anchor;

/* Must match progs/exceptions_cleanup_shapes.c. */
#define INNER_COOKIE		0x200

SEC("freplace/pad_callee")
__u64 new_pad_callee(__u64 x)
{
	bpf_throw(INNER_COOKIE);
	return 0;
}

char _license[] SEC("license") = "GPL";
