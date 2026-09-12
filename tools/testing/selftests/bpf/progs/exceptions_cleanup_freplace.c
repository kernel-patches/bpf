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

/*
 * The placeholder variables libbpf stands up for the .ksyms externs point at
 * whatever 4-byte integer it can find in the object's BTF, and this program
 * is small enough to have none: a __u64 argument, a char array, and the
 * extern above. Clang leaves one lying around by accident -- the array index
 * type it invents for _license[] is 4 bytes wide -- but GCC reuses the DWARF
 * index type, which is 8, and the placeholder ends up with type id 0, which
 * the kernel refuses. Every other program here is big enough for the question
 * not to come up. This one says what it needs.
 */
int btf_int_anchor;

/* Must match progs/exceptions_cleanup_shapes.c. */
#define THROW_COOKIE		0x100

SEC("freplace/fr_callee")
__u64 new_fr_callee(__u64 x)
{
	bpf_throw(THROW_COOKIE);
	return 0;
}

char _license[] SEC("license") = "GPL";
