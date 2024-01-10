// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include <vmlinux.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

int target_pid = 0;

#define NR_MAP_ELEMS 100

/*
 * We want to test valid accesses into an array, but we also need to fool the
 * verifier.  If we just do for (i = 0; i < 100; i++), the verifier knows the
 * value of i and can tell we're inside the array.
 *
 * This "lookup" array is just the values 0, 1, 2..., such that
 * lookup_indexes[i] == i.  (set by userspace).  But the verifier doesn't know
 * that.
 */
unsigned int lookup_indexes[NR_MAP_ELEMS];

/*
 * This second lookup array also has the values 0, 1, 2.  The extra layer of
 * lookups seems to make the compiler work a little harder, and more likely to
 * spill to the stack.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_MAP_ELEMS);
	__type(key, u32);
	__type(value, u32);
	__uint(map_flags, BPF_F_MMAPABLE);
} lookup_again SEC(".maps");

struct map_array {
	int elems[NR_MAP_ELEMS];
};

/*
 * This is an ARRAY_MAP of a single struct, and that struct is an array of
 * elements.  Userspace can mmap the map as if it was just a basic array of
 * elements.  Though if you make an ARRAY_MAP where the *values* are ints, don't
 * forget that bpf map elements are rounded up to 8 bytes.
 *
 * Once you get the pointer to the base of the inner array, you can access all
 * of the elements without another bpf_map_lookup_elem(), which is useful if you
 * are operating on multiple elements while holding a spinlock.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct map_array);
	__uint(map_flags, BPF_F_MMAPABLE);
} arraymap SEC(".maps");

static struct map_array *get_map_array(void)
{
	int zero = 0;

	return bpf_map_lookup_elem(&arraymap, &zero);
}

static int *get_map_elems(void)
{
	struct map_array *arr = get_map_array();

	if (!arr)
		return NULL;
	return arr->elems;
}

/*
 * This is convoluted enough that the compiler may spill a register (r1) before
 * bounds checking it.
 */
static void bad_set_elem(unsigned int which, int val)
{
	u32 idx_1;
	u32 *idx_2p;
	int *map_elems;

	if (which >= NR_MAP_ELEMS)
		return;

	idx_1 = lookup_indexes[which];
	idx_2p = bpf_map_lookup_elem(&lookup_again, &idx_1);
	if (!idx_2p)
		return;

	/*
	 * reuse idx_1, which is often r1.  if you use a new variable, e.g.
	 * idx_3 = *idx_2p, the compiler will pick a non-caller save register
	 * (e.g. r6), and won't spill it to the stack.
	 */
	idx_1 = *idx_2p;

	/*
	 * Whether we use bpf_cmp or a normal comparison, r1 might get spilled
	 * to the stack, *then* checked against NR_MAP_ELEMS.  The verifier will
	 * know r1's bounds, but since the check happened after the spill, it
	 * doesn't know about the stack variable's bounds.
	 */
	if (bpf_cmp_unlikely(idx_1, >=, NR_MAP_ELEMS))
		return;

	/*
	 * This does a bpf_map_lookup_elem(), which is a function call, which
	 * necessitates spilling r1.
	 */
	map_elems = get_map_elems();
	if (map_elems)
		map_elems[idx_1] = val;
}

SEC("?tp/syscalls/sys_enter_nanosleep")
__failure
__msg("R0 unbounded memory access, make sure to bounds check any such access")
int bad_access_single(void *ctx)
{
	bad_set_elem(0, 1337);
	return 0;
}

SEC("?tp/syscalls/sys_enter_nanosleep")
__failure
__msg("R0 unbounded memory access, make sure to bounds check any such access")
int bad_access_all(void *ctx)
{
	for (int i = 0; i < NR_MAP_ELEMS; i++)
		bad_set_elem(i, i);
	return 0;
}

/*
 * Both lookup_indexes and lookup_again are identity maps, i.e. f(x) = x (within
 * bounds), so ultimately we're setting map_elems[which] = val.
 */
static void good_set_elem(unsigned int which, int val)
{
	u32 idx_1;
	u32 *idx_2p;
	int *map_elems, *x;

	if (which >= NR_MAP_ELEMS)
		return;
	idx_1 = lookup_indexes[which];
	idx_2p = bpf_map_lookup_elem(&lookup_again, &idx_1);

	if (!idx_2p)
		return;

	idx_1 = *idx_2p;

	map_elems = get_map_elems();
	x = bpf_array_elem(map_elems, NR_MAP_ELEMS, idx_1);
	if (x)
		*x = val;
}

/*
 * Test accessing a single element in the array with a convoluted lookup.
 */
SEC("?tp/syscalls/sys_enter_nanosleep")
int access_single(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	good_set_elem(0, 1337);

	return 0;
}

/*
 * Test that we can access all elements, and that we are accessing the element
 * we think we are accessing.
 */
SEC("?tp/syscalls/sys_enter_nanosleep")
int access_all(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	for (int i = 0; i < NR_MAP_ELEMS; i++)
		good_set_elem(i, i);

	return 0;
}

/*
 * Helper for various OOB tests.  An out-of-bound access should be handled like
 * a lookup failure.  Specifically, the verifier should ensure we do not access
 * outside the array.  Userspace will check that we didn't access somewhere
 * inside the array.
 */
static void set_elem_to_1(long idx)
{
	int *map_elems = get_map_elems();
	int *x;

	x = bpf_array_elem(map_elems, NR_MAP_ELEMS, idx);
	if (x)
		*x = 1;
}

/*
 * Test various out-of-bounds accesses.
 */
SEC("?tp/syscalls/sys_enter_nanosleep")
int oob_access(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	set_elem_to_1(NR_MAP_ELEMS + 5);
	set_elem_to_1(NR_MAP_ELEMS);
	set_elem_to_1(-1);
	set_elem_to_1(~0UL);

	return 0;
}

/*
 * Test that we can use the ARRAY_SIZE-style helper with an array in a map.
 *
 * Note that you cannot infer the size of the array from just a pointer; you
 * have to use the actual elems[100].  i.e. this will fail and should fail to
 * compile (-Wsizeof-pointer-div):
 *
 *	int *map_elems = get_map_elems();
 *	x = bpf_array_sz_elem(map_elems, lookup_indexes[i]);
 */
SEC("?tp/syscalls/sys_enter_nanosleep")
int infer_size(void *ctx)
{
	struct map_array *arr = get_map_array();
	int *x;

	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	for (int i = 0; i < NR_MAP_ELEMS; i++) {
		x = bpf_array_sz_elem(arr->elems, lookup_indexes[i]);
		if (x)
			*x = i;
	}

	return 0;
}
