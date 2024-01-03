// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */
#include <stdbool.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

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

/* Arrays can be in the BSS or inside a map element.  Make sure both work. */
int bss_elems[NR_MAP_ELEMS];

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
	__type(key, int);
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
 * Test that we can access all elements, and that we are accessing the element
 * we think we are accessing.
 */
static void access_all(void)
{
	int *map_elems = get_map_elems();
	int *x;

	for (int i = 0; i < NR_MAP_ELEMS; i++) {
		x = bpf_array_elem(map_elems, NR_MAP_ELEMS, lookup_indexes[i]);
		if (x)
			*x = i;
	}

	for (int i = 0; i < NR_MAP_ELEMS; i++) {
		x = bpf_array_sz_elem(bss_elems, lookup_indexes[i]);
		if (x)
			*x = i;
	}
}

SEC("?tp/syscalls/sys_enter_nanosleep")
int x_access_all(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;
	access_all();
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
	x = bpf_array_sz_elem(bss_elems, idx);
	if (x)
		*x = 1;
}

/*
 * Test various out-of-bounds accesses.
 */
static void oob_access(void)
{
	set_elem_to_1(NR_MAP_ELEMS + 5);
	set_elem_to_1(NR_MAP_ELEMS);
	set_elem_to_1(-1);
	set_elem_to_1(~0UL);
}

SEC("?tp/syscalls/sys_enter_nanosleep")
int x_oob_access(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;
	oob_access();
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
static void access_array_map_infer_sz(void)
{
	struct map_array *arr = get_map_array();
	int *x;

	for (int i = 0; i < NR_MAP_ELEMS; i++) {
		x = bpf_array_sz_elem(arr->elems, lookup_indexes[i]);
		if (x)
			*x = i;
	}
}

SEC("?tp/syscalls/sys_enter_nanosleep")
int x_access_array_map_infer_sz(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;
	access_array_map_infer_sz();
	return 0;
}



SEC("?tp/syscalls/sys_enter_nanosleep")
int x_bad_map_array_access(void *ctx)
{
	int *map_elems = get_map_elems();

	/*
	 * Need to check to promote map_elems from MAP_OR_NULL to MAP so that we
	 * fail to load below for the right reason.
	 */
	if (!map_elems)
		return 0;
	/* Fail to load: we don't prove our access is inside map_elems[] */
	for (int i = 0; i < NR_MAP_ELEMS; i++)
		map_elems[lookup_indexes[i]] = i;
	return 0;
}

SEC("?tp/syscalls/sys_enter_nanosleep")
int x_bad_bss_array_access(void *ctx)
{
	/* Fail to load: we don't prove our access is inside bss_elems[] */
	for (int i = 0; i < NR_MAP_ELEMS; i++)
		bss_elems[lookup_indexes[i]] = i;
	return 0;
}
