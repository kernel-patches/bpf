// SPDX-License-Identifier: GPL-2.0
/*
 * Regression tests for the shared mem+size argument checking
 * (check_mem_size_reg() and the kfunc mem+size path).
 *
 * These guard two properties that a refactor of check_mem_size_reg() /
 * check_kfunc_mem_size_reg() can silently break:
 *
 *  1) A read-only mem+size argument must be verified with a READ access
 *     only.  If the direction check is bugged so that a WRITE access is
 *     also performed (e.g. using '|' instead of '&' on the access type),
 *     a read-only buffer is wrongly rejected.
 *
 *  2) An un-narrowed (maybe-NULL) map-in-map value must not be usable as a
 *     __nullable kfunc mem buffer.  The kfunc mem+size path relies on
 *     mark_ptr_not_null_reg() to reclassify a map-of-maps value_or_null to
 *     CONST_PTR_TO_MAP (which is not a valid memory type).  base_type()
 *     alone would leave it as PTR_TO_MAP_VALUE and let the program read the
 *     inner-map descriptor as raw bytes.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

/* Read-only string in .rodata -> PTR_TO_MAP_VALUE of a frozen (read-only)
 * BPF_MAP_TYPE_ARRAY.
 */
const char rdonly_num[] = "42";

/* map-in-map: lookup on outer_map returns PTR_TO_MAP_VALUE_OR_NULL whose
 * map_ptr has inner_map_meta set.
 */
struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} inner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__array(values, struct inner_map);
} outer_map SEC(".maps") = {
	.values = { [0] = &inner_map },
};

/*
 * Case 1: read-only mem+size arg must verify with only a READ check.
 *
 * bpf_strtol()'s first argument is ARG_PTR_TO_MEM | MEM_RDONLY paired with
 * ARG_MEM_SIZE, so access_type is BPF_READ.  Passing a read-only .rodata
 * pointer must succeed.  A direction bug that also runs the BPF_WRITE check
 * would reject it ("write into map ... forbidden" / "cannot write into
 * rdonly_mem").
 */
SEC("?tc")
__success
int rdonly_mem_size_arg_is_read_only(struct __sk_buff *skb)
{
	long res = 0;

	bpf_strtol(rdonly_num, sizeof(rdonly_num), 0, &res);
	return res + skb->len;
}

/*
 * Case 2: an un-narrowed map-of-maps value must be rejected as a __nullable
 * kfunc mem buffer.
 *
 * bpf_map_lookup_elem() on a map-of-maps yields PTR_TO_MAP_VALUE_OR_NULL
 * (inner_map_meta set).  Without a NULL check it is passed as the scratch
 * buffer of bpf_dynptr_slice() (a __nullable KF_ARG_PTR_TO_MEM_SIZE arg).
 * The verifier must reject it: mark_ptr_not_null_reg() reclassifies it to
 * CONST_PTR_TO_MAP, which is not a valid memory type.
 */
SEC("?tc")
__failure
int mapofmaps_value_as_kfunc_mem_buf(struct __sk_buff *skb)
{
	struct bpf_dynptr dptr;
	__u32 key = 0;
	void *inner;
	char *p;

	inner = bpf_map_lookup_elem(&outer_map, &key);
	/* intentionally NOT NULL-checked: reg stays PTR_TO_MAP_VALUE_OR_NULL */

	bpf_dynptr_from_skb(skb, 0, &dptr);
	/* pass the un-narrowed map-of-maps value as the scratch buffer */
	p = bpf_dynptr_slice(&dptr, 0, inner, 8);
	if (p)
		return p[0];
	return 0;
}

/*
 * Case 3 (exploratory): the same un-narrowed map-of-maps value passed to a
 * __nullable *helper* mem arg (bpf_csum_diff()'s @from is
 * ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY + ARG_MEM_SIZE_OR_ZERO).
 *
 * Unlike the kfunc path, the helper mem+size path uses base_type() dispatch
 * and does NOT run mark_ptr_not_null_reg(), so it would not reclassify the
 * map-of-maps value to CONST_PTR_TO_MAP.  For safety this SHOULD be rejected
 * (same as case 2).  If it instead loads successfully, it exposes a
 * helper-side normalization gap: the program can read the inner-map
 * descriptor bytes (a kernel pointer) as data via check_map_access().
 */
SEC("?tc")
__failure
int mapofmaps_value_as_helper_mem_arg(struct __sk_buff *skb)
{
	__u32 key = 0;
	void *inner;

	inner = bpf_map_lookup_elem(&outer_map, &key);
	/* intentionally NOT NULL-checked: reg stays PTR_TO_MAP_VALUE_OR_NULL */

	/* @from is a nullable read-only mem+size arg; outer value_size is 4 */
	return bpf_csum_diff(inner, 4, NULL, 0, 0) + skb->len;
}
