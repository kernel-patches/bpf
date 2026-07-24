// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

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

/* An un-narrowed map-of-maps value must be rejected as a __nullable kfunc mem buffer */
SEC("?tc")
__failure __msg("type=map_ptr expected=fp")
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
	p = bpf_dynptr_slice(&dptr, 0, inner, 4);
	if (p)
		return p[0];
	return 0;
}

/* An un-narrowed map-of-maps value must be rejected as a PTR_MAYBE_NULL helper mem buffer */
SEC("?tc")
__failure __msg("type=map_ptr expected=fp")
int mapofmaps_value_as_helper_mem_buf(struct __sk_buff *skb)
{
	__u32 key = 0;
	void *inner;

	inner = bpf_map_lookup_elem(&outer_map, &key);
	/* intentionally NOT NULL-checked: reg stays PTR_TO_MAP_VALUE_OR_NULL */

	/* @from is a nullable read-only mem+size arg; outer value_size is 4 */
	return bpf_csum_diff(inner, 4, NULL, 0, 0) + skb->len;
}
