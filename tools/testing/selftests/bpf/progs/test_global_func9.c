// SPDX-License-Identifier: GPL-2.0-only
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct S {
	int x;
};

struct C {
	int x;
	int y;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct S);
} map SEC(".maps");

__noinline int foo(const struct S *s)
{
	if (s)
		return bpf_get_prandom_u32() < s->x;

	return 0;
}

SEC("cgroup_skb/ingress")
int test_cls(struct __sk_buff *skb)
{
	int result = 0;

	{
		const struct S s = {.x = skb->len };

		result |= foo(&s);
	}

	{
		const __u32 key = 1;
		const struct S *s = bpf_map_lookup_elem(&map, &key);

		result |= foo(s);
	}

	{
		const struct C c = {.x = skb->len, .y = skb->family };

		result |= foo((const struct S *)&c);
	}

	{
		result |= foo(NULL);
	}

	return result ? 1 : 0;
}
