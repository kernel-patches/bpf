// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"

struct extint {
	_ExtInt(256) v256;
	_ExtInt(512) v512;
};

struct bpf_map_def SEC("maps") btf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct extint),
	.max_entries = 1,
};

BPF_ANNOTATE_KV_PAIR(btf_map, int, struct extint);

__attribute__((noinline))
int test_long_fname_2(void)
{
	struct extint *bi;
	int key = 0;

	bi = bpf_map_lookup_elem(&btf_map, &key);
	if (!bi)
		return 0;

	bi->v256 <<= 64;
	bi->v256 += (_ExtInt(256))0xcafedead;
	bi->v512 <<= 128;
	bi->v512 += (_ExtInt(512))0xff00ff00ff00ffull;

	return 0;
}

__attribute__((noinline))
int test_long_fname_1(void)
{
	return test_long_fname_2();
}

SEC("dummy_tracepoint")
int _dummy_tracepoint(void *arg)
{
	return test_long_fname_1();
}

char _license[] SEC("license") = "GPL";
