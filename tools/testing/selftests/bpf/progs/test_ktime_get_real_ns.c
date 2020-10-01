// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, unsigned long long);
} time_map SEC(".maps");

SEC("realtime_helper")
int realtime_helper_test(struct __sk_buff *skb)
{
	unsigned long long *lasttime;
	unsigned long long curtime;
	int key = 0;
	int err = 0;

	lasttime = bpf_map_lookup_elem(&time_map, &key);
	if (!lasttime)
		goto err;

	curtime = bpf_ktime_get_real_ns();
	if (curtime <= *lasttime) {
		err = 1;
		goto err;
	}
	*lasttime = curtime;

err:
	return err;
}

char _license[] SEC("license") = "GPL";
