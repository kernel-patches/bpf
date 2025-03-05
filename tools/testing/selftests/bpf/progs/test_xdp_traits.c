// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

extern int bpf_xdp_trait_set(const struct xdp_md *xdp, __u64 key,
			     const void *val, __u64 val__sz,
			     __u64 flags) __ksym;
extern int bpf_xdp_trait_get(const struct xdp_md *xdp, __u64 key, void *val,
			     __u64 val__sz) __ksym;
extern int bpf_xdp_trait_del(const struct xdp_md *xdp, __u64 key) __ksym;

SEC("xdp")
int _xdp_traits(struct xdp_md *xdp)
{
	int ret;
	__u16 val, got, want;

	// No keys to start.
	for (int i = 0; i < 64; i++) {
		ret = bpf_xdp_trait_get(xdp, i, &val, sizeof(val));
		if (ret != -ENOENT) {
			bpf_printk("get(%d) ret %d", i, ret);
			return XDP_DROP;
		}
	}

	// Set 64 2 byte KVs.
	for (int i = 0; i < 64; i++) {
		val = i << 8 | i;
		ret = bpf_xdp_trait_set(xdp, i, &val, sizeof(val), 0);
		if (ret < 0) {
			bpf_printk("set(%d) ret %d\n", i, ret);
			return XDP_DROP;
		}
		bpf_printk("set(%d, 0x%04x)\n", i, val);
	}

	// Check we can get the 64 2 byte KVs back out.
	for (int i = 0; i < 64; i++) {
		ret = bpf_xdp_trait_get(xdp, i, &got, sizeof(got));
		if (ret != 2) {
			bpf_printk("get(%d) ret %d", i, ret);
			return XDP_DROP;
		}
		want = (i << 8) | i;
		if (got != want) {
			bpf_printk("get(%d) got 0x%04x want 0x%04x\n", i, got,
				   want);
			return XDP_DROP;
		}
		bpf_printk("get(%d) 0x%04x\n", i, got);
	}

	// Overwrite all 64 2 byte KVs.
	for (int i = 0; i < 64; i++) {
		val = i << 9 | i << 1;
		ret = bpf_xdp_trait_set(xdp, i, &val, sizeof(val), 0);
		if (ret < 0) {
			bpf_printk("set(%d) ret %d\n", i, ret);
			return XDP_DROP;
		}
		bpf_printk("set(%d, 0x%04x)\n", i, val);
	}

	// Delete all the even KVs.
	for (int i = 0; i < 64; i += 2) {
		ret = bpf_xdp_trait_del(xdp, i);
		if (ret < 0) {
			bpf_printk("del(%d) ret %d\n", i, ret);
			return XDP_DROP;
		}
	}

	// Read out all the odd KVs again.
	for (int i = 1; i < 63; i += 2) {
		ret = bpf_xdp_trait_get(xdp, i, &got, sizeof(got));
		if (ret != 2) {
			bpf_printk("get(%d) ret %d", i, ret);
			return XDP_DROP;
		}
		want = (i << 9) | i << 1;
		if (got != want) {
			bpf_printk("get(%d) got 0x%04x want 0x%04x\n", i, got,
				   want);
			return XDP_DROP;
		}
		bpf_printk("get(%d) 0x%04x\n", i, got);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
