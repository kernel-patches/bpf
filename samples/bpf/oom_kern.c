// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} sc_map SEC(".maps");

SEC("oom_policy")
int bpf_prog1(struct bpf_oom_ctx *ctx)
{
	u64 cg_ino_1, cg_ino_2;
	u32 cs_1, sc_2;
	u32 *value;

	cs_1 = sc_2 = 250;
	cg_ino_1 = bpf_get_ino_from_cgroup_id(ctx->cg_id_1);
	cg_ino_2 = bpf_get_ino_from_cgroup_id(ctx->cg_id_2);

	value = bpf_map_lookup_elem(&sc_map, &cg_ino_1);
	if (value)
		cs_1 = *value;

	value = bpf_map_lookup_elem(&sc_map, &cg_ino_2);
	if (value)
		sc_2 = *value;

	if (cs_1 > sc_2)
		ctx->cmp_ret = BPF_OOM_CMP_GREATER;
	else if (cs_1 < sc_2)
		ctx->cmp_ret = BPF_OOM_CMP_LESS;
	else
		ctx->cmp_ret = BPF_OOM_CMP_EQUAL;
	return 0;
}

char _license[] SEC("license") = "GPL";
