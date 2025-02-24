#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#define META_SIZE 32

/* Demonstrates how metadata can be passed from an XDP program to a TC program
 * using bpf_xdp_adjust_meta.
 * For the sake of testing the metadata support in drivers, the XDP program uses
 * a fixed-size payload after the Ethernet header as metadata. The TC program
 * copies the metadata it receives into a map so it can be checked from
 * userspace.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__uint(value_size, META_SIZE);
} test_result SEC(".maps");

SEC("tc")
int ing_cls(struct __sk_buff *ctx)
{
	void *data_meta = (void *)(unsigned long)ctx->data_meta;
	void *data = (void *)(unsigned long)ctx->data;

	if (data_meta + META_SIZE > data)
		return TC_ACT_SHOT;

	int key = 0;

	bpf_map_update_elem(&test_result, &key, data_meta, BPF_ANY);

	return TC_ACT_SHOT;
}

SEC("xdp")
int ing_xdp(struct xdp_md *ctx)
{
	int ret = bpf_xdp_adjust_meta(ctx, -META_SIZE);
	if (ret < 0)
		return XDP_DROP;

	void *data_meta = (void *)(unsigned long)ctx->data_meta;
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;

	void *payload = data + sizeof(struct ethhdr);

	if (data_meta + META_SIZE > data || payload + META_SIZE > data_end)
		return XDP_DROP;

	__builtin_memcpy(data_meta, payload, META_SIZE);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
