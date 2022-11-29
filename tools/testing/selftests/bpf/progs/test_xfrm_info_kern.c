// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define log_err(__ret) bpf_printk("ERROR line:%d ret:%d\n", __LINE__, __ret)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} dst_if_id_map SEC(".maps");

struct bpf_xfrm_info {
	__u32 if_id;
	int link;
};

int bpf_skb_set_xfrm_info(struct __sk_buff *skb_ctx,
			  const struct bpf_xfrm_info *from) __ksym;
int bpf_skb_get_xfrm_info(struct __sk_buff *skb_ctx,
			  struct bpf_xfrm_info *to) __ksym;

SEC("tc")
int set_xfrm_info(struct __sk_buff *skb)
{
	struct bpf_xfrm_info info = {};
	__u32 *if_id = NULL;
	__u32 index = 0;
	int ret = -1;

	if_id = bpf_map_lookup_elem(&dst_if_id_map, &index);
	if (!if_id) {
		log_err(ret);
		return TC_ACT_SHOT;
	}

	info.if_id = *if_id;
	ret = bpf_skb_set_xfrm_info(skb, &info);
	if (ret < 0) {
		log_err(ret);
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC;
}

SEC("tc")
int get_xfrm_info(struct __sk_buff *skb)
{
	struct bpf_xfrm_info info = {};
	__u32 *if_id = NULL;
	__u32 index = 1;
	int ret = -1;

	if_id = bpf_map_lookup_elem(&dst_if_id_map, &index);
	if (!if_id) {
		log_err(ret);
		return TC_ACT_SHOT;
	}

	ret = bpf_skb_get_xfrm_info(skb, &info);
	if (ret < 0) {
		log_err(ret);
		return TC_ACT_SHOT;
	}

	*if_id = info.if_id;

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
