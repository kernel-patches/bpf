// SPDX-License-Identifier: GPL-2.0-only
/* Unstable XFRM Helpers for TC-BPF hook
 *
 * These are called from SCHED_CLS BPF programs. Note that it is
 * allowed to break compatibility for these functions since the interface they
 * are exposed through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>

#include <net/dst_metadata.h>
#include <net/xfrm.h>

struct bpf_xfrm_info {
	u32 if_id;
	int link;
};

static struct metadata_dst __percpu *xfrm_md_dst;
__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in xfrm_interface BTF");

__used noinline
int bpf_skb_get_xfrm_info(struct __sk_buff *skb_ctx, struct bpf_xfrm_info *to)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct xfrm_md_info *info;

	memset(to, 0, sizeof(*to));

	info = skb_xfrm_md_info(skb);
	if (!info)
		return -EINVAL;

	to->if_id = info->if_id;
	to->link = info->link;
	return 0;
}

__used noinline
int bpf_skb_set_xfrm_info(struct __sk_buff *skb_ctx,
			  const struct bpf_xfrm_info *from)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct metadata_dst *md_dst;
	struct xfrm_md_info *info;

	if (unlikely(skb_metadata_dst(skb)))
		return -EINVAL;

	md_dst = this_cpu_ptr(xfrm_md_dst);

	info = &md_dst->u.xfrm_info;
	memset(info, 0, sizeof(*info));

	info->if_id = from->if_id;
	info->link = from->link;
	info->dst_orig = skb_dst(skb);

	dst_hold((struct dst_entry *)md_dst);
	skb_dst_set(skb, (struct dst_entry *)md_dst);
	return 0;
}

__diag_pop()

BTF_SET8_START(xfrm_ifc_kfunc_set)
BTF_ID_FLAGS(func, bpf_skb_get_xfrm_info)
BTF_ID_FLAGS(func, bpf_skb_set_xfrm_info)
BTF_SET8_END(xfrm_ifc_kfunc_set)

static const struct btf_kfunc_id_set xfrm_interface_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &xfrm_ifc_kfunc_set,
};

int __init register_xfrm_interface_bpf(void)
{
	xfrm_md_dst = metadata_dst_alloc_percpu(0, METADATA_XFRM,
						GFP_KERNEL);
	if (!xfrm_md_dst)
		return -ENOMEM;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &xfrm_interface_kfunc_set);
}

void __exit cleanup_xfrm_interface_bpf(void)
{
	metadata_dst_free_percpu(xfrm_md_dst);
}
