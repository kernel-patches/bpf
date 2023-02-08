// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netfilter.h>

#include <net/netfilter/nf_hook_bpf.h>

static unsigned int nf_hook_run_bpf(void *bpf_prog, struct sk_buff *skb, const struct nf_hook_state *s)
{
	const struct bpf_prog *prog = bpf_prog;
	struct bpf_nf_ctx ctx = {
		.state = s,
		.skb = skb,
		.data = skb->data,
		.data_end = skb->data + skb_headlen(skb),
	};

	return bpf_prog_run(prog, &ctx);
}

struct bpf_nf_link {
	struct bpf_link link;
	struct nf_hook_ops hook_ops;
	struct net *net;
};

static void bpf_nf_link_release(struct bpf_link *link)
{
	struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);

	nf_unregister_net_hook(nf_link->net, &nf_link->hook_ops);
}

static void bpf_nf_link_dealloc(struct bpf_link *link)
{
	struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);

	kfree(nf_link);
}

static int bpf_nf_link_detach(struct bpf_link *link)
{
	bpf_nf_link_release(link);
	return 0;
}

static void bpf_nf_link_show_info(const struct bpf_link *link,
				  struct seq_file *seq)
{
	struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);

	seq_printf(seq, "pf:\t%u\thooknum:\t%u\tprio:\t%d\n",
		  nf_link->hook_ops.pf, nf_link->hook_ops.hooknum,
		  nf_link->hook_ops.priority);
}

static int bpf_nf_link_fill_link_info(const struct bpf_link *link,
				      struct bpf_link_info *info)
{
	struct bpf_nf_link *nf_link = container_of(link, struct bpf_nf_link, link);

	info->netfilter.pf = nf_link->hook_ops.pf;
	info->netfilter.hooknum = nf_link->hook_ops.hooknum;
	info->netfilter.priority = nf_link->hook_ops.priority;

	return 0;
}

static int bpf_nf_link_update(struct bpf_link *link, struct bpf_prog *new_prog,
			      struct bpf_prog *old_prog)
{
	return -EOPNOTSUPP;
}

static const struct bpf_link_ops bpf_nf_link_lops = {
	.release = bpf_nf_link_release,
	.dealloc = bpf_nf_link_dealloc,
	.detach = bpf_nf_link_detach,
	.show_fdinfo = bpf_nf_link_show_info,
	.fill_link_info = bpf_nf_link_fill_link_info,
	.update_prog = bpf_nf_link_update,
};

int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct net *net = current->nsproxy->net_ns;
	struct bpf_link_primer link_primer;
	struct bpf_nf_link *link;
	int err;

	if (attr->link_create.flags)
		return -EINVAL;

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link)
		return -ENOMEM;

	bpf_link_init(&link->link, BPF_LINK_TYPE_NETFILTER, &bpf_nf_link_lops, prog);

	link->hook_ops.hook = nf_hook_run_bpf;
	link->hook_ops.hook_ops_type = NF_HOOK_OP_BPF;
	link->hook_ops.priv = prog;

	link->hook_ops.pf = attr->link_create.netfilter.pf;
	link->hook_ops.priority = attr->link_create.netfilter.prio;
	link->hook_ops.hooknum = attr->link_create.netfilter.hooknum;

	link->net = net;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err)
		goto out_free;

	err = nf_register_net_hook(net, &link->hook_ops);
	if (err) {
		bpf_link_cleanup(&link_primer);
		goto out_free;
	}

	return bpf_link_settle(&link_primer);

out_free:
	kfree(link);
	return err;
}

static int bpf_prog_test_run_nf(struct bpf_prog *prog,
				const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	return -EOPNOTSUPP;
}

const struct bpf_prog_ops netfilter_prog_ops = {
	.test_run		= bpf_prog_test_run_nf,
};

static u32 nf_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct __sk_buff, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_nf_ctx, data),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_nf_ctx, data));
		break;
	case offsetof(struct __sk_buff, data_end):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_nf_ctx, data_end),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_nf_ctx, data_end));
		break;
	}

	return insn - insn_buf;
}

static bool nf_is_valid_access(int off, int size, enum bpf_access_type type,
			       const struct bpf_prog *prog,
			       struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct __sk_buff))
		return false;

	if (type == BPF_WRITE)
		return false;

	switch (off) {
	case bpf_ctx_range(struct __sk_buff, data):
		if (size != sizeof(u32))
			return false;
		info->reg_type = PTR_TO_PACKET;
		return true;
	case bpf_ctx_range(struct __sk_buff, data_end):
		if (size != sizeof(u32))
			return false;
		info->reg_type = PTR_TO_PACKET_END;
		return true;
	default:
		return false;
	}

	return false;
}

static const struct bpf_func_proto *
bpf_nf_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}

const struct bpf_verifier_ops netfilter_verifier_ops = {
	.is_valid_access	= nf_is_valid_access,
	.convert_ctx_access	= nf_convert_ctx_access,
	.get_func_proto		= bpf_nf_func_proto,
};

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "kfuncs which will be used in BPF programs");

/* bpf_nf_hook_state_ctx_get - get nf_hook_state context structure
 *
 * Get the real nf_hook_state context structure.
 *
 *
 */
const struct nf_hook_state *bpf_nf_hook_state_ctx_get(struct __sk_buff *s)
{
	return (const struct nf_hook_state *)s;
}

int bpf_xt_change_status(struct nf_conn *nfct, u32 status)
{
	return 1;
}

__diag_pop()

BTF_SET8_START(nf_hook_kfunc_set)
BTF_ID_FLAGS(func, bpf_nf_hook_state_ctx_get, 0)
BTF_ID_FLAGS(func, bpf_xt_change_status, KF_TRUSTED_ARGS)
BTF_SET8_END(nf_hook_kfunc_set)

static const struct btf_kfunc_id_set nf_basehook_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &nf_hook_kfunc_set,
};

int register_nf_hook_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_NETFILTER, &nf_basehook_kfunc_set);
	if (ret)
		return ret;

	return ret;
}
