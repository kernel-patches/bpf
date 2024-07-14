#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

static struct bpf_struct_ops bpf_Qdisc_ops;

static u32 unsupported_ops[] = {
	offsetof(struct Qdisc_ops, change),
	offsetof(struct Qdisc_ops, attach),
	offsetof(struct Qdisc_ops, change_real_num_tx),
	offsetof(struct Qdisc_ops, dump),
	offsetof(struct Qdisc_ops, dump_stats),
	offsetof(struct Qdisc_ops, ingress_block_set),
	offsetof(struct Qdisc_ops, egress_block_set),
	offsetof(struct Qdisc_ops, ingress_block_get),
	offsetof(struct Qdisc_ops, egress_block_get),
};

struct bpf_sched_data {
	struct qdisc_watchdog watchdog;
};

struct bpf_sk_buff_ptr {
	struct sk_buff *skb;
};

static int bpf_qdisc_init(struct btf *btf)
{
	return 0;
}

int bpf_qdisc_init_pre_op(struct Qdisc *sch, struct nlattr *opt,
			  struct netlink_ext_ack *extack)
{
	struct bpf_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_init(&q->watchdog, sch);
	return 0;
}

void bpf_qdisc_reset_post_op(struct Qdisc *sch)
{
	struct bpf_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}

void bpf_qdisc_destroy_post_op(struct Qdisc *sch)
{
	struct bpf_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}

static const struct bpf_func_proto *
bpf_qdisc_get_func_proto(enum bpf_func_id func_id,
			 const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

BTF_ID_LIST_SINGLE(bpf_sk_buff_ids, struct, sk_buff)
BTF_ID_LIST_SINGLE(bpf_sk_buff_ptr_ids, struct, bpf_sk_buff_ptr)

static bool bpf_qdisc_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	struct btf *btf = prog->aux->attach_btf;
	u32 arg;

	arg = get_ctx_arg_idx(btf, prog->aux->attach_func_proto, off);
	if (!strcmp(prog->aux->attach_func_name, "enqueue")) {
		if (arg == 2) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = btf;
			info->btf_id = bpf_sk_buff_ptr_ids[0];
			return true;
		}
	}

	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_qdisc_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t, *skbt;
	size_t end;

	skbt = btf_type_by_id(reg->btf, bpf_sk_buff_ids[0]);
	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t != skbt) {
		bpf_log(log, "only read is supported\n");
		return -EACCES;
	}

	switch (off) {
	case offsetof(struct sk_buff, tstamp):
		end = offsetofend(struct sk_buff, tstamp);
		break;
	case offsetof(struct sk_buff, priority):
		end = offsetofend(struct sk_buff, priority);
		break;
	case offsetof(struct sk_buff, mark):
		end = offsetofend(struct sk_buff, mark);
		break;
	case offsetof(struct sk_buff, queue_mapping):
		end = offsetofend(struct sk_buff, queue_mapping);
		break;
	case offsetof(struct sk_buff, cb) + offsetof(struct qdisc_skb_cb, tc_classid):
		end = offsetof(struct sk_buff, cb) +
		      offsetofend(struct qdisc_skb_cb, tc_classid);
		break;
	case offsetof(struct sk_buff, cb) + offsetof(struct qdisc_skb_cb, data[0]) ...
	     offsetof(struct sk_buff, cb) + offsetof(struct qdisc_skb_cb,
						     data[QDISC_CB_PRIV_LEN - 1]):
		end = offsetof(struct sk_buff, cb) +
		      offsetofend(struct qdisc_skb_cb, data[QDISC_CB_PRIV_LEN - 1]);
		break;
	case offsetof(struct sk_buff, tc_index):
		end = offsetofend(struct sk_buff, tc_index);
		break;
	default:
		bpf_log(log, "no write support to sk_buff at off %d\n", off);
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log,
			"write access at off %d with size %d beyond the member of sk_buff ended at %zu\n",
			off, size, end);
		return -EACCES;
	}

	return 0;
}

__bpf_kfunc_start_defs();

/* bpf_skb_get_hash - Get the flow hash of an skb.
 * @skb: The skb to get the flow hash from.
 */
__bpf_kfunc u32 bpf_skb_get_hash(struct sk_buff *skb)
{
	return skb_get_hash(skb);
}

/* bpf_skb_release - Release an skb reference acquired on an skb immediately.
 * @skb: The skb on which a reference is being released.
 */
__bpf_kfunc void bpf_skb_release(struct sk_buff *skb)
{
	consume_skb(skb);
}

/* bpf_qdisc_skb_drop - Add an skb to be dropped later to a list.
 * @skb: The skb on which a reference is being released and dropped.
 * @to_free_list: The list of skbs to be dropped.
 */
__bpf_kfunc void bpf_qdisc_skb_drop(struct sk_buff *skb,
				    struct bpf_sk_buff_ptr *to_free_list)
{
	__qdisc_drop(skb, (struct sk_buff **)to_free_list);
}

/* bpf_qdisc_watchdog_schedule - Schedule a qdisc to a later time using a timer.
 * @sch: The qdisc to be scheduled.
 * @expire: The expiry time of the timer.
 * @delta_ns: The slack range of the timer.
 */
__bpf_kfunc void bpf_qdisc_watchdog_schedule(struct Qdisc *sch, u64 expire, u64 delta_ns)
{
	struct bpf_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_schedule_range_ns(&q->watchdog, expire, delta_ns);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_qdisc_kfunc_ids)
BTF_ID_FLAGS(func, bpf_skb_get_hash)
BTF_ID_FLAGS(func, bpf_skb_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_qdisc_skb_drop, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_qdisc_watchdog_schedule)
BTF_KFUNCS_END(bpf_qdisc_kfunc_ids)

static const struct btf_kfunc_id_set bpf_qdisc_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_qdisc_kfunc_ids,
};

BTF_ID_LIST(skb_kfunc_dtor_ids)
BTF_ID(struct, sk_buff)
BTF_ID_FLAGS(func, bpf_skb_release, KF_RELEASE)

static const struct bpf_verifier_ops bpf_qdisc_verifier_ops = {
	.get_func_proto		= bpf_qdisc_get_func_proto,
	.is_valid_access	= bpf_qdisc_is_valid_access,
	.btf_struct_access	= bpf_qdisc_btf_struct_access,
};

static int bpf_qdisc_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	const struct Qdisc_ops *uqdisc_ops;
	struct Qdisc_ops *qdisc_ops;
	u32 moff;

	uqdisc_ops = (const struct Qdisc_ops *)udata;
	qdisc_ops = (struct Qdisc_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct Qdisc_ops, priv_size):
		if (uqdisc_ops->priv_size)
			return -EINVAL;
		qdisc_ops->priv_size = sizeof(struct bpf_sched_data);
		return 1;
	case offsetof(struct Qdisc_ops, static_flags):
		if (uqdisc_ops->static_flags)
			return -EINVAL;
		qdisc_ops->static_flags = TCQ_F_BPF;
		return 1;
	case offsetof(struct Qdisc_ops, peek):
		if (!uqdisc_ops->peek)
			qdisc_ops->peek = qdisc_peek_dequeued;
		return 1;
	case offsetof(struct Qdisc_ops, id):
		if (bpf_obj_name_cpy(qdisc_ops->id, uqdisc_ops->id,
				     sizeof(qdisc_ops->id)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static bool is_unsupported(u32 member_offset)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(unsupported_ops); i++) {
		if (member_offset == unsupported_ops[i])
			return true;
	}

	return false;
}

static int bpf_qdisc_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	if (is_unsupported(__btf_member_bit_offset(t, member) / 8))
		return -ENOTSUPP;
	return 0;
}

static int bpf_qdisc_validate(void *kdata)
{
	return 0;
}

static int bpf_qdisc_reg(void *kdata, struct bpf_link *link)
{
	return register_qdisc(kdata);
}

static void bpf_qdisc_unreg(void *kdata, struct bpf_link *link)
{
	return unregister_qdisc(kdata);
}

static int Qdisc_ops__enqueue(struct sk_buff *skb__ref, struct Qdisc *sch,
			       struct sk_buff **to_free)
{
	return 0;
}

static struct sk_buff *Qdisc_ops__dequeue(struct Qdisc *sch)
{
	return NULL;
}

static struct sk_buff *Qdisc_ops__peek(struct Qdisc *sch)
{
	return NULL;
}

static int Qdisc_ops__init(struct Qdisc *sch, struct nlattr *arg,
			    struct netlink_ext_ack *extack)
{
	return 0;
}

static void Qdisc_ops__reset(struct Qdisc *sch)
{
}

static void Qdisc_ops__destroy(struct Qdisc *sch)
{
}

static int Qdisc_ops__change(struct Qdisc *sch, struct nlattr *arg,
			      struct netlink_ext_ack *extack)
{
	return 0;
}

static void Qdisc_ops__attach(struct Qdisc *sch)
{
}

static int Qdisc_ops__change_tx_queue_len(struct Qdisc *sch, unsigned int new_len)
{
	return 0;
}

static void Qdisc_ops__change_real_num_tx(struct Qdisc *sch, unsigned int new_real_tx)
{
}

static int Qdisc_ops__dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return 0;
}

static int Qdisc_ops__dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	return 0;
}

static void Qdisc_ops__ingress_block_set(struct Qdisc *sch, u32 block_index)
{
}

static void Qdisc_ops__egress_block_set(struct Qdisc *sch, u32 block_index)
{
}

static u32 Qdisc_ops__ingress_block_get(struct Qdisc *sch)
{
	return 0;
}

static u32 Qdisc_ops__egress_block_get(struct Qdisc *sch)
{
	return 0;
}

static struct Qdisc_ops __bpf_ops_qdisc_ops = {
	.enqueue = Qdisc_ops__enqueue,
	.dequeue = Qdisc_ops__dequeue,
	.peek = Qdisc_ops__peek,
	.init = Qdisc_ops__init,
	.reset = Qdisc_ops__reset,
	.destroy = Qdisc_ops__destroy,
	.change = Qdisc_ops__change,
	.attach = Qdisc_ops__attach,
	.change_tx_queue_len = Qdisc_ops__change_tx_queue_len,
	.change_real_num_tx = Qdisc_ops__change_real_num_tx,
	.dump = Qdisc_ops__dump,
	.dump_stats = Qdisc_ops__dump_stats,
	.ingress_block_set = Qdisc_ops__ingress_block_set,
	.egress_block_set = Qdisc_ops__egress_block_set,
	.ingress_block_get = Qdisc_ops__ingress_block_get,
	.egress_block_get = Qdisc_ops__egress_block_get,
};

static struct bpf_struct_ops bpf_Qdisc_ops = {
	.verifier_ops = &bpf_qdisc_verifier_ops,
	.reg = bpf_qdisc_reg,
	.unreg = bpf_qdisc_unreg,
	.check_member = bpf_qdisc_check_member,
	.init_member = bpf_qdisc_init_member,
	.init = bpf_qdisc_init,
	.validate = bpf_qdisc_validate,
	.name = "Qdisc_ops",
	.cfi_stubs = &__bpf_ops_qdisc_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_qdisc_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc skb_kfunc_dtors[] = {
		{
			.btf_id       = skb_kfunc_dtor_ids[0],
			.kfunc_btf_id = skb_kfunc_dtor_ids[1]
		},
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_qdisc_kfunc_set);
	ret = ret ?: register_btf_id_dtor_kfuncs(skb_kfunc_dtors,
						 ARRAY_SIZE(skb_kfunc_dtors),
						 THIS_MODULE);
	ret = ret ?: register_bpf_struct_ops(&bpf_Qdisc_ops, Qdisc_ops);

	return ret;
}
late_initcall(bpf_qdisc_kfunc_init);
