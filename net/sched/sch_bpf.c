// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Programmable Qdisc with eBPF
 *
 * Copyright (C) 2022, ByteDance, Cong Wang <cong.wang@bytedance.com>
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define ACT_BPF_NAME_LEN	256

struct sch_bpf_prog {
	struct bpf_prog *prog;
	const char *name;
};

struct sch_bpf_class {
	struct Qdisc_class_common common;
	struct Qdisc *qdisc;

	unsigned int drops;
	unsigned int overlimits;
	struct gnet_stats_basic_sync bstats;
};

struct sch_bpf_qdisc {
	struct tcf_proto __rcu *filter_list; /* optional external classifier */
	struct tcf_block *block;
	struct Qdisc_class_hash clhash;
	struct sch_bpf_prog enqueue_prog;
	struct sch_bpf_prog dequeue_prog;

	struct qdisc_watchdog watchdog;
};

static int sch_bpf_dump_prog(const struct sch_bpf_prog *prog, struct sk_buff *skb,
			     int name, int id, int tag)
{
	struct nlattr *nla;

	if (prog->name &&
	    nla_put_string(skb, name, prog->name))
		return -EMSGSIZE;

	if (nla_put_u32(skb, id, prog->prog->aux->id))
		return -EMSGSIZE;

	nla = nla_reserve(skb, tag, sizeof(prog->prog->tag));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), prog->prog->tag, nla_len(nla));
	return 0;
}

static int sch_bpf_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	struct nlattr *opts;
	u32 bpf_flags = 0;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (bpf_flags && nla_put_u32(skb, TCA_SCH_BPF_FLAGS, bpf_flags))
		goto nla_put_failure;

	if (sch_bpf_dump_prog(&q->enqueue_prog, skb, TCA_SCH_BPF_ENQUEUE_PROG_NAME,
			      TCA_SCH_BPF_ENQUEUE_PROG_ID, TCA_SCH_BPF_ENQUEUE_PROG_TAG))
		goto nla_put_failure;
	if (sch_bpf_dump_prog(&q->dequeue_prog, skb, TCA_SCH_BPF_DEQUEUE_PROG_NAME,
			      TCA_SCH_BPF_DEQUEUE_PROG_ID, TCA_SCH_BPF_DEQUEUE_PROG_TAG))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int sch_bpf_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	return 0;
}

static struct sch_bpf_class *sch_bpf_find(struct Qdisc *sch, u32 classid)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (!clc)
		return NULL;
	return container_of(clc, struct sch_bpf_class, common);
}

static int sch_bpf_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			   struct sk_buff **to_free)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb);
	struct sch_bpf_ctx ctx = {};
	struct sch_bpf_class *cl;
	int res = NET_XMIT_SUCCESS;
	struct bpf_prog *enqueue;
	s64 now;

	enqueue = rcu_dereference(q->enqueue_prog.prog);
	bpf_compute_data_pointers(skb);
	ctx.skb = (struct __sk_buff *)skb;
	ctx.classid = sch->handle;
	res = bpf_prog_run(enqueue, &ctx);
	switch (res) {
	case SCH_BPF_THROTTLE:
		now = ktime_get_ns();
		qdisc_watchdog_schedule_ns(&q->watchdog, now + ctx.delay);
		qdisc_qstats_overlimit(sch);
		fallthrough;
	case SCH_BPF_QUEUED:
		return NET_XMIT_SUCCESS;
	case SCH_BPF_CN:
		return NET_XMIT_CN;
	case SCH_BPF_PASS:
		break;
	default:
		__qdisc_drop(skb, to_free);
		return NET_XMIT_DROP;
	}

	cl = sch_bpf_find(sch, ctx.classid);
	if (!cl || !cl->qdisc) {
		if (res & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return res;
	}

	res = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (res != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(res)) {
			qdisc_qstats_drop(sch);
			cl->drops++;
		}
		return res;
	}

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return res;
}

static struct sk_buff *sch_bpf_dequeue(struct Qdisc *sch)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	struct sk_buff *ret = NULL;
	struct sch_bpf_ctx ctx = {};
	struct bpf_prog *dequeue;
	struct sch_bpf_class *cl;
	s64 now;
	int res;

	dequeue = rcu_dereference(q->dequeue_prog.prog);
	ctx.classid = sch->handle;
	res = bpf_prog_run(dequeue, &ctx);
	switch (res) {
	case SCH_BPF_DEQUEUED:
		ret = (struct sk_buff *)ctx.skb;
		break;
	case SCH_BPF_THROTTLE:
		now = ktime_get_ns();
		qdisc_watchdog_schedule_ns(&q->watchdog, now + ctx.delay);
		qdisc_qstats_overlimit(sch);
		cl->overlimits++;
		return NULL;
	case SCH_BPF_PASS:
		cl = sch_bpf_find(sch, ctx.classid);
		if (!cl || !cl->qdisc)
			return NULL;
		ret = qdisc_dequeue_peeked(cl->qdisc);
		if (ret) {
			qdisc_bstats_update(sch, ret);
			qdisc_qstats_backlog_dec(sch, ret);
			sch->q.qlen--;
		}
	}

	return ret;
}

static struct Qdisc *sch_bpf_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct sch_bpf_class *cl = (struct sch_bpf_class *)arg;

	return cl->qdisc;
}

static int sch_bpf_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
			 struct Qdisc **old, struct netlink_ext_ack *extack)
{
	struct sch_bpf_class *cl = (struct sch_bpf_class *)arg;

	if (new)
		*old = qdisc_replace(sch, new, &cl->qdisc);
	return 0;
}

static unsigned long sch_bpf_bind(struct Qdisc *sch, unsigned long parent,
				  u32 classid)
{
	return 0;
}

static void sch_bpf_unbind(struct Qdisc *q, unsigned long cl)
{
}

static unsigned long sch_bpf_search(struct Qdisc *sch, u32 handle)
{
	return (unsigned long)sch_bpf_find(sch, handle);
}

static struct tcf_block *sch_bpf_tcf_block(struct Qdisc *sch, unsigned long cl,
					   struct netlink_ext_ack *extack)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return q->block;
}

static const struct nla_policy sch_bpf_policy[TCA_SCH_BPF_MAX + 1] = {
	[TCA_SCH_BPF_FLAGS]		= { .type = NLA_U32 },
	[TCA_SCH_BPF_ENQUEUE_PROG_FD]	= { .type = NLA_U32 },
	[TCA_SCH_BPF_ENQUEUE_PROG_NAME]	= { .type = NLA_NUL_STRING,
					    .len = ACT_BPF_NAME_LEN },
	[TCA_SCH_BPF_DEQUEUE_PROG_FD]	= { .type = NLA_U32 },
	[TCA_SCH_BPF_DEQUEUE_PROG_NAME]	= { .type = NLA_NUL_STRING,
					    .len = ACT_BPF_NAME_LEN },
};

static int bpf_init_prog(struct nlattr *fd, struct nlattr *name, struct sch_bpf_prog *prog)
{
	char *prog_name = NULL;
	struct bpf_prog *fp;
	u32 bpf_fd;

	if (!fd)
		return -EINVAL;
	bpf_fd = nla_get_u32(fd);

	fp = bpf_prog_get_type(bpf_fd, BPF_PROG_TYPE_SCHED_QDISC);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	if (name) {
		prog_name = nla_memdup(name, GFP_KERNEL);
		if (!prog_name) {
			bpf_prog_put(fp);
			return -ENOMEM;
		}
	}

	prog->name = prog_name;
	prog->prog = fp;
	return 0;
}

static void bpf_cleanup_prog(struct sch_bpf_prog *prog)
{
	if (prog->prog)
		bpf_prog_put(prog->prog);
	kfree(prog->name);
}

static int sch_bpf_change(struct Qdisc *sch, struct nlattr *opt,
			  struct netlink_ext_ack *extack)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_SCH_BPF_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_SCH_BPF_MAX, opt,
					  sch_bpf_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_SCH_BPF_FLAGS]) {
		u32 bpf_flags = nla_get_u32(tb[TCA_SCH_BPF_FLAGS]);

		if (bpf_flags & ~TCA_SCH_BPF_FLAG_DIRECT)
			return -EINVAL;
	}

	err = bpf_init_prog(tb[TCA_SCH_BPF_ENQUEUE_PROG_FD],
			    tb[TCA_SCH_BPF_ENQUEUE_PROG_NAME], &q->enqueue_prog);
	if (err)
		return err;
	err = bpf_init_prog(tb[TCA_SCH_BPF_DEQUEUE_PROG_FD],
			    tb[TCA_SCH_BPF_DEQUEUE_PROG_NAME], &q->dequeue_prog);
	return err;
}

static int sch_bpf_init(struct Qdisc *sch, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	int err;

	qdisc_watchdog_init(&q->watchdog, sch);
	if (opt) {
		err = sch_bpf_change(sch, opt, extack);
		if (err)
			return err;
	}

	err = tcf_block_get(&q->block, &q->filter_list, sch, extack);
	if (err)
		return err;

	return qdisc_class_hash_init(&q->clhash);
}

static void sch_bpf_reset(struct Qdisc *sch)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}

static void sch_bpf_destroy(struct Qdisc *sch)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	tcf_block_put(q->block);
	qdisc_class_hash_destroy(&q->clhash);
	bpf_cleanup_prog(&q->enqueue_prog);
	bpf_cleanup_prog(&q->dequeue_prog);
}

static int sch_bpf_change_class(struct Qdisc *sch, u32 classid,
				u32 parentid, struct nlattr **tca,
				unsigned long *arg,
				struct netlink_ext_ack *extack)
{
	struct sch_bpf_class *cl = (struct sch_bpf_class *)*arg;
	struct sch_bpf_qdisc *q = qdisc_priv(sch);

	if (!cl) {
		cl = kzalloc(sizeof(*cl), GFP_KERNEL);
		if (!cl)
			return -ENOBUFS;
		qdisc_class_hash_insert(&q->clhash, &cl->common);
	}

	qdisc_class_hash_grow(sch, &q->clhash);
	*arg = (unsigned long)cl;
	return 0;
}

static int sch_bpf_delete(struct Qdisc *sch, unsigned long arg,
			  struct netlink_ext_ack *extack)
{
	struct sch_bpf_class *cl = (struct sch_bpf_class *)arg;
	struct sch_bpf_qdisc *q = qdisc_priv(sch);

	qdisc_class_hash_remove(&q->clhash, &cl->common);
	if (cl->qdisc)
		qdisc_put(cl->qdisc);
	return 0;
}

static int sch_bpf_dump_class(struct Qdisc *sch, unsigned long arg,
			      struct sk_buff *skb, struct tcmsg *tcm)
{
	return 0;
}

static int
sch_bpf_dump_class_stats(struct Qdisc *sch, unsigned long arg, struct gnet_dump *d)
{
	struct sch_bpf_class *cl = (struct sch_bpf_class *)arg;
	struct gnet_stats_queue qs = {
		.drops = cl->drops,
		.overlimits = cl->overlimits,
	};
	__u32 qlen = 0;

	if (cl->qdisc)
		qdisc_qstats_qlen_backlog(cl->qdisc, &qlen, &qs.backlog);
	else
		qlen = 0;

	if (gnet_stats_copy_basic(d, NULL, &cl->bstats, true) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &qs, qlen) < 0)
		return -1;
	return 0;
}

static void sch_bpf_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct sch_bpf_qdisc *q = qdisc_priv(sch);
	struct sch_bpf_class *cl;
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, &q->clhash.hash[i], common.hnode) {
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
				arg->stop = 1;
				return;
			}
			arg->count++;
		}
	}
}

static const struct Qdisc_class_ops sch_bpf_class_ops = {
	.graft		=	sch_bpf_graft,
	.leaf		=	sch_bpf_leaf,
	.find		=	sch_bpf_search,
	.change		=	sch_bpf_change_class,
	.delete		=	sch_bpf_delete,
	.tcf_block	=	sch_bpf_tcf_block,
	.bind_tcf	=	sch_bpf_bind,
	.unbind_tcf	=	sch_bpf_unbind,
	.dump		=	sch_bpf_dump_class,
	.dump_stats	=	sch_bpf_dump_class_stats,
	.walk		=	sch_bpf_walk,
};

static struct Qdisc_ops sch_bpf_qdisc_ops __read_mostly = {
	.cl_ops		=	&sch_bpf_class_ops,
	.id		=	"bpf",
	.priv_size	=	sizeof(struct sch_bpf_qdisc),
	.enqueue	=	sch_bpf_enqueue,
	.dequeue	=	sch_bpf_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	sch_bpf_init,
	.reset		=	sch_bpf_reset,
	.destroy	=	sch_bpf_destroy,
	.change		=	sch_bpf_change,
	.dump		=	sch_bpf_dump,
	.dump_stats	=	sch_bpf_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init sch_bpf_mod_init(void)
{
	return register_qdisc(&sch_bpf_qdisc_ops);
}

static void __exit sch_bpf_mod_exit(void)
{
	unregister_qdisc(&sch_bpf_qdisc_ops);
}

module_init(sch_bpf_mod_init)
module_exit(sch_bpf_mod_exit)
MODULE_AUTHOR("Cong Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("eBPF queue discipline");
