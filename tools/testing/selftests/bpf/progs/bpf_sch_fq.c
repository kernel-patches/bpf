// SPDX-License-Identifier: GPL-2.0

#define fq_flow fq_flow_kern
#define fq_sched_data fq_sched_data_kern
#include <vmlinux.h>
#undef fq_sched_data
#undef fq_flow
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"
#include "bpf_qdisc_common.h"
#include "bpf_tracing_net.h"

#define NR_QUEUES 4

#define FQ_TREE_LOG 15
#define FQ_FLOW_TREE_ENTRIES (1 << FQ_TREE_LOG) /* 32k */

#define FQ_TREE_LOOP_MAX 16	   /* Search 16 depth rbtree to look
				    * for a sk.
				    */
#define FQ_DEQUEUE_LOOP_MAX (1 << 15) /* Max look for 32k flows to
				       * dequeue at a skb.
				       */
#define FQ_GC_MAX 8
#define FQ_GC_AGE (3*HZ)

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1 : __max2; })

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1 : __min2; })

struct sock *dummy_sk;
struct sk_buff *dummy_skb;
int zero = 0;

static inline struct fq_skb_cb *fq_skb_cb(struct sk_buff *skb)
{
	return (struct fq_skb_cb *)qdisc_skb_cb(skb)->data;
}

struct skb_node {
	/* cannot directly read time_to_send from skbn->skb,
	 * so duplicate the time_to_send here.
	 */
	u64 time_to_send;
	struct sk_buff __kptr * skb;
	struct bpf_list_node list_node;
	struct bpf_rb_node rb_node;
	struct bpf_refcount refcount;
};

struct fq_flow {
	struct bpf_spin_lock	lock;
	struct bpf_rb_root	skb_root __contains(skb_node, rb_node);
	struct bpf_list_head	skb_list __contains(skb_node, list_node);
	struct bpf_rb_node	fq_node;
	u64			tail_time_to_send;
	u64			stat_fastpath_packets;
	unsigned long		sk_long;
	unsigned long		age;
	u32			socket_hash;
	u32			qlen;
	u64			time_next_packet;
	int			credit;
	bool			throttled;
	struct bpf_list_node 	new_flow_node;
	struct bpf_list_node 	old_flow_node;
	struct bpf_rb_node  	rate_node;
	struct bpf_refcount	refcount;
};

struct fq_sched_data {
	struct bpf_spin_lock lock;
	struct bpf_list_head new_flows __contains(fq_flow, new_flow_node);
	struct bpf_list_head old_flows __contains(fq_flow, old_flow_node);
	struct bpf_rb_root   delayed   __contains(fq_flow, rate_node);	/* for rate limited flows */

	u64		time_next_delayed_flow;
	unsigned long	unthrottle_latency_ns;

	u32		quantum;
	u32		initial_quantum;
	u32		flow_refill_delay;
	u32		flow_plimit;	/* max packets per flow */
	unsigned long	flow_max_rate;	/* optional max rate per flow */
	u64		horizon;	/* horizon in ns */
	u32		orphan_mask;	/* mask for orphaned skb */
	u32		low_rate_threshold;
	u8		rate_enable;
	u8		fq_trees_log;
	u8		horizon_drop;
	u32		timer_slack; /* hrtimer slack in ns */

	u32		flows;
	u32		inactive_flows; /* Flows with no packet to send. */
	u32		throttled_flows;

	u64		stat_throttled;
	u64		stat_gc_flows;

	u64		stat_internal_packets; /* aka highprio */
	u64		stat_horizon_drops;
	u64		stat_horizon_caps;
	u64		stat_flows_plimit;
	u64		stat_pkts_too_long;
	u64		stat_allocation_errors;
};

struct fq_flow_root {
	struct bpf_spin_lock lock;
	struct bpf_rb_root root __contains(fq_flow, fq_node);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fq_sched_data);
	__uint(max_entries, NR_QUEUES);
} priv_data_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fq_flow);
	__uint(max_entries, NR_QUEUES);
} fq_internal_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned long);
	__type(value, int);
	__uint(max_entries, NR_QUEUES);
} sch_to_idx_map SEC(".maps");

struct fq_flow_root_array {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fq_flow_root);
	__uint(max_entries, FQ_FLOW_TREE_ENTRIES);
} fq_flows0 SEC(".maps"),
  fq_flows1 SEC(".maps"),
  fq_flows2 SEC(".maps"),
  fq_flows3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__uint(max_entries, NR_QUEUES);
	__array(values, struct fq_flow_root_array);
} fq_flow_roots SEC(".maps") = {
	.values = {
		[0] = &fq_flows0,
		[1] = &fq_flows1,
		[2] = &fq_flows2,
		[3] = &fq_flows3,
	}
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock lock;
private(A) __u64 used_idx[NR_QUEUES];

struct bpf_rb_node *bpf_rbtree_root(struct bpf_rb_root *root) __ksym;
struct bpf_rb_node *bpf_rbtree_left(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
struct bpf_rb_node *bpf_rbtree_right(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;

static int sch_idx(struct Qdisc *sch)
{
	unsigned long sch_long = (unsigned long)sch;
	int *idx;

	idx = bpf_map_lookup_elem(&sch_to_idx_map, &sch_long);
	if (!idx || *idx < 0 || *idx >= NR_QUEUES)
		return -1;

	return *idx;
}

static struct fq_sched_data *qdisc_priv(struct Qdisc *sch)
{
	int idx = sch_idx(sch);

	if (idx == -1)
		return NULL;

	return bpf_map_lookup_elem(&priv_data_array, &idx);
}

static struct fq_flow *fq_internal(struct Qdisc *sch)
{
	int idx = sch_idx(sch);

	if (idx == -1)
		return NULL;

	return bpf_map_lookup_elem(&fq_internal_array, &idx);
}

/*
 * f->tail and f->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes f->tail low order bit must be 0 since alignof(struct sk_buff) >= 2
 */
static void fq_flow_set_detached(struct fq_flow *f, u64 jiffies_now)
{
	f->age = jiffies_now;
}

static bool fq_flow_is_detached(const struct fq_flow *f)
{
	return !!f->age;
}

static bool fq_flow_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct fq_flow *f_a;
	struct fq_flow *f_b;

	f_a = bpf_rb_entry(a, struct fq_flow, fq_node);
	f_b = bpf_rb_entry(b, struct fq_flow, fq_node);

	return f_a->sk_long < f_b->sk_long;
}

static bool fq_flow_is_throttled(const struct fq_flow *f)
{
	return f->throttled;
}

static void fq_flow_unset_throttled(struct fq_sched_data *q, struct fq_flow *f)
{
	struct bpf_rb_node *rb_n;

	rb_n = bpf_rbtree_remove(&q->delayed, &f->rate_node);
	if (rb_n) {
		f = container_of(rb_n, struct fq_flow, rate_node);
		q->throttled_flows--;
		bpf_list_push_back(&q->old_flows, &f->old_flow_node);
	}
}

static bool fq_flow_delay_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct fq_flow *f_a;
	struct fq_flow *f_b;

	f_a = bpf_rb_entry(a, struct fq_flow, rate_node);
	f_b = bpf_rb_entry(b, struct fq_flow, rate_node);

	return f_a->time_next_packet < f_b->time_next_packet;
}

static void fq_flow_set_throttled(struct fq_sched_data *q, struct fq_flow *f)
{
	bpf_rbtree_add(&q->delayed, &f->rate_node, fq_flow_delay_less);
	q->throttled_flows++;
	q->stat_throttled++;
	f->throttled = true;
	if (q->time_next_delayed_flow > f->time_next_packet)
		q->time_next_delayed_flow = f->time_next_packet;
}

static bool fq_gc_candidate(const struct fq_flow *f, u64 jiffies_now)
{
	return fq_flow_is_detached(f) &&
		time_after(jiffies_now, f->age + FQ_GC_AGE);
}

/* Fast path can be used if :
 * 1) Packet tstamp is in the past.
 * 2) FQ qlen == 0   OR
 *   (no flow is currently eligible for transmit,
 *    AND fast path queue has less than 8 packets)
 * 3) No SO_MAX_PACING_RATE on the socket (if any).
 * 4) No @maxrate attribute on this qdisc,
 *
 * FQ can not use generic TCQ_F_CAN_BYPASS infrastructure.
 */
static bool fq_fastpath_check(struct Qdisc *sch, struct sk_buff *skb, u64 now,
			      struct fq_flow *f_internal)
{
	const struct fq_sched_data *q = qdisc_priv(sch);
	const struct sock *sk;

	/* impossible */
	if (!q)
		return false;

	if (fq_skb_cb(skb)->time_to_send > now)
		return false;

	if (sch->q.qlen != 0) {
		/* Even if some packets are stored in this qdisc,
		 * we can still enable fast path if all of them are
		 * scheduled in the future (ie no flows are eligible)
		 * or in the fast path queue.
		 */
		if (q->flows != q->inactive_flows + q->throttled_flows)
			return false;

		/* Do not allow fast path queue to explode, we want Fair Queue mode
		 * under pressure.
		 */
		if (f_internal->qlen >= 8)
			return false;
	}

	sk = skb->sk;
	if (sk && sk_fullsock(sk) && !sk_is_tcp(sk) &&
	    sk->sk_max_pacing_rate != ~0UL)
		return false;

	if (q->flow_max_rate != ~0UL)
		return false;

	return true;
}

static struct fq_flow *fq_classify(struct Qdisc *sch, struct sk_buff *skb, u64 jiffies_now,
				   bool *unthrottle)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct bpf_rb_node *p;
	struct sock *sk = skb->sk;
	struct fq_flow_root *root;
	unsigned long sk_long;
	struct fq_flow *f;

	__u32 idx = sch_idx(sch), socket_hash = 0, key;
	struct bpf_rb_node *tofree[FQ_GC_MAX];
	struct bpf_map *fq_flows_bucket;
	struct fq_flow *gc_f;
	int i, fcnt = 0;

	/* impossible */
	if (!q || idx == -1)
		return NULL;

	/* This force sk_long to be a scalar. Otherwise,
	 * reading skb->sk is a ptr_to_btf_id and the verifier
	 * does not allow to do ptr math that is needed in
	 * the hash_ptr()
	 */
	bpf_probe_read_kernel(&sk_long, sizeof(sk_long), &skb->sk);

	*unthrottle = false;

	/* SYNACK messages are attached to a TCP_NEW_SYN_RECV request socket
	 * or a listener (SYNCOOKIE mode)
	 * 1) request sockets are not full blown,
	 *    they do not contain sk_pacing_rate
	 * 2) They are not part of a 'flow' yet
	 * 3) We do not want to rate limit them (eg SYNFLOOD attack),
	 *    especially if the listener set SO_MAX_PACING_RATE
	 * 4) We pretend they are orphaned
	 */
	if (!sk || sk_listener_or_tw(sk)) {
		unsigned long hash = bpf_skb_get_hash(skb) & q->orphan_mask;

		/* By forcing low order bit to 1, we make sure to not
		 * collide with a local flow (socket pointers are word aligned)
		 */
		sk_long = (hash << 1) | 1UL;
		/* It sets skb->sk to NULL.
		 * It is needed by the "if (sk) rate = ..." in the bpf_fq_dequeue.
		 */
		bpf_qdisc_skb_orphan(skb);
	} else if (sk->sk_state == TCP_CLOSE) {
		unsigned long hash = bpf_skb_get_hash(skb) & q->orphan_mask;
		/*
		 * Sockets in TCP_CLOSE are non connected.
		 * Typical use case is UDP sockets, they can send packets
		 * with sendto() to many different destinations.
		 * We probably could use a generic bit advertising
		 * non connected sockets, instead of sk_state == TCP_CLOSE,
		 * if we care enough.
		 */
		sk_long = (hash << 1) | 1UL;
	} else {
		socket_hash = sk->sk_hash;
	}

	fq_flows_bucket = bpf_map_lookup_elem(&fq_flow_roots, &idx);
	if (!fq_flows_bucket)
		return NULL;

	key = hash_ptr(sk_long, q->fq_trees_log);
	root = bpf_map_lookup_elem(fq_flows_bucket, &key);
	if (!root)
		return NULL;

	f = NULL;
	bpf_spin_lock(&root->lock);
	p = bpf_rbtree_root(&root->root);
	while (can_loop) {
		if (!p)
			break;

		gc_f = bpf_rb_entry(p, struct fq_flow, fq_node);
		if (gc_f->sk_long == sk_long) {
			f = bpf_refcount_acquire(gc_f);
			break;
		}

		if (fcnt < FQ_GC_MAX && fq_gc_candidate(gc_f, jiffies_now))
			tofree[fcnt++] = p;

		if (gc_f->sk_long > sk_long)
			p = bpf_rbtree_left(&root->root, p);
		else
			p = bpf_rbtree_right(&root->root, p);
	}

	for (i = 0; i < fcnt; i++) {
		p = tofree[i];
		tofree[i] = bpf_rbtree_remove(&root->root, p);
	}

	bpf_spin_unlock(&root->lock);

	for (i = 0; i < fcnt; i++) {
		p = tofree[i];
		if (p) {
			gc_f = bpf_rb_entry(p, struct fq_flow, fq_node);
			bpf_obj_drop(gc_f);
		}
	}

	q->flows -= fcnt;
	q->inactive_flows -= fcnt;
	q->stat_gc_flows += fcnt;

	if (f) {
		/* socket might have been reallocated, so check
		 * if its sk_hash is the same.
		 * It not, we need to refill credit with
		 * initial quantum
		 */
		if (unlikely((unsigned long)skb->sk == sk_long &&
			     f->socket_hash != socket_hash)) {
			f->credit = q->initial_quantum;
			f->socket_hash = socket_hash;
			f->time_next_packet = 0ULL;
			if (q->rate_enable)
				bpf_qdisc_set_sk_pacing(skb, SK_PACING_FQ);
			if (fq_flow_is_throttled(f))
				*unthrottle = true;
		}
	} else {
		struct fq_flow *f_new;

		f_new = bpf_obj_new(typeof(*f_new));
		if (unlikely(!f_new)) {
			q->stat_allocation_errors++;
			return NULL;
		}

		/* bpf mem allocator does not zero memory */
		f_new->tail_time_to_send = 0;
		f_new->stat_fastpath_packets = 0;
		f_new->sk_long = sk_long;
		f_new->socket_hash = socket_hash;
		f_new->qlen = 0;
		f_new->time_next_packet = 0;
		f_new->credit = q->initial_quantum;
		f_new->throttled = 0;

		fq_flow_set_detached(f_new, jiffies_now);
		f = bpf_refcount_acquire(f_new);
		bpf_spin_lock(&root->lock);
		bpf_rbtree_add(&root->root, &f_new->fq_node, fq_flow_less);
		bpf_spin_unlock(&root->lock);

		q->flows++;
		q->inactive_flows++;
		if (q->rate_enable)
			bpf_qdisc_set_sk_pacing(skb, SK_PACING_FQ);
	}

	return f;
}

static bool bpf_list_empty(struct bpf_list_head *bpf_head)
{
	struct list_head *head;

	head = bpf_core_cast(bpf_head, struct list_head);
	return (!head->next || head->next == head);
}

static struct skb_node *list_to_skbn(struct bpf_list_node *l_n)
{
	return l_n ? container_of(l_n, struct skb_node, list_node) : NULL;
}

static struct skb_node *rb_to_skbn(struct bpf_rb_node *rb_n)
{
	return rb_n ? container_of(rb_n, struct skb_node, rb_node) : NULL;
}

/* Remove one skb from flow queue.
 * This skb must be the return value of prior fq_peek().
 */
static struct skb_node *fq_dequeue_skbn(struct Qdisc *sch, struct fq_flow *flow,
					struct skb_node *skbn, bool from_rb)
{
	struct bpf_list_node *l_n;
	struct bpf_rb_node *rb_n;

	if (from_rb) {
		rb_n = bpf_rbtree_remove(&flow->skb_root, &skbn->rb_node);
		skbn = rb_n ? rb_to_skbn(rb_n) : NULL;
	} else {
		l_n = bpf_list_pop_front(&flow->skb_list);
		skbn = l_n ? list_to_skbn(l_n) : NULL;
	}

	return skbn;
}

static struct skb_node *fq_internal_dequeue_skbn(struct Qdisc *sch, struct fq_flow *flow,
						 struct skb_node *skbn, bool from_rb)
{
	struct bpf_list_node *l_n;
	struct bpf_rb_node *rb_n;

	if (from_rb) {
		rb_n = bpf_rbtree_remove(&flow->skb_root, &skbn->rb_node);
		skbn = rb_n ? rb_to_skbn(rb_n) : NULL;
	} else {
		l_n = bpf_list_pop_front(&flow->skb_list);
		skbn = l_n ? list_to_skbn(l_n) : NULL;
	}

	return skbn;
}

static struct sk_buff *skbn_drop(struct Qdisc *sch, struct skb_node *skbn)
{
	struct sk_buff *skb;

	if (!skbn)
		return NULL;

	skb = bpf_kptr_xchg(&skbn->skb, NULL);
	bpf_obj_drop(skbn);

	if (skb) {
		bpf_qdisc_bstats_update(sch, skb);
		qdisc_qstats_backlog_dec(sch, skb);
		sch->q.qlen--;
	}

	return skb;
}

static struct skb_node *fq_peek(struct fq_flow *flow, bool *from_rb)
{
	struct bpf_rb_node *rb_n = bpf_rbtree_first(&flow->skb_root);
	struct bpf_list_node *l_n = bpf_list_front(&flow->skb_list);
	struct skb_node *rb_skbn;
	struct skb_node *l_skbn;

	if (!rb_n) {
		*from_rb = false;
		return l_n ? list_to_skbn(l_n) : NULL;
	}

	if (!l_n) {
		*from_rb = true;
		return rb_n ? rb_to_skbn(rb_n) : NULL;
	}

	l_skbn = list_to_skbn(l_n);
	rb_skbn = rb_to_skbn(rb_n);

	if (rb_skbn->time_to_send < l_skbn->time_to_send) {
		*from_rb = true;
		return rb_skbn;
	} else {
		*from_rb = false;
		return l_skbn;
	}
}

static bool skbn_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct skb_node *skbn_a, *skbn_b;

	skbn_a = container_of(a, struct skb_node, rb_node);
	skbn_b = container_of(b, struct skb_node, rb_node);

	return skbn_a->time_to_send < skbn_b->time_to_send;
}

/* __always_inline. Otherwise, verifier rejects the "flow" related insn:
 * "same insn cannot be used with different pointers"
 * flow can be a map_value or a ptr-to-alloc-mem.
 */
static __always_inline void flow_queue_add(struct fq_flow *flow, struct skb_node *skbn)
{
	bool empty_list = bpf_list_empty(&flow->skb_list);

	bpf_spin_lock(&flow->lock);
	if (!empty_list || skbn->time_to_send >= flow->tail_time_to_send) {
		flow->tail_time_to_send = skbn->time_to_send;
		bpf_list_push_back(&flow->skb_list, &skbn->list_node);
	} else {
		bpf_rbtree_add(&flow->skb_root, &skbn->rb_node, skbn_less);
	}
	bpf_spin_unlock(&flow->lock);
	flow->age = 0;
}

static bool fq_packet_beyond_horizon(const struct sk_buff *skb,
				     const struct fq_sched_data *q, u64 now)
{
	return unlikely((s64)skb->tstamp > (s64)(now + q->horizon));
}

/* inline because >5 arguments */
static __always_inline
int queue_skb_and_drop_flow(struct Qdisc *sch, struct fq_sched_data *q,
			    struct fq_flow *f, struct sk_buff *skb,
			    struct bpf_sk_buff_ptr *to_free,
			    u64 jiffies_now, bool unthrottle)
{
	struct skb_node *skbn;

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn) {
		bpf_obj_drop(f);
		return qdisc_drop(skb, sch, to_free);
	}

	f->qlen++;
	sch->q.qlen++;

	/* finish reading everything we need on skb before
	 * bpf_kptr_xchg. After xchg, neither skb nor
	 * skbn->skb is readable.
	 */
	skbn->time_to_send = fq_skb_cb(skb)->time_to_send;
	qdisc_qstats_backlog_inc(sch, skb);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		qdisc_drop(skb, sch, to_free);
	/* Note: this overwrites f->age */
	flow_queue_add(f, skbn);

	bpf_spin_lock(&q->lock);
	if (fq_flow_is_detached(f)) {
		struct fq_flow *f_dup;

		f_dup = bpf_refcount_acquire(f);
		if (f_dup)
			bpf_list_push_back(&q->new_flows, &f_dup->new_flow_node);
		if (time_after(jiffies_now, f->age + q->flow_refill_delay))
			f->credit = max_t(u32, f->credit, q->quantum);
	} else {
		if (unthrottle)
			fq_flow_unset_throttled(q, f);
	}
	bpf_spin_unlock(&q->lock);
	bpf_obj_drop(f);

	return NET_XMIT_SUCCESS;
}

static int queue_skb(struct Qdisc *sch, struct fq_sched_data *q,
		     struct fq_flow *f, struct sk_buff *skb,
		     struct bpf_sk_buff_ptr *to_free)
{
	struct skb_node *skbn;

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn)
		return qdisc_drop(skb, sch, to_free);

	f->qlen++;
	sch->q.qlen++;

	/* finish reading everything we need on skb before
	 * bpf_kptr_xchg. After xchg, neither skb nor
	 * skbn->skb is readable.
	 */
	skbn->time_to_send = fq_skb_cb(skb)->time_to_send;
	qdisc_qstats_backlog_inc(sch, skb);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		qdisc_drop(skb, sch, to_free);
	/* Note: this overwrites f->age */
	flow_queue_add(f, skbn);

	return NET_XMIT_SUCCESS;
}

SEC("struct_ops")
int BPF_PROG(bpf_fq_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct fq_flow *f, *f_internal = fq_internal(sch);
	struct fq_sched_data *q = qdisc_priv(sch);
	bool unthrottle;
	u64 now, jiffies_now;

	if (!q || !f_internal)
		return qdisc_drop(skb, sch, to_free);

	if (unlikely(sch->q.qlen >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

	now = bpf_ktime_get_ns();
	jiffies_now = bpf_jiffies64();

	if (!skb->tstamp) {
		fq_skb_cb(skb)->time_to_send = now;
	} else {
		/* Check if packet timestamp is too far in the future. */
		if (fq_packet_beyond_horizon(skb, q, now)) {
			if (q->horizon_drop) {
				q->stat_horizon_drops++;
				return qdisc_drop(skb, sch, to_free);
			}
			q->stat_horizon_caps++;
			skb->tstamp = now + q->horizon;
		}
		fq_skb_cb(skb)->time_to_send = skb->tstamp;
	}

	/* warning: no starvation prevention... */
	if (unlikely((skb->priority & TC_PRIO_MAX) == TC_PRIO_CONTROL) ||
	    fq_fastpath_check(sch, skb, now, f_internal)) {
		struct sock *sk = skb->sk;

		if (sk && !sk_listener_or_tw(sk))
			bpf_qdisc_skb_orphan(skb);
		q->stat_internal_packets++;
		return queue_skb(sch, q, f_internal, skb, to_free);
	}

	f = fq_classify(sch, skb, jiffies_now, &unthrottle);

	if (!f)
		return qdisc_drop(skb, sch, to_free);

	if (unlikely(f->qlen >= q->flow_plimit)) {
		q->stat_flows_plimit++;
		bpf_obj_drop(f);
		return qdisc_drop(skb, sch, to_free);
	}

	return queue_skb_and_drop_flow(sch, q, f, skb, to_free, jiffies_now, unthrottle);
}

static void fq_check_throttled(struct fq_sched_data *q, u64 now)
{
	struct bpf_rb_node *rb_n;
	unsigned long sample;
	u32 i;

	if (q->time_next_delayed_flow > now)
		return;

	/* Update unthrottle latency EWMA.
	 * This is cheap and can help diagnosing timer/latency problems.
	 */
	sample = (unsigned long)(now - q->time_next_delayed_flow);
	q->unthrottle_latency_ns -= q->unthrottle_latency_ns >> 3;
	q->unthrottle_latency_ns += sample >> 3;

	q->time_next_delayed_flow = ~0ULL;
	for (i = zero; (rb_n = bpf_rbtree_first(&q->delayed)) && i < FQ_TREE_LOOP_MAX && can_loop;
	     i++) {
		struct fq_flow *f = container_of(rb_n, struct fq_flow, rate_node);

		if (f->time_next_packet > now) {
			q->time_next_delayed_flow = f->time_next_packet;
			break;
		}
		fq_flow_unset_throttled(q, f);
	}
}

struct fq_flow *fq_flow_peek(struct fq_sched_data *q, bool *new)
{
	struct bpf_list_node *l_n;

	*new = false;
	l_n = bpf_list_front(&q->new_flows);
	if (l_n) {
		*new = true;
		return container_of(l_n, struct fq_flow, new_flow_node);
	}

	l_n = bpf_list_front(&q->old_flows);
	if (l_n) {
		*new = false;
		return container_of(l_n, struct fq_flow, old_flow_node);
	}

	return NULL;
}

struct fq_flow *fq_flow_pop_front(struct fq_sched_data *q, bool new)
{
	struct bpf_list_node *l_n;
	struct fq_flow *f = NULL;

	if (new) {
		l_n = bpf_list_pop_front(&q->new_flows);
		if (l_n)
			f = container_of(l_n, struct fq_flow, new_flow_node);
	} else {
		l_n = bpf_list_pop_front(&q->old_flows);
		if (l_n)
			f = container_of(l_n, struct fq_flow, old_flow_node);
	}

	return f;
}

SEC("struct_ops/bpf_fq_dequeue")
struct sk_buff *BPF_PROG(bpf_fq_dequeue, struct Qdisc *sch)
{
	struct fq_flow *f = NULL, *f_internal = fq_internal(sch);
	struct fq_sched_data *q = qdisc_priv(sch);
	u64 time_next_packet, now, jiffies_now;
	struct sk_buff *skb = NULL;
	struct skb_node *skbn = NULL;
	unsigned long rate;
	bool from_rb, new;
	u32 plen;

	if (!q || !f_internal)
		return NULL;

	if (!sch->q.qlen)
		return NULL;

	now = bpf_ktime_get_ns();
	jiffies_now = bpf_jiffies64();

	if (unlikely(f_internal->qlen)) {
		bpf_spin_lock(&f_internal->lock);
		skbn = fq_peek(f_internal, &from_rb);
		if (skbn) {
			skbn = fq_internal_dequeue_skbn(sch, f_internal, skbn, from_rb);
			bpf_spin_unlock(&f_internal->lock);
			skb = skbn_drop(sch, skbn);
			f_internal->qlen--;
			return skb;
		}
		bpf_spin_unlock(&f_internal->lock);
	}

	bpf_spin_lock(&q->lock);
	fq_check_throttled(q, now);
	bpf_spin_unlock(&q->lock);

	while (can_loop) {
		bpf_spin_lock(&q->lock);
		f = fq_flow_peek(q, &new);
		if (!f) {
			bpf_spin_unlock(&q->lock);
			if (q->time_next_delayed_flow != ~0ULL)
				bpf_qdisc_watchdog_schedule(sch, q->time_next_delayed_flow,
							    q->timer_slack);
			return NULL;
		}

		if (f->credit <= 0) {
			f->credit += q->quantum;
			f = fq_flow_pop_front(q, new);
			if (f) {
				bpf_list_push_back(&q->old_flows, &f->old_flow_node);
				f = NULL;
			}
			bpf_spin_unlock(&q->lock);
			continue;
		}

		f = bpf_refcount_acquire(f);
		bpf_spin_unlock(&q->lock);

		if (!f)
			continue;

		bpf_spin_lock(&f->lock);
		skbn = fq_peek(f, &from_rb);
		if (skbn) {
			time_next_packet = max_t(u64, skbn->time_to_send, f->time_next_packet);

			if (now < time_next_packet) {
				bpf_spin_unlock(&f->lock);
				bpf_obj_drop(f);

				bpf_spin_lock(&q->lock);
				f = fq_flow_pop_front(q, new);
				if (f) {
					f->time_next_packet = time_next_packet;
					fq_flow_set_throttled(q, f);
					f = NULL;
				}
				bpf_spin_unlock(&q->lock);
				continue;
			}
			skbn = fq_dequeue_skbn(sch, f, skbn, from_rb);
			bpf_spin_unlock(&f->lock);
			break;
		} else {
			bpf_spin_unlock(&f->lock);
			bpf_obj_drop(f);

			bpf_spin_lock(&q->lock);
			f = fq_flow_pop_front(q, new);
			if (f) {
				/* force a pass through old_flows to prevent starvation */
				if (new && bpf_list_front(&q->old_flows)) {
					bpf_list_push_back(&q->old_flows, &f->old_flow_node);
					f = NULL;
				} else {
					fq_flow_set_detached(f, jiffies_now);
				}
			}
			bpf_spin_unlock(&q->lock);
			if (f) {
				bpf_obj_drop(f);
				f = NULL;
			}
		}
	}

	if (!f)
		return NULL;

	skb = skbn_drop(sch, skbn);;
	if (!skb) {
		bpf_obj_drop(f);
		return NULL;
	}

	if (--f->qlen == 0)
		q->inactive_flows++;

	plen = qdisc_pkt_len(skb);
	f->credit -= plen;

	if (!q->rate_enable)
		goto out;

	rate = q->flow_max_rate;

	/* If EDT time was provided for this skb, we need to
	 * update f->time_next_packet only if this qdisc enforces
	 * a flow max rate.
	 */
	if (!skb->tstamp) {
		struct sock *sk = skb->sk;

		if (sk)
			rate = min_t(unsigned long, sk->sk_pacing_rate, rate);

		if (rate <= q->low_rate_threshold) {
			f->credit = 0;
		} else {
			plen = max_t(u32, plen, q->quantum);
			if (f->credit > 0)
				goto out;
		}
	}
	if (rate != ~0UL) {
		u64 len = (u64)plen * NSEC_PER_SEC;

		if (likely(rate))
			len = len / rate;
		/* Since socket rate can change later,
		 * clamp the delay to 1 second.
		 * Really, providers of too big packets should be fixed !
		 */
		if (unlikely(len > NSEC_PER_SEC)) {
			len = NSEC_PER_SEC;
			q->stat_pkts_too_long++;
		}
		/* Account for schedule/timers drifts.
		 * f->time_next_packet was set when prior packet was sent,
		 * and current time (@now) can be too late by tens of us.
		 */
		if (f->time_next_packet)
			len -= min_t(u64, len/2, now - f->time_next_packet);
		f->time_next_packet = now + len;
	}

out:
	bpf_obj_drop(f);
	bpf_qdisc_bstats_update(sch, skb);
	return skb;
}

static int fq_init(struct Qdisc *sch, struct fq_sched_data *q)
{
	sch->limit		= 10000;
	q->flow_plimit		= 100;
	q->quantum		= 2 * psched_mtu(qdisc_dev(sch));
	q->initial_quantum	= 10 * psched_mtu(qdisc_dev(sch));
	q->flow_refill_delay	= msecs_to_jiffies(40);
	q->flow_max_rate	= ~0UL;
	q->time_next_delayed_flow = ~0ULL;
	q->rate_enable		= 1;
	q->fq_trees_log		= FQ_TREE_LOG;
	q->orphan_mask		= 1024 - 1;
	q->low_rate_threshold	= 550000 / 8;
	q->timer_slack = 10 * NSEC_PER_USEC; /* 10 usec of hrtimer slack */
	q->horizon = 10ULL * NSEC_PER_SEC; /* 10 seconds */
	q->horizon_drop = 1; /* by default, drop packets beyond horizon */
	return 0;
}

SEC("struct_ops")
int BPF_PROG(bpf_fq_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	unsigned long sch_long = (unsigned long)sch;
	struct fq_sched_data *q;
	int idx, err;

	bpf_spin_lock(&lock);
	for (idx = 0; idx < NR_QUEUES; idx++) {
		if (!used_idx[idx]) {
			used_idx[idx] = 1;
			break;
		}
	}
	bpf_spin_unlock(&lock);

	if (idx == NR_QUEUES)
		return -E2BIG;

	err = bpf_map_update_elem(&sch_to_idx_map, &sch_long, &idx, 0);
	if (err)
		return err;

	q = qdisc_priv(sch);
	if (!q)
		return -EINVAL;

	return fq_init(sch, q);
}

static void fq_flow_purge(struct fq_flow *f)
{
	struct bpf_list_node *l_n;
	struct bpf_rb_node *rb_n;
	struct skb_node *skbn;

	while (can_loop) {
		bpf_spin_lock(&f->lock);
		rb_n = bpf_rbtree_first(&f->skb_root);
		if (rb_n)
			rb_n = bpf_rbtree_remove(&f->skb_root, rb_n);
		l_n = bpf_list_pop_front(&f->skb_list);
		bpf_spin_unlock(&f->lock);
		skbn = NULL;
		if (rb_n) {
			skbn = rb_to_skbn(rb_n);
			bpf_obj_drop(skbn);
		}
		if (l_n) {
			skbn = list_to_skbn(l_n);
			bpf_obj_drop(skbn);
		}
		if (!skbn)
			break;
	}
}

SEC("struct_ops")
void BPF_PROG(bpf_fq_reset, struct Qdisc *sch)
{
	struct fq_flow *f, *f_internal = fq_internal(sch);
	struct fq_sched_data *q = qdisc_priv(sch);
	struct bpf_map *fq_flows_bucket;
	struct bpf_list_node *l_n0, *l_n1;
	struct bpf_rb_node *rb_n;
	struct fq_flow_root *root;
	int i, idx = sch_idx(sch);

	if (!q || !f_internal || idx == -1)
		return;

	fq_flows_bucket = bpf_map_lookup_elem(&fq_flow_roots, &idx);
	if (!fq_flows_bucket)
		return;

	fq_flow_purge(f_internal);

	while (can_loop) {
		bpf_spin_lock(&q->lock);
		l_n0 = bpf_list_pop_front(&q->new_flows);
		l_n1 = bpf_list_pop_front(&q->old_flows);
		rb_n = bpf_rbtree_first(&q->delayed);
		if (rb_n)
			rb_n = bpf_rbtree_remove(&q->delayed, rb_n);
		bpf_spin_unlock(&q->lock);

		f = NULL;
		if (l_n0) {
			f = container_of(l_n0, struct fq_flow, new_flow_node);
			bpf_obj_drop(f);
		}
		if (l_n1) {
			f = container_of(l_n1, struct fq_flow, old_flow_node);
			bpf_obj_drop(f);
		}
		if (rb_n) {
			f = container_of(rb_n, struct fq_flow, rate_node);
			bpf_obj_drop(f);
		}
		if (!f)
			break;
	}

	for (i = zero; i < FQ_FLOW_TREE_ENTRIES && can_loop; i++) {
		root = bpf_map_lookup_elem(fq_flows_bucket, &i);
		if (!root)
			break;
		bpf_spin_lock(&root->lock);
		rb_n = bpf_rbtree_first(&root->root);
		if (rb_n)
			rb_n = bpf_rbtree_remove(&root->root, rb_n);
		bpf_spin_unlock(&root->lock);

		if (rb_n) {
			f = container_of(rb_n, struct fq_flow, fq_node);
			/* this should be the final refcount of the flow and
			 * this drop will flush all the queued skb.
			 */
			bpf_obj_drop(f);
		}
	}
}

SEC("struct_ops")
void BPF_PROG(bpf_fq_destroy, struct Qdisc *sch)
{
	unsigned long sch_long = (unsigned long)sch;
	int idx = sch_idx(sch);

	if (idx == -1)
		return;

	____bpf_fq_reset(ctx, sch);

	bpf_map_delete_elem(&sch_to_idx_map, &sch_long);
	bpf_spin_lock(&lock);
	used_idx[idx] = 0;
	bpf_spin_unlock(&lock);
}

SEC(".struct_ops.link")
struct Qdisc_ops fq = {
	.enqueue	= (void *)bpf_fq_enqueue,
	.dequeue	= (void *)bpf_fq_dequeue,
	.init		= (void *)bpf_fq_init,
	.reset		= (void *)bpf_fq_reset,
	.destroy	= (void *)bpf_fq_destroy,
	.id		= "bpf_sch_fq",
};

char _license[] SEC("license") = "GPL";
