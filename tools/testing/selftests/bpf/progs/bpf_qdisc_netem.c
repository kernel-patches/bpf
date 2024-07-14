#include <vmlinux.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

int q_loss_model = CLG_GILB_ELL;
unsigned int q_limit = 1000;
signed long q_latency = 0;
signed long q_jitter = 0;
unsigned int q_loss = 1;
unsigned int q_qlen = 0;

struct crndstate q_loss_cor = {.last = 0, .rho = 0,};
struct crndstate q_delay_cor = {.last = 0, .rho = 0,};

struct skb_node {
	u64 tstamp;
	struct sk_buff __kptr *skb;
	struct bpf_rb_node node;
};

struct clg_state {
	u64 state;
	u32 a1;
	u32 a2;
	u32 a3;
	u32 a4;
	u32 a5;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct clg_state);
	__uint(max_entries, 1);
} g_clg_state SEC(".maps");

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock t_root_lock;
private(A) struct bpf_rb_root t_root __contains(skb_node, node);

static bool skb_tstamp_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct skb_node *skbn_a;
	struct skb_node *skbn_b;

	skbn_a = container_of(a, struct skb_node, node);
	skbn_b = container_of(b, struct skb_node, node);

	return skbn_a->tstamp < skbn_b->tstamp;
}

static u32 get_crandom(struct crndstate *state)
{
	u64 value, rho;
	unsigned long answer;

	if (!state || state->rho == 0)	/* no correlation */
		return bpf_get_prandom_u32();

	value = bpf_get_prandom_u32();
	rho = (u64)state->rho + 1;
	answer = (value * ((1ull<<32) - rho) + state->last * rho) >> 32;
	state->last = answer;
	return answer;
}

static s64 tabledist(s64 mu, s32 sigma, struct crndstate *state)
{
	u32 rnd;

	if (sigma == 0)
		return mu;

	rnd = get_crandom(state);

	/* default uniform distribution */
	return ((rnd % (2 * (u32)sigma)) + mu) - sigma;
}

static bool loss_gilb_ell(void)
{
	struct clg_state *clg;
	u32 r1, r2, key = 0;
	bool ret = false;

	clg = bpf_map_lookup_elem(&g_clg_state, &key);
	if (!clg)
		return false;

	r1 = bpf_get_prandom_u32();
	r2 = bpf_get_prandom_u32();

	switch (clg->state) {
	case GOOD_STATE:
		if (r1 < clg->a1)
			__sync_val_compare_and_swap(&clg->state,
						    GOOD_STATE, BAD_STATE);
		if (r2 < clg->a4)
			ret = true;
		break;
	case BAD_STATE:
		if (r1 < clg->a2)
			__sync_val_compare_and_swap(&clg->state,
						    BAD_STATE, GOOD_STATE);
		if (r2 > clg->a3)
			ret = true;
	}

	return ret;
}

static bool loss_event(void)
{
	switch (q_loss_model) {
	case CLG_RANDOM:
		return q_loss && q_loss >= get_crandom(&q_loss_cor);
	case CLG_GILB_ELL:
		return loss_gilb_ell();
	}

	return false;
}

SEC("struct_ops/bpf_netem_enqueue")
int BPF_PROG(bpf_netem_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct skb_node *skbn;
	int count = 1;
	s64 delay = 0;
	u64 now;

	if (loss_event())
		--count;

	if (count == 0) {
		bpf_qdisc_skb_drop(skb, to_free);
		return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	}

	q_qlen++;
	if (q_qlen > q_limit) {
		bpf_qdisc_skb_drop(skb, to_free);
		return NET_XMIT_DROP;
	}

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn) {
		bpf_qdisc_skb_drop(skb, to_free);
		return NET_XMIT_DROP;
	}

	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	delay = tabledist(q_latency, q_jitter, &q_delay_cor);
	now = bpf_ktime_get_ns();
	skbn->tstamp = now + delay;

	bpf_spin_lock(&t_root_lock);
	bpf_rbtree_add(&t_root, &skbn->node, skb_tstamp_less);
	bpf_spin_unlock(&t_root_lock);

	return NET_XMIT_SUCCESS;
}

SEC("struct_ops/bpf_netem_dequeue")
struct sk_buff *BPF_PROG(bpf_netem_dequeue, struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
	struct bpf_rb_node *node;
	struct skb_node *skbn;
	u64 now, tstamp;

	now = bpf_ktime_get_ns();

	bpf_spin_lock(&t_root_lock);
	node = bpf_rbtree_first(&t_root);
	if (!node) {
		bpf_spin_unlock(&t_root_lock);
		return NULL;
	}

	skbn = container_of(node, struct skb_node, node);
	tstamp = skbn->tstamp;
	if (tstamp <= now) {
		node = bpf_rbtree_remove(&t_root, node);
		bpf_spin_unlock(&t_root_lock);

		if (!node)
			return NULL;

		skbn = container_of(node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		bpf_obj_drop(skbn);

		q_qlen--;
		return skb;
	}

	bpf_spin_unlock(&t_root_lock);
	bpf_qdisc_watchdog_schedule(sch, tstamp, 0);
	return NULL;
}

SEC("struct_ops/bpf_netem_init")
int BPF_PROG(bpf_netem_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	return 0;
}

SEC("struct_ops/bpf_netem_reset")
void BPF_PROG(bpf_netem_reset, struct Qdisc *sch)
{
	struct bpf_rb_node *node;
	struct skb_node *skbn;
	int i;

	bpf_for(i, 0, q_limit) {
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&t_root_lock);
		node = bpf_rbtree_first(&t_root);
		if (!node) {
			bpf_spin_unlock(&t_root_lock);
			break;
		}

		skbn = container_of(node, struct skb_node, node);
		node = bpf_rbtree_remove(&t_root, node);
		bpf_spin_unlock(&t_root_lock);

		if (!node)
			continue;

		skbn = container_of(node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		if (skb)
			bpf_skb_release(skb);
		bpf_obj_drop(skbn);
	}
	q_qlen = 0;
}

SEC(".struct_ops")
struct Qdisc_ops netem = {
	.enqueue   = (void *)bpf_netem_enqueue,
	.dequeue   = (void *)bpf_netem_dequeue,
	.init      = (void *)bpf_netem_init,
	.reset     = (void *)bpf_netem_reset,
	.id        = "bpf_netem",
};

