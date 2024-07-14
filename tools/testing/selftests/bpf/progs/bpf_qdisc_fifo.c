#include <vmlinux.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

struct skb_node {
	struct sk_buff __kptr *skb;
	struct bpf_list_node node;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock q_fifo_lock;
private(A) struct bpf_list_head q_fifo __contains(skb_node, node);

unsigned int q_limit = 1000;
unsigned int q_qlen = 0;

SEC("struct_ops/bpf_fifo_enqueue")
int BPF_PROG(bpf_fifo_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct skb_node *skbn;

	if (q_qlen == q_limit)
		goto drop;

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn)
		goto drop;

	q_qlen++;
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb) //unexpected
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&q_fifo_lock);
	bpf_list_push_back(&q_fifo, &skbn->node);
	bpf_spin_unlock(&q_fifo_lock);

	return NET_XMIT_SUCCESS;
drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/bpf_fifo_dequeue")
struct sk_buff *BPF_PROG(bpf_fifo_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct sk_buff *skb = NULL;
	struct skb_node *skbn;

	bpf_spin_lock(&q_fifo_lock);
	node = bpf_list_pop_front(&q_fifo);
	bpf_spin_unlock(&q_fifo_lock);
	if (!node)
		return NULL;

	skbn = container_of(node, struct skb_node, node);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	bpf_obj_drop(skbn);
	q_qlen--;

	return skb;
}

SEC("struct_ops/bpf_fifo_reset")
void BPF_PROG(bpf_fifo_reset, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct skb_node *skbn;
	int i;

	bpf_for(i, 0, q_qlen) {
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&q_fifo_lock);
		node = bpf_list_pop_front(&q_fifo);
		bpf_spin_unlock(&q_fifo_lock);

		if (!node)
			break;

		skbn = container_of(node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		if (skb)
			bpf_skb_release(skb);
		bpf_obj_drop(skbn);
	}
	q_qlen = 0;
}

SEC(".struct_ops")
struct Qdisc_ops fifo = {
	.enqueue   = (void *)bpf_fifo_enqueue,
	.dequeue   = (void *)bpf_fifo_dequeue,
	.reset     = (void *)bpf_fifo_reset,
	.id        = "bpf_fifo",
};

