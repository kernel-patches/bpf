/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM skb

#if !defined(_TRACE_SKB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SKB_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/tracepoint.h>

#undef FN
#define FN(reason)	TRACE_DEFINE_ENUM(SKB_DROP_REASON_##reason);
DEFINE_DROP_REASON(FN, FN)

#undef FN
#undef FNe
#define FN(reason)	{ SKB_DROP_REASON_##reason, #reason },
#define FNe(reason)	{ SKB_DROP_REASON_##reason, #reason }

/*
 * Tracepoint for free an sk_buff:
 */
TRACE_EVENT(kfree_skb,

	TP_PROTO(struct sk_buff *skb, void *location,
		 enum skb_drop_reason reason, const struct sock *rx_sk),

	TP_ARGS(skb, location, reason, rx_sk),

	TP_STRUCT__entry(
		__field(void *,		skbaddr)
		__field(void *,		location)
		__field(const void *,	rx_sk)
		__field(unsigned short,	protocol)
		__field(enum skb_drop_reason,	reason)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->location = location;
		__entry->rx_sk = rx_sk;
		__entry->protocol = ntohs(skb->protocol);
		__entry->reason = reason;
	),

	TP_printk("skbaddr=%p rx_sk=%p protocol=%u location=%pS reason: %s",
		  __entry->skbaddr, __entry->rx_sk, __entry->protocol,
		  __entry->location,
		  __print_symbolic(__entry->reason,
				   DEFINE_DROP_REASON(FN, FNe)))
);

#undef FN
#undef FNe

TRACE_EVENT(consume_skb,

	TP_PROTO(struct sk_buff *skb, void *location),

	TP_ARGS(skb, location),

	TP_STRUCT__entry(
		__field(	void *,	skbaddr)
		__field(	void *,	location)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->location = location;
	),

	TP_printk("skbaddr=%p location=%pS", __entry->skbaddr, __entry->location)
);

TRACE_EVENT(skb_copy_datagram_iovec,

	TP_PROTO(const struct sk_buff *skb, int len),

	TP_ARGS(skb, len),

	TP_STRUCT__entry(
		__field(	const void *,		skbaddr		)
		__field(	int,			len		)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->len = len;
	),

	TP_printk("skbaddr=%p len=%d", __entry->skbaddr, __entry->len)
);

/*
 * Gated variant of the kfree/consume_skb tracepoints, which fires only for skbs
 * tagged with bpf_trace_skb().
 */

#undef FN
#undef FNe
#define FN(reason)	{ SKB_DROP_REASON_##reason, #reason },
#define FNe(reason)	{ SKB_DROP_REASON_##reason, #reason }

TRACE_EVENT_CONDITION(skb_free,

	TP_PROTO(struct sk_buff *skb, enum skb_drop_reason reason,
		 void *location),

	TP_ARGS(skb, reason, location),

	TP_CONDITION(skb->traced),

	TP_STRUCT__entry(
		__field(	void *,		skbaddr)
		__field(	enum skb_drop_reason,	reason)
		__field(	void *,		location)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->reason = reason;
		__entry->location = location;
	),

	TP_printk("skbaddr=%p reason=%s location=%pS",
		  __entry->skbaddr,
		  __print_symbolic(__entry->reason,
				   DEFINE_DROP_REASON(FN, FNe)),
		  __entry->location)
);

#undef FN
#undef FNe

TRACE_EVENT_CONDITION(skb_copy,

	TP_PROTO(struct sk_buff *dst, const struct sk_buff *src),

	TP_ARGS(dst, src),

	TP_CONDITION(src->traced && !dst->traced),

	TP_STRUCT__entry(
		__field(	void *,		dst)
		__field(	const void *,	src)
	),

	TP_fast_assign(
		__entry->dst = dst;
		__entry->src = src;
	),

	TP_printk("dst=%p src=%p", __entry->dst, __entry->src)
);

#define trace_consume_skb(skb, location)			 \
	do {							 \
		struct sk_buff *__skb = (skb);			 \
		void *__location = (location);			 \
								 \
		trace_consume_skb(__skb, __location);		 \
		trace_skb_free(__skb, SKB_CONSUMED, __location); \
	} while (0)

#define trace_kfree_skb(skb, location, reason, rx_sk)		     \
	do {							     \
		struct sk_buff *__skb = (skb);			     \
		void *__location = (location);			     \
		enum skb_drop_reason __reason = (reason);	     \
								     \
		trace_kfree_skb(__skb, __location, __reason, rx_sk); \
		trace_skb_free(__skb, __reason, __location);	     \
	} while (0)

#endif /* _TRACE_SKB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
