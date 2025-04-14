/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sockmap

#if !defined(_TRACE_SOCKMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SOCKMAP_H

#include <linux/tracepoint.h>
#include <linux/bpf.h>
#include <linux/skmsg.h>

#ifndef __TRACE_SOCKMAP_HELPER_ONCE_ONLY
#define __TRACE_SOCKMAP_HELPER_ONCE_ONLY

enum sockmap_direct_type {
	SOCKMAP_REDIR_NONE	= 0,
	SOCKMAP_REDIR_INGRESS,
	SOCKMAP_REDIR_EGRESS,
};

enum sockmap_data_type {
	SOCKMAP_MSG		= 0,
	SOCKMAP_SKB,
};

#endif /* end __TRACE_SOCKMAP_HELPER_ONCE_ONLY */

TRACE_DEFINE_ENUM(SOCKMAP_MSG);
TRACE_DEFINE_ENUM(SOCKMAP_SKB);
TRACE_DEFINE_ENUM(SOCKMAP_REDIR_NONE);
TRACE_DEFINE_ENUM(SOCKMAP_REDIR_INGRESS);
TRACE_DEFINE_ENUM(SOCKMAP_REDIR_EGRESS);

TRACE_DEFINE_ENUM(__SK_DROP);
TRACE_DEFINE_ENUM(__SK_PASS);
TRACE_DEFINE_ENUM(__SK_REDIRECT);
TRACE_DEFINE_ENUM(__SK_NONE);

#define show_redirect_type(x)					\
	__print_symbolic(x,					\
		{ SOCKMAP_REDIR_NONE,		"none" },	\
		{ SOCKMAP_REDIR_INGRESS,	"ingress" },	\
		{ SOCKMAP_REDIR_EGRESS,		"egress" })

#define show_act(x)						\
	__print_symbolic(x,					\
		{ __SK_DROP,			"DROP" },	\
		{ __SK_PASS,			"PASS" },	\
		{ __SK_REDIRECT,		"REDIRECT" },	\
		{ __SK_NONE,			"NONE" })

#define show_data_type(x)					\
	__print_symbolic(x,					\
		{ SOCKMAP_MSG,			"msg" },	\
		{ SOCKMAP_SKB,			"skb" })

#define trace_sockmap_skmsg_redirect(sk, prog, msg, act)	\
	trace_sockmap_redirect((sk), SOCKMAP_MSG, (prog),	\
			       (msg)->sg.size, (act),		\
			       sk_msg_to_ingress(msg))

#define trace_sockmap_skb_redirect(sk, prog, skb, act)		\
	trace_sockmap_redirect((sk), SOCKMAP_SKB, (prog),	\
			       (skb)->len, (act),		\
			       skb_bpf_ingress(skb))

#define trace_sockmap_skb_strp_parse(sk, prog, skb, ret)	\
	trace_sockmap_strparser((sk), (prog), (skb)->len, (ret))

TRACE_EVENT(sockmap_redirect,

	TP_PROTO(const struct sock *sk, enum sockmap_data_type type,
		 const struct bpf_prog *prog, int len, int act,
		 bool ingress),

	TP_ARGS(sk, type, prog, len, act, ingress),

	TP_STRUCT__entry(
		__field(const void *, sk)
		__field(unsigned long, ino)
		__field(unsigned int, netns_ino)
		__field(__u16, family)
		__field(__u16, protocol)
		__field(int, prog_id)
		__field(int, len)
		__field(int, act)
		__field(enum sockmap_data_type, type)
		__field(enum sockmap_direct_type, redir)
	),

	TP_fast_assign(
		/* 'redir' is undefined if action is not REDIRECT */
		enum sockmap_direct_type redir = SOCKMAP_REDIR_NONE;

		if (act == __SK_REDIRECT) {
			if (ingress)
				redir = SOCKMAP_REDIR_INGRESS;
			else
				redir = SOCKMAP_REDIR_EGRESS;
		}
		__entry->sk		= sk;
		__entry->ino		= sock_i_ino((struct sock *)sk);
		__entry->netns_ino	= sock_net(sk)->ns.inum;
		__entry->type		= type;
		__entry->family		= sk->sk_family;
		__entry->protocol	= sk->sk_protocol;
		__entry->prog_id	= prog->aux->id;
		__entry->len		= len;
		__entry->act		= act;
		__entry->redir		= redir;
	),

	TP_printk("sk=%p, netns=%u, inode=%lu, family=%u, protocol=%u,"
		  " prog_id=%d, len=%d, type=%s, action=%s, redirect_type=%s",
		  __entry->sk, __entry->netns_ino, __entry->ino,
		  __entry->family, __entry->protocol, __entry->prog_id,
		  __entry->len, show_data_type(__entry->type),
		  show_act(__entry->act), show_redirect_type(__entry->redir))
);

TRACE_EVENT(sockmap_strparser,

	TP_PROTO(const struct sock *sk, const struct bpf_prog *prog,
		 int in_len, int full_len),

	TP_ARGS(sk, prog, in_len, full_len),

	TP_STRUCT__entry(
		__field(const void *, sk)
		__field(unsigned long, ino)
		__field(unsigned int, netns_ino)
		__field(__u16, family)
		__field(__u16, protocol)
		__field(int, prog_id)
		__field(int, in_len)
		__field(int, full_len)
	),

	TP_fast_assign(
		__entry->sk		= sk;
		__entry->ino		= sock_i_ino((struct sock *)sk);
		__entry->netns_ino	= sock_net(sk)->ns.inum;
		__entry->family		= sk->sk_family;
		__entry->protocol	= sk->sk_protocol;
		__entry->prog_id	= prog->aux->id;
		__entry->in_len		= in_len;
		__entry->full_len	= full_len;
	),

	TP_printk("sk=%p, netns=%u, inode=%lu, family=%u, protocol=%u,"
		  " prog_id=%d, in_len=%d, full_len=%d",
		  __entry->sk, __entry->netns_ino, __entry->ino,
		  __entry->family, __entry->protocol, __entry->prog_id,
		  __entry->in_len, __entry->full_len)
);
#endif /* _TRACE_SOCKMAP_H */

#include <trace/define_trace.h>
