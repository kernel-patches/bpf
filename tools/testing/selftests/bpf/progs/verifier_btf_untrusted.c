// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

#undef container_of
#define container_of(ptr, type, member) \
	((type *)((void *)(ptr) - __builtin_offsetof(type, member)))
#define tcp_sk(sk) ((struct tcp_sock *)(sk))

long out;

/* Nobody vouches for an argument of a function that fmod_ret attaches to */
SEC("fmod_ret/security_sock_rcv_skb")
__failure
__msg("R1 type=untrusted_ptr_ expected=sock_common")
int BPF_PROG(arg_to_helper, struct sock *sk)
{
	out = bpf_get_socket_cookie(sk);
	return 0;
}

SEC("fmod_ret/security_socket_listen")
__failure
__msg("R1 type=untrusted_ptr_ expected=sock_common")
int BPF_PROG(member_of_arg_to_helper, struct socket *sock)
{
	out = bpf_get_socket_cookie(sock->sk);
	return 0;
}

/* A load that the type does not describe gives a number */
SEC("fmod_ret/security_sock_rcv_skb")
__success
int BPF_PROG(past_the_end, struct sock *sk)
{
	out = tcp_sk(sk)->snd_una == tcp_sk(sk)->snd_nxt;
	return 0;
}

SEC("syscall")
__success __retval(0)
int negative_offset(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf(), *self;

	/* next->prev points to task->tasks. prio stands in front of tasks */
	self = container_of(task->tasks.next->prev, struct task_struct, tasks);
	return self->prio != task->prio;
}

SEC("fmod_ret/security_sock_rcv_skb")
__success
int BPF_PROG(part_of_a_pointer, struct sock *sk)
{
	out = *(u32 *)&sk->sk_socket;
	return 0;
}

SEC("fmod_ret/security_sock_rcv_skb")
__success
int BPF_PROG(no_array, struct sock *sk, struct sk_buff *skb)
{
	struct net *net = sk->__sk_common.skc_net.net;

	out = !net->dev_index_head[skb->len & 255].first;
	return 0;
}

SEC("syscall")
__success __retval(0)
int bad_address(void *ctx)
{
	struct sock *sk = bpf_core_cast(NULL, struct sock);

	return *(int *)((void *)sk - 8) + tcp_sk(sk)->snd_una;
}

/* The number is no pointer */
SEC("fmod_ret/security_sock_rcv_skb")
__failure
__msg("invalid mem access 'scalar'")
int BPF_PROG(number_is_no_pointer, struct sock *sk)
{
	out = !tcp_sk(sk)->out_of_order_queue.rb_node->rb_left;
	return 0;
}

SEC("fmod_ret/security_sock_rcv_skb")
__failure
__msg("only read is supported")
int BPF_PROG(no_store, struct sock *sk)
{
	tcp_sk(sk)->snd_una = 0;
	return 0;
}

/* The type of a trusted pointer is no hint */
SEC("tp_btf/sys_enter")
__failure
__msg("access beyond struct task_struct")
int trusted_past_the_end(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return *(int *)(task + 1);
}

char _license[] SEC("license") = "GPL";
