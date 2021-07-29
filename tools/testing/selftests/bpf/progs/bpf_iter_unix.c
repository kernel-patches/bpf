// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */
#include "bpf_iter.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

#define __SO_ACCEPTCON		(1 << 16)
#define UNIX_HASH_SIZE		256
#define UNIX_ABSTRACT(unix_sk)	(unix_sk->addr->hash < UNIX_HASH_SIZE)

static long sock_i_ino(const struct sock *sk)
{
	const struct socket *sk_socket = sk->sk_socket;
	const struct inode *inode;
	unsigned long ino;

	if (!sk_socket)
		return 0;

	inode = &container_of(sk_socket, struct socket_alloc, socket)->vfs_inode;
	bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
	return ino;
}

SEC("iter/unix")
int dump_unix(struct bpf_iter__unix *ctx)
{
	struct unix_sock *unix_sk = ctx->unix_sk;
	struct sock *sk = (struct sock *)unix_sk;
	struct seq_file *seq;
	__u32 seq_num;

	if (!unix_sk)
		return 0;

	seq = ctx->meta->seq;
	seq_num = ctx->meta->seq_num;
	if (seq_num == 0)
		BPF_SEQ_PRINTF(seq, "Num       RefCount Protocol Flags    "
			       "Type St Inode Path\n");

	BPF_SEQ_PRINTF(seq, "%pK: %08X %08X %08X %04X %02X %5lu",
		       unix_sk,
		       sk->sk_refcnt.refs.counter,
		       0,
		       sk->sk_state == TCP_LISTEN ? __SO_ACCEPTCON : 0,
		       sk->sk_type,
		       sk->sk_socket ?
		       (sk->sk_state == TCP_ESTABLISHED ?
			SS_CONNECTED : SS_UNCONNECTED) :
		       (sk->sk_state == TCP_ESTABLISHED ?
			SS_CONNECTING : SS_DISCONNECTING),
		       sock_i_ino(sk));

	if (unix_sk->addr) {
		if (UNIX_ABSTRACT(unix_sk))
			/* Abstract UNIX domain socket can contain '\0' in
			 * the path, and it should be escaped.  However, it
			 * requires loops and the BPF verifier rejects it.
			 * So here, print only the escaped first byte to
			 * indicate it is an abstract UNIX domain socket.
			 * (See: unix_seq_show() and commit e7947ea770d0d)
			 */
			BPF_SEQ_PRINTF(seq, " @");
		else
			BPF_SEQ_PRINTF(seq, " %s", unix_sk->addr->name->sun_path);
	}

	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}
