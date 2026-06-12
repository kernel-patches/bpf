// SPDX-License-Identifier: GPL-2.0
/* Sock_ops BPF program that pairs locally-connected TCP sockets via the
 * bpf_sock_splice_pair kfunc. Each side of an established loopback
 * connection inserts itself into a sockhash keyed by its 4-tuple and
 * looks up the peer using the swapped tuple. Whichever side finds the
 * peer attempts to splice; the race loser sees -EEXIST.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif

struct flow_key {
	__u32	saddr;
	__u32	daddr;
	__u16	sport;
	__u16	dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 16);
	__type(key, struct flow_key);
	__type(value, __u64);
} rendezvous SEC(".maps");

int bpf_sock_splice_pair(struct sock *peer, struct bpf_sock_ops_kern *skops) __ksym;
void *bpf_cast_to_kern_ctx(void *obj) __ksym;

__u32 pair_ok;
__u32 pair_other_err;

__u32 busy_poll_us;

/* IPv4 only: the verifier doesn't accept memcpy from sock_ops ctx
 * because it lowers to "ctx + reg" pointer arithmetic. IPv6 support
 * would need explicit field-by-field reads of local_ip6[i] /
 * remote_ip6[i] at constant indices.
 */
static __always_inline void mk_key(struct bpf_sock_ops *s,
				   struct flow_key *k, int swap)
{
	/* skops->local_port is already in host byte order. skops->remote_port
	 * is laid out as the network-order 16-bit port in the upper half of
	 * a u32 (see sock_ops_convert_ctx_access); bpf_ntohl produces the
	 * host-order port directly - no further shift.
	 */
	__u16 lport = (__u16)s->local_port;
	__u16 rport = bpf_ntohl(s->remote_port);

	if (!swap) {
		k->saddr = s->local_ip4;
		k->daddr = s->remote_ip4;
		k->sport = lport;
		k->dport = rport;
	} else {
		k->saddr = s->remote_ip4;
		k->daddr = s->local_ip4;
		k->sport = rport;
		k->dport = lport;
	}
}

SEC("sockops")
int sockops_splice(struct bpf_sock_ops *skops)
{
	struct flow_key self_key, peer_key;
	struct bpf_sock *peer;
	int ret;

	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 0;
	if (skops->family != 2 /* AF_INET */)
		return 0;

	/* Enable busy-poll on this socket. Both endpoints run this callback,
	 * so each sets its own socket; this must happen here, before the
	 * peer-not-found early return below, because pairing is asymmetric -
	 * only the second side to establish finds a peer and calls
	 * bpf_sock_splice_pair. Setting it only on the pairing side would
	 * leave the other side without busy-poll. bpf_setsockopt acts on
	 * skops->sk only - there is no variant to set the peer - but the peer
	 * sets itself when its own ESTABLISHED callback fires.
	 */
	if (busy_poll_us) {
		int us = busy_poll_us;

		bpf_setsockopt(skops, SOL_SOCKET, SO_BUSY_POLL, &us, sizeof(us));
	}

	mk_key(skops, &self_key, 0);
	mk_key(skops, &peer_key, 1);

	/* BPF_ANY: a reused 4-tuple after close (e.g. fast reconnect) must
	 * overwrite the stale entry rather than silently fail.
	 */
	bpf_sock_hash_update(skops, &rendezvous, &self_key, BPF_ANY);

	peer = bpf_map_lookup_elem(&rendezvous, &peer_key);
	if (!peer)
		return 0;

	/* The sockhash bpf_map_lookup_elem above is an acquire, so @peer
	 * carries a reference. A sock_ops program cannot call
	 * bpf_sk_release, so the reference is handed to bpf_sock_splice_pair
	 * which is KF_RELEASE and consumes it - no explicit release here,
	 * and none is possible from this program type.
	 */
	ret = bpf_sock_splice_pair((struct sock *)peer,
				   bpf_cast_to_kern_ctx(skops));
	if (ret == 0)
		__sync_fetch_and_add(&pair_ok, 1);
	else if (ret != -17 /* -EEXIST: race loser, expected */)
		__sync_fetch_and_add(&pair_other_err, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
