// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "socket.h"

#define QUIC_HLEN		1

/* Make these fixed for easy coding. */
#define QUIC_PACKET_NUMBER_LEN	QUIC_PN_MAX_LEN
#define QUIC_PACKET_LENGTH_LEN	4

static struct sk_buff *quic_packet_handshake_create(struct sock *sk, gfp_t gfp)
{
	return NULL;
}

static int quic_packet_number_check(struct sock *sk, gfp_t gfp)
{
	return 0;
}

static struct sk_buff *quic_packet_app_create(struct sock *sk, gfp_t gfp)
{
	return NULL;
}

/* Update the MSS and inform congestion control. */
void quic_packet_mss_update(struct sock *sk, u32 mss)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_cong *cong = quic_cong(sk);

	packet->mss[QUIC_PACKET_MSS_NORMAL] = (u16)mss;
	quic_cong_set_mss(cong, packet->mss[QUIC_PACKET_MSS_NORMAL]);
}

/* Perform routing for the QUIC packet on the specified path, update header
 * length and MSS accordingly, reset path and start PMTU timer.
 */
int quic_packet_route(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa, *da;
	u32 pmtu;
	int err;

	da = quic_path_daddr(paths, packet->path);
	sa = quic_path_saddr(paths, packet->path);
	err = quic_flow_route(sk, da, sa, &paths->fl);
	if (err)
		return err < 0 ? err : 0;

	packet->hlen = quic_encap_len(da);
	pmtu = clamp(dst_mtu(__sk_dst_get(sk)),
		     QUIC_PATH_MIN_PMTU, QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - packet->hlen);

	quic_path_pl_reset(paths);
	quic_timer_reset(sk, QUIC_TIMER_PMTU, paths->plpmtud_interval);
	return 0;
}

/* Return QUIC packet header overhead for the given level and path. Includes
 * packet number, connection IDs, and for long headers also version, length,
 * and Initial token (if present). Excludes payload.
 */
u16 quic_packet_overhead(struct sock *sk, u8 level, u8 path)
{
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_conn_id_set *dest = quic_dest(sk);
	u16 len = QUIC_HLEN;

	len += QUIC_PACKET_NUMBER_LEN; /* Packet number length. */
	len += quic_conn_id_choose(dest, path)->len; /* DCID length. */
	if (level == QUIC_CRYPTO_APP)
		return len;

	len += 1; /* Length byte for DCID. */
	/* Length byte + SCID length. */
	len += 1 + quic_conn_id_active(source)->len;
	/* Include token for Initial packets. */
	if (level == QUIC_CRYPTO_INITIAL)
		len += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
	len += QUIC_VERSION_LEN; /* Version length. */
	len += QUIC_PACKET_LENGTH_LEN; /* Packet length field. */

	return len;
}

/* Configure the QUIC packet header and routing based on encryption level and
 * path.
 */
int quic_packet_config(struct sock *sk, u8 level, u8 path)
{
	struct quic_packet *packet = quic_packet(sk);

	/* If packet already has data, no need to reconfigure. */
	if (!quic_packet_empty(packet))
		return 0;

	packet->path_validating = 0;
	packet->ipfragok = 0;
	packet->padding = 0;
	packet->frames = 0;

	packet->level = level;
	packet->overhead = quic_packet_overhead(sk, level, path);
	packet->len = packet->overhead + quic_packet_taglen(packet);

	/* Allow fragmentation for handshake packets if PLPMTUD is enabled, as
	 * MTU discovery does not rely on ICMP Packet Too Big once PLPMTUD is
	 * enabled.
	 */
	packet->ipfragok = level && !!quic_paths(sk)->plpmtud_interval;

	if (packet->path != path) {
		/* Path changed; update and reset routing cache */
		packet->path = path;
		__sk_dst_reset(sk);
	}

	/* Perform routing and MSS update for the configured packet. */
	return quic_packet_route(sk);
}

static void quic_packet_encrypt_done(struct sk_buff *skb, int err)
{
	/* Free it for now, future patches will implement the actual deferred
	 * transmission logic.
	 */
	kfree_skb(skb);
}

/* Coalescing Packets. */
static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_skb_cb *head_cb, *cb = QUIC_SKB_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) /* First packet to bundle: initialize the head. */
		goto init;

	/* If bundling would exceed MSS, flush the current bundle. */
	if (packet->head->len + skb->len >
	    packet->mss[QUIC_PACKET_MSS_NORMAL]) {
		quic_packet_flush(sk);
		goto init;
	}
	/* Bundle it and update metadata for the aggregate skb. */
	skb_orphan(skb);
	p = packet->head;
	head_cb = QUIC_SKB_CB(p);
	if (head_cb->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		head_cb->last->next = skb;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;
	head_cb->last = skb;
	head_cb->ecn |= cb->ecn;  /* Merge ECN flags. */

out:
	/* rfc9000#section-12.2: Packets with a short header (Section 17.3) do
	 * not contain a Length field and so cannot be followed by other
	 * packets in the same UDP datagram.
	 *
	 * so Return 1 to flush if it is a Short header packet.
	 */
	return !cb->level;
init:
	packet->head = skb;
	cb->last = skb;
	goto out;
}

/* Transmit a QUIC packet, possibly encrypting and bundling it. */
static int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct net *net = sock_net(sk);
	int err;

	/* Associate skb with sk to ensure sk is valid during async encryption
	 * completion.
	 */
	WARN_ON_ONCE(!skb_set_owner_sk_safe(skb, sk));

	/* Skip encryption if taglen == 0 (e.g., disable_1rtt_encryption). */
	if (!packet->taglen[quic_hdr(skb)->form])
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb, gfp);
	if (err) {
		if (err != -EINPROGRESS) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCDROP);
			kfree_skb(skb);
			return err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCBACKLOGS);
		return err;
	}
	if (!cb->resume) /* Encryption completes synchronously. */
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCFASTPATHS);

xmit:
	if (quic_packet_bundle(sk, skb))
		quic_packet_flush(sk);
	return 0;
}

/* Create and transmit a new QUIC packet. */
int quic_packet_create_and_xmit(struct sock *sk, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk, gfp);
	if (err)
		goto err;

	if (packet->level)
		skb = quic_packet_handshake_create(sk, gfp);
	else
		skb = quic_packet_app_create(sk, gfp);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	err = quic_packet_xmit(sk, skb, gfp);
	if (err && err != -EINPROGRESS)
		goto err;

	return 0;
err:
	pr_debug("%s: err: %d\n", __func__, err);
	return err;
}

/* Flush any coalesced/bundled QUIC packets. */
void quic_packet_flush(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);

	if (packet->head) {
		quic_lower_xmit(sk, packet->head,
				quic_path_daddr(paths, packet->path),
				&paths->fl);
		packet->head = NULL;
	}
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	INIT_LIST_HEAD(&packet->frame_list);
	packet->taglen[QUIC_PACKET_FORM_SHORT] = QUIC_TAG_LEN;
	packet->taglen[QUIC_PACKET_FORM_LONG] = QUIC_TAG_LEN;
	packet->mss[QUIC_PACKET_MSS_NORMAL] = QUIC_MIN_UDP_PAYLOAD;
	packet->mss[QUIC_PACKET_MSS_DGRAM] = QUIC_MIN_UDP_PAYLOAD;

	packet->version = QUIC_VERSION_V1;
}
