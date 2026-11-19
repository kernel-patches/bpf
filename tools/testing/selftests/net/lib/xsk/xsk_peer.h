/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XSK_PEER_H_
#define XSK_PEER_H_

#include <linux/types.h>

struct xsk_peer;

struct xsk_peer *xsk_peer_open(const char *host, const char *port,
			       bool listen_side);
void xsk_peer_close(struct xsk_peer *peer);

int xsk_peer_ready(struct xsk_peer *peer);
void xsk_peer_abort(struct xsk_peer *peer);
int xsk_peer_rx_progress(struct xsk_peer *peer, u32 pkts);
int xsk_peer_tx_sync(struct xsk_peer *peer);
bool xsk_peer_closed(struct xsk_peer *peer);

#endif /* XSK_PEER_H_ */
