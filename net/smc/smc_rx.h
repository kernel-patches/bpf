/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 * Manage RMBE
 *
 * Copyright IBM Corp. 2016
 *
 * Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */

#ifndef SMC_RX_H
#define SMC_RX_H

#include <linux/socket.h>
#include <linux/types.h>

#include "smc.h"

void smc_rx_init(struct smc_sock *smc);

int smc_rx_recvmsg(struct smc_sock *smc, struct msghdr *msg,
		   struct pipe_inode_info *pipe, size_t len, int flags);
int smc_rx_wait(struct smc_sock *smc, long *timeo, size_t peeked,
		int (*fcrit)(struct smc_connection *conn, size_t baseline));
static inline int smc_rx_data_available(struct smc_connection *conn, size_t peeked)
{
	int avail = atomic_read(&conn->bytes_to_rcv);

	/* bytes_to_rcv follows the peer's producer cursor and can be past
	 * the RMB or negative. Report no more than fits in the RMB behind the
	 * bytes already spliced or peeked. Compare before subtracting: near
	 * INT_MIN, avail - peeked wraps. This also runs unlocked, possibly
	 * after rmb_desc was freed, hence rmb_len.
	 */
	avail = min(avail, conn->rmb_len - atomic_read(&conn->splice_pending));
	return avail > (int)peeked ? avail - (int)peeked : 0;
}

#endif /* SMC_RX_H */
