/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _NET_QRTR_H
#define _NET_QRTR_H

#include <linux/types.h>

/* The offset is chosen carefully to not collide with the node ids allocated by
 * the remote nodes. All the remote nodes use node ids in range 0 to 0xffff.
 */
#define QRTR_NODE_HOST_BASE 0x10000u

/* Compute host node id from a per-device index. The index must be unique
 * among the host assigned endpoints and smaller than QRTR_NODE_HOST_BASE.
 */
static inline unsigned int qrtr_host_node_id(unsigned int index)
{
	return QRTR_NODE_HOST_BASE + index;
}

#endif /* _NET_QRTR_H */
