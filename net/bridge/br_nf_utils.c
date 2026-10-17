// SPDX-License-Identifier: GPL-2.0-only
#include <linux/netdevice.h>
#include <linux/netfilter.h>

#include "br_private.h"

/* True if the bridge now sends to @addr through another port than @ifindex.
 * An entry that aged out is not a move: packets the flowtable forwards do
 * not pass the bridge, so they do not refresh it. Called under RCU.
 */
static bool nf_br_fdb_moved(struct net *net, int ifindex,
			    const unsigned char *addr, u16 vid)
{
	const struct net_bridge_fdb_entry *f;
	const struct net_bridge_port *p;
	struct net_device *dev;

	dev = dev_get_by_index_rcu(net, ifindex);
	p = dev ? br_port_get_check_rcu(dev) : NULL;
	if (!p)
		return true;

	f = br_fdb_find_rcu(p->br, addr, vid);

	return f && br_fdb_dst_port(f) != p;
}

static const struct nf_br_utils nf_br_utils = {
	.fdb_moved	= nf_br_fdb_moved,
};

void br_nf_utils_init(void)
{
	rcu_assign_pointer(nf_br_utils_hook, &nf_br_utils);
}

void br_nf_utils_fini(void)
{
	RCU_INIT_POINTER(nf_br_utils_hook, NULL);
}
