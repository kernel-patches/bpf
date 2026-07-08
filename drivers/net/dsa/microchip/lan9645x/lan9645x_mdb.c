// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include "lan9645x_main.h"

/* HW ignores dest_idx for IPv4/IPv6 types, so we use this dummy index */
#define IP_ENTRY_PGID		0
#define PGID_INDEX(pgid)	((pgid) ? (pgid)->index : IP_ENTRY_PGID)

struct lan9645x_pgid_entry {
	struct list_head list;
	int index;
	refcount_t refcount;
	u16 ports;
};

struct lan9645x_mdb_entry {
	struct list_head list;
	unsigned char mac[ETH_ALEN];
	u16 vid;
	u16 ports;
	struct lan9645x_pgid_entry *pgid;
};

void lan9645x_mdb_init(struct lan9645x *lan9645x)
{
	INIT_LIST_HEAD(&lan9645x->mdb_entries);
	INIT_LIST_HEAD(&lan9645x->pgid_entries);
	mutex_init(&lan9645x->mdb_lock);

	/* Use CPU queues to communicate frame classification to the CPU */
	lan_rmw(ANA_CPUQ_CFG_CPUQ_IGMP_SET(LAN9645X_CPUQ_TRAP) |
		ANA_CPUQ_CFG_CPUQ_MLD_SET(LAN9645X_CPUQ_TRAP) |
		ANA_CPUQ_CFG_CPUQ_IPMC_CTRL_SET(LAN9645X_CPUQ_COPY),
		ANA_CPUQ_CFG_CPUQ_IGMP |
		ANA_CPUQ_CFG_CPUQ_MLD |
		ANA_CPUQ_CFG_CPUQ_IPMC_CTRL,
		lan9645x, ANA_CPUQ_CFG);
}

static enum macaccess_entry_type lan9645x_mdb_classify(const unsigned char *mac)
{
	if (ether_addr_is_ipv4_mcast(mac))
		return ENTRYTYPE_MACV4;
	if (ether_addr_is_ipv6_mcast(mac))
		return ENTRYTYPE_MACV6;
	return ENTRYTYPE_LOCKED;
}

static struct lan9645x_mdb_entry *
lan9645x_mdb_entry_lookup(struct lan9645x *lan9645x, const unsigned char *mac,
			  u16 vid)
{
	struct lan9645x_mdb_entry *mdb;

	list_for_each_entry(mdb, &lan9645x->mdb_entries, list) {
		if (ether_addr_equal(mdb->mac, mac) && mdb->vid == vid)
			return mdb;
	}

	return NULL;
}

static struct lan9645x_mdb_entry *
lan9645x_mdb_entry_alloc(struct lan9645x *lan9645x,
			 const unsigned char addr[ETH_ALEN], u16 vid)
{
	struct lan9645x_mdb_entry *mdb_entry;

	mdb_entry = kzalloc_obj(*mdb_entry);
	if (!mdb_entry)
		return ERR_PTR(-ENOMEM);

	ether_addr_copy(mdb_entry->mac, addr);
	mdb_entry->vid = vid;

	list_add_tail(&mdb_entry->list, &lan9645x->mdb_entries);

	dev_dbg(lan9645x->dev, "vid=%u addr=%pM\n", mdb_entry->vid,
		mdb_entry->mac);

	return mdb_entry;
}

static void lan9645x_mdb_encode_mac(unsigned char *dst, unsigned char *mac,
				    u16 ports, enum macaccess_entry_type type)
{
	ether_addr_copy(dst, mac);

	/* The HW encodes the portmask in the high bits of the mac for ip
	 * multicast entries, to save on the limited PGID resources.
	 *
	 * IPv4 Multicast DMAC: 0x01005Exxxxxx
	 * IPv6 Multicast DMAC: 0x3333xxxxxxxx
	 *
	 * which gives us 24 or 16 bits to encode the portmask.
	 */
	if (type == ENTRYTYPE_MACV4) {
		dst[0] = 0;
		dst[1] = ports >> 8;
		dst[2] = ports & 0xff;
	} else if (type == ENTRYTYPE_MACV6) {
		dst[0] = ports >> 8;
		dst[1] = ports & 0xff;
	}
}

static void lan9645x_pgid_entry_put(struct lan9645x *lan9645x,
				    struct lan9645x_pgid_entry *pgid_entry)
{
	if (!pgid_entry)
		return;

	if (!refcount_dec_and_test(&pgid_entry->refcount))
		return;

	dev_dbg(lan9645x->dev, "pgid=%d ports=0x%x", pgid_entry->index,
		pgid_entry->ports);
	/* We leave the PGID written in HW, as no entry is pointing to it. */
	list_del(&pgid_entry->list);
	kfree(pgid_entry);
}

static void lan9645x_mdb_entry_dealloc(struct lan9645x *lan9645x,
				       struct lan9645x_mdb_entry *mdb_entry)
{
	dev_dbg(lan9645x->dev, "vid=%u addr=%pM\n", mdb_entry->vid,
		mdb_entry->mac);
	list_del(&mdb_entry->list);
	lan9645x_pgid_entry_put(lan9645x, mdb_entry->pgid);
	kfree(mdb_entry);
}

static struct lan9645x_pgid_entry *
lan9645x_mdb_pgid_entry_lookup(struct lan9645x *lan9645x, u16 ports)
{
	struct lan9645x_pgid_entry *pgid_entry;

	list_for_each_entry(pgid_entry, &lan9645x->pgid_entries, list) {
		if (pgid_entry->ports == ports &&
		    refcount_inc_not_zero(&pgid_entry->refcount))
			return pgid_entry;
	}

	return NULL;
}

static struct lan9645x_pgid_entry *
lan9645x_pgid_entry_alloc(struct lan9645x *lan9645x, int index, u16 ports)
{
	struct lan9645x_pgid_entry *pgid_entry;

	pgid_entry = kzalloc_obj(*pgid_entry);
	if (!pgid_entry)
		return ERR_PTR(-ENOMEM);

	pgid_entry->ports = ports;
	pgid_entry->index = index;
	refcount_set(&pgid_entry->refcount, 1);

	list_add_tail(&pgid_entry->list, &lan9645x->pgid_entries);

	dev_dbg(lan9645x->dev, "index=%d ports=0x%x", pgid_entry->index,
		pgid_entry->ports);

	lan_rmw(ANA_PGID_PGID_SET(pgid_entry->ports),
		ANA_PGID_PGID, lan9645x,
		ANA_PGID(pgid_entry->index));

	return pgid_entry;
}

static struct lan9645x_pgid_entry *
lan9645x_mdb_pgid_entry_create(struct lan9645x *lan9645x, u16 ports)
{
	struct lan9645x_pgid_entry *pgid_entry = NULL;
	int index;

	for (index = PGID_GP_START; index < PGID_GP_END; index++) {
		bool used = false;

		list_for_each_entry(pgid_entry, &lan9645x->pgid_entries, list) {
			if (pgid_entry->index == index) {
				used = true;
				break;
			}
		}

		if (!used)
			return lan9645x_pgid_entry_alloc(lan9645x, index,
							 ports);
	}

	return ERR_PTR(-ENOSPC);
}

static struct lan9645x_pgid_entry *
lan9645x_mdb_pgid_entry_get(struct lan9645x *lan9645x, u16 ports,
			    enum macaccess_entry_type type)
{
	struct lan9645x_pgid_entry *pgid_entry;
	u16 pgid_ports;

	if (type == ENTRYTYPE_MACV4 || type == ENTRYTYPE_MACV6 || !ports)
		return NULL;

	/* CPU port module forwarding is handled by cpu_copy flag on mac table
	 * entry. So we can strip the CPU port module here to allow better PGID
	 * sharing.
	 */
	pgid_ports = ports & ~BIT(lan9645x->num_phys_ports);

	pgid_entry = lan9645x_mdb_pgid_entry_lookup(lan9645x, pgid_ports);
	if (!pgid_entry)
		return lan9645x_mdb_pgid_entry_create(lan9645x, pgid_ports);

	return pgid_entry;
}

static int lan9645x_mdb_update_dest(struct lan9645x *lan9645x,
				    struct lan9645x_mdb_entry *mdb_entry,
				    enum macaccess_entry_type type,
				    struct lan9645x_pgid_entry *new_pgid,
				    u16 new_ports)
{
	unsigned char mac[ETH_ALEN] __aligned(2);
	struct lan9645x_pgid_entry *old_pgid;
	int err, pgid_index;
	bool cpu_copy;

	old_pgid = mdb_entry->pgid;
	lan9645x_mdb_encode_mac(mac, mdb_entry->mac, new_ports, type);
	cpu_copy = !!(new_ports & BIT(lan9645x->num_phys_ports));
	pgid_index = PGID_INDEX(new_pgid);

	/* For IP multicast, the hardware lookup uses the DMAC
	 * (01:00:5E:.. / 33:33:..) as the (mac, vid) key, not the encoded mac.
	 * Therefore, this CMD_LEARN will atomically rewrite the existing
	 * hardware entry. We intentionally do not do a forget before learn
	 * sequence, as that would not be atomic, and leave a forwarding gap.
	 */
	err = lan9645x_mact_learn_cpu_copy(lan9645x, pgid_index, mac,
					   mdb_entry->vid, type, cpu_copy);
	if (err) {
		lan9645x_pgid_entry_put(lan9645x, new_pgid);
		return err;
	}
	mdb_entry->pgid = new_pgid;
	mdb_entry->ports = new_ports;
	lan9645x_pgid_entry_put(lan9645x, old_pgid);
	return 0;
}

static int __lan9645x_mdb_add(struct lan9645x *lan9645x, int chip_port,
			      const unsigned char addr[ETH_ALEN], u16 vid,
			      enum macaccess_entry_type type)
{
	struct lan9645x_pgid_entry *new_pgid;
	struct lan9645x_mdb_entry *mdb_entry;
	u16 new_ports;
	int err;

	mdb_entry = lan9645x_mdb_entry_lookup(lan9645x, addr, vid);
	if (!mdb_entry) {
		mdb_entry = lan9645x_mdb_entry_alloc(lan9645x, addr, vid);
		if (IS_ERR(mdb_entry))
			return PTR_ERR(mdb_entry);
	}

	if (mdb_entry->ports & BIT(chip_port))
		return 0;

	new_ports = mdb_entry->ports | BIT(chip_port);

	/* Update PGID ptr for non-IP entries (L2 multicast) */
	new_pgid = lan9645x_mdb_pgid_entry_get(lan9645x, new_ports, type);
	if (IS_ERR(new_pgid)) {
		/* Out of PGIDs or mem. Continue forwarding to old port
		 * group, or remove if fresh mdb_entry.
		 */
		if (!mdb_entry->ports)
			lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);

		return PTR_ERR(new_pgid);
	}

	err = lan9645x_mdb_update_dest(lan9645x, mdb_entry, type, new_pgid,
				       new_ports);
	if (err && !mdb_entry->ports)
		lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);

	return err;
}

static int __lan9645x_mdb_del(struct lan9645x *lan9645x, int chip_port,
			      const unsigned char addr[ETH_ALEN], u16 vid,
			      enum macaccess_entry_type type)
{
	struct lan9645x_pgid_entry *new_pgid;
	struct lan9645x_mdb_entry *mdb_entry;
	u16 new_ports;
	int err;

	mdb_entry = lan9645x_mdb_entry_lookup(lan9645x, addr, vid);
	if (!mdb_entry)
		return -ENOENT;

	if (!(mdb_entry->ports & BIT(chip_port)))
		return 0;

	new_ports = mdb_entry->ports & ~BIT(chip_port);

	if (!new_ports) {
		/* For IP multicast hardware uses DMAC as key (mac,vid) not
		 * encoded mac.
		 */
		err = lan9645x_mact_forget(lan9645x, mdb_entry->mac,
					   mdb_entry->vid, type);
		if (err)
			return err;
		lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);
		return 0;
	}

	/* Update PGID ptr for non-IP entries (L2 multicast) */
	new_pgid = lan9645x_mdb_pgid_entry_get(lan9645x, new_ports, type);
	if (IS_ERR(new_pgid))
		/* Continue forwarding to old port group. */
		return PTR_ERR(new_pgid);

	return lan9645x_mdb_update_dest(lan9645x, mdb_entry, type, new_pgid,
					new_ports);
}

static int lan9645x_mdb_add(struct lan9645x *lan9645x, int chip_port,
			    const unsigned char addr[ETH_ALEN], u16 vid,
			    enum macaccess_entry_type type)
{
	int err;

	mutex_lock(&lan9645x->mdb_lock);
	err = __lan9645x_mdb_add(lan9645x, chip_port, addr, vid, type);
	mutex_unlock(&lan9645x->mdb_lock);
	return err;
}

static int lan9645x_mdb_del(struct lan9645x *lan9645x, int chip_port,
			    const unsigned char addr[ETH_ALEN], u16 vid,
			    enum macaccess_entry_type type)
{
	int err;

	mutex_lock(&lan9645x->mdb_lock);
	err = __lan9645x_mdb_del(lan9645x, chip_port, addr, vid, type);
	mutex_unlock(&lan9645x->mdb_lock);
	return err;
}

int lan9645x_mdb_port_add(struct lan9645x *lan9645x, int port,
			  const struct switchdev_obj_port_mdb *mdb,
			  struct net_device *bridge)
{
	enum macaccess_entry_type type;
	u16 vid = mdb->vid;

	type = lan9645x_mdb_classify(mdb->addr);

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!bridge);

	return lan9645x_mdb_add(lan9645x, port, mdb->addr, vid, type);
}

int lan9645x_mdb_port_del(struct lan9645x *lan9645x, int port,
			  const struct switchdev_obj_port_mdb *mdb,
			  struct net_device *bridge)
{
	enum macaccess_entry_type type;
	u16 vid = mdb->vid;

	type = lan9645x_mdb_classify(mdb->addr);

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!bridge);

	return lan9645x_mdb_del(lan9645x, port, mdb->addr, vid, type);
}

void lan9645x_mdb_deinit(struct lan9645x *lan9645x)
{
	struct lan9645x_mdb_entry *mdb, *tmp;

	list_for_each_entry_safe(mdb, tmp, &lan9645x->mdb_entries, list)
		lan9645x_mdb_entry_dealloc(lan9645x, mdb);

	mutex_destroy(&lan9645x->mdb_lock);
}
