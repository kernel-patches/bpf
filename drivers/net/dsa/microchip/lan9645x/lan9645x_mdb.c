// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include "lan9645x_main.h"

/* IPv4/IPv6 types the mac entry dest_idx is not used for forwarding. The
 * datasheet recommends using 0 as the dummy index.
 */
#define IP_ENTRY_PGID		0

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

static int lan9645x_pgid_idx(const struct lan9645x_pgid_entry *pgid)
{
	return pgid ? pgid->index : IP_ENTRY_PGID;
}

void lan9645x_mdb_init(struct lan9645x *lan9645x)
{
	INIT_LIST_HEAD(&lan9645x->mdb_entries);
	INIT_LIST_HEAD(&lan9645x->pgid_entries);
	mutex_init(&lan9645x->mdb_lock);
}

static enum macaccess_entry_type lan9645x_mdb_classify(const unsigned char *mac)
{
	if (mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e)
		return ENTRYTYPE_MACV4;
	if (mac[0] == 0x33 && mac[1] == 0x33)
		return ENTRYTYPE_MACV6;
	return ENTRYTYPE_LOCKED;
}

static struct lan9645x_mdb_entry *
lan9645x_mdb_entry_lookup(struct lan9645x *lan9645x, const unsigned char *mac,
			  u16 vid)
{
	struct lan9645x_mdb_entry *mdb;

	lockdep_assert_held(&lan9645x->mdb_lock);

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

	lockdep_assert_held(&lan9645x->mdb_lock);

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

static void lan9645x_mdb_encode_mac(unsigned char *dst,
				    const unsigned char *mac, u16 ports,
				    enum macaccess_entry_type type)
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
	lockdep_assert_held(&lan9645x->mdb_lock);

	if (!pgid_entry)
		return;

	if (!refcount_dec_and_test(&pgid_entry->refcount))
		return;

	dev_dbg(lan9645x->dev, "pgid=%d ports=0x%x\n", pgid_entry->index,
		pgid_entry->ports);
	/* Leave the destination mask programmed in HW. Reusing the index
	 * rewrites the mask in lan9645x_pgid_entry_alloc() before anything
	 * points at it.
	 */
	list_del(&pgid_entry->list);
	kfree(pgid_entry);
}

static void lan9645x_mdb_entry_dealloc(struct lan9645x *lan9645x,
				       struct lan9645x_mdb_entry *mdb_entry)
{
	lockdep_assert_held(&lan9645x->mdb_lock);

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

	lockdep_assert_held(&lan9645x->mdb_lock);

	list_for_each_entry(pgid_entry, &lan9645x->pgid_entries, list) {
		if (pgid_entry->ports == ports) {
			refcount_inc(&pgid_entry->refcount);
			return pgid_entry;
		}
	}

	return NULL;
}

static struct lan9645x_pgid_entry *
lan9645x_pgid_entry_alloc(struct lan9645x *lan9645x, int index, u16 ports)
{
	struct lan9645x_pgid_entry *pgid_entry;

	lockdep_assert_held(&lan9645x->mdb_lock);

	pgid_entry = kzalloc_obj(*pgid_entry);
	if (!pgid_entry)
		return ERR_PTR(-ENOMEM);

	pgid_entry->ports = ports;
	pgid_entry->index = index;
	refcount_set(&pgid_entry->refcount, 1);

	list_add_tail(&pgid_entry->list, &lan9645x->pgid_entries);

	dev_dbg(lan9645x->dev, "index=%d ports=0x%x\n", pgid_entry->index,
		pgid_entry->ports);

	lan_rmw(ANA_PGID_PGID_SET(pgid_entry->ports),
		ANA_PGID_PGID, lan9645x,
		ANA_PGID(pgid_entry->index));

	return pgid_entry;
}

static struct lan9645x_pgid_entry *
lan9645x_mdb_pgid_entry_create(struct lan9645x *lan9645x, u16 ports)
{
	struct lan9645x_pgid_entry *pgid_entry;
	int index;

	lockdep_assert_held(&lan9645x->mdb_lock);

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

	lockdep_assert_held(&lan9645x->mdb_lock);

	if (type == ENTRYTYPE_MACV4 || type == ENTRYTYPE_MACV6)
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

/* An L2 MC group without a pgid is one that fell back to the flood mask in
 * __lan9645x_mdb_del().
 */
static bool
lan9645x_mdb_on_flood_mask(const struct lan9645x_mdb_entry *mdb_entry,
			   enum macaccess_entry_type type)
{
	return type == ENTRYTYPE_LOCKED && mdb_entry->ports && !mdb_entry->pgid;
}

/* Point the hardware mac table entry at pgid_index with the port mask
 * new_ports. Does not touch mdb_entry, the caller owns the software state.
 */
static int lan9645x_mdb_write_dest(struct lan9645x *lan9645x,
				   struct lan9645x_mdb_entry *mdb_entry,
				   enum macaccess_entry_type type,
				   int pgid_index, u16 new_ports)
{
	unsigned char mac[ETH_ALEN] __aligned(2);
	bool cpu_copy;

	lockdep_assert_held(&lan9645x->mdb_lock);

	lan9645x_mdb_encode_mac(mac, mdb_entry->mac, new_ports, type);
	cpu_copy = !!(new_ports & BIT(lan9645x->num_phys_ports));

	/* For IP multicast, the hardware lookup uses the DMAC
	 * (01:00:5E:.. / 33:33:..) as the (mac, vid) key, not the encoded mac.
	 * Therefore, this CMD_LEARN will atomically rewrite the existing
	 * hardware entry. We intentionally do not do a forget before learn
	 * sequence, as that would not be atomic, and leave a forwarding gap.
	 */
	return lan9645x_mact_learn(lan9645x, pgid_index, mac, mdb_entry->vid,
				   type, cpu_copy);
}

/* Grow the group. A port can be refused membership, and the bridge reads the
 * return value of a SWITCHDEV_PORT_OBJ_ADD, so a failure must leave the
 * software entry exactly as it was and drop the reference taken on new_pgid.
 */
static int lan9645x_mdb_widen_dest(struct lan9645x *lan9645x,
				   struct lan9645x_mdb_entry *mdb_entry,
				   enum macaccess_entry_type type,
				   struct lan9645x_pgid_entry *new_pgid,
				   int pgid_index, u16 new_ports)
{
	struct lan9645x_pgid_entry *old_pgid = mdb_entry->pgid;
	int err;

	lockdep_assert_held(&lan9645x->mdb_lock);

	err = lan9645x_mdb_write_dest(lan9645x, mdb_entry, type, pgid_index,
				      new_ports);
	if (err) {
		lan9645x_pgid_entry_put(lan9645x, new_pgid);
		return err;
	}
	mdb_entry->pgid = new_pgid;
	mdb_entry->ports = new_ports;
	lan9645x_pgid_entry_put(lan9645x, old_pgid);
	return 0;
}

/* Shrink the group. A port cannot be refused leaving, and reporting a failure
 * is worse than useless. One del path ignores the error:
 * switchdev_port_obj_del_deferred() only logs it, and unlike RTM_NEWMDB the
 * RTM_DELMDB path installs no obj.complete. The other truncates on it:
 * br_switchdev_mdb_replay() abandons the remaining entries after the first
 * failure, so failing one delete during a bridge leave would leave the other
 * groups programmed. The bridge has already dropped the group by the time we
 * run, so it will never ask again.
 *
 * Commit the software state first, then program hardware and only log a
 * failure. That keeps both invariants the rest of this file relies on:
 *
 *   mdb_entry->ports stays a subset of the bridge's view of the group, so a
 *   later delete can still drive it to zero and reclaim the entry, and
 *
 *   mdb_entry->pgid->ports stays equal to
 *   mdb_entry->ports & ~BIT(num_phys_ports), which is what lets
 *   __lan9645x_mdb_del() conclude that a departing port reaching the
 *   overwrite in place branch cannot be the CPU port module.
 */
static void lan9645x_mdb_narrow_dest(struct lan9645x *lan9645x,
				     struct lan9645x_mdb_entry *mdb_entry,
				     enum macaccess_entry_type type,
				     struct lan9645x_pgid_entry *new_pgid,
				     int pgid_index, u16 new_ports)
{
	struct lan9645x_pgid_entry *old_pgid = mdb_entry->pgid;
	int err;

	lockdep_assert_held(&lan9645x->mdb_lock);

	mdb_entry->pgid = new_pgid;
	mdb_entry->ports = new_ports;

	err = lan9645x_mdb_write_dest(lan9645x, mdb_entry, type, pgid_index,
				      new_ports);
	if (err) {
		dev_err(lan9645x->dev,
			"Narrowing %pM vid %u to mask 0x%x returned %pe\n",
			mdb_entry->mac, mdb_entry->vid, new_ports,
			ERR_PTR(err));
		return;
	}

	lan9645x_pgid_entry_put(lan9645x, old_pgid);
}

static int __lan9645x_mdb_add(struct lan9645x *lan9645x, int chip_port,
			      const unsigned char addr[ETH_ALEN], u16 vid,
			      enum macaccess_entry_type type)
{
	struct lan9645x_pgid_entry *new_pgid;
	struct lan9645x_mdb_entry *mdb_entry;
	u16 new_ports;
	int err;

	lockdep_assert_held(&lan9645x->mdb_lock);

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
		/* Out of PGIDs or mem. Remove a fresh mdb_entry again. */
		if (!mdb_entry->ports) {
			lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);
			return PTR_ERR(new_pgid);
		}

		/* For a L2 MC group already on the flood mask, we keep it there
		 * so that the host can still join/leave a group we had to give
		 * up offloading.
		 */
		if (lan9645x_mdb_on_flood_mask(mdb_entry, type))
			return lan9645x_mdb_widen_dest(lan9645x, mdb_entry,
						       type, NULL, PGID_MC,
						       new_ports);

		/* Continue forwarding to old port group. */
		return PTR_ERR(new_pgid);
	}

	err = lan9645x_mdb_widen_dest(lan9645x, mdb_entry, type, new_pgid,
				      lan9645x_pgid_idx(new_pgid), new_ports);
	if (err && !mdb_entry->ports) {
		/* We are about to drop a fresh entry, so make sure the hardware
		 * does not keep one we can no longer reach. The mac commands
		 * complete in a few microseconds, so the only way to get here
		 * with an entry actually written is for the register bus to
		 * fail between the command and the status read. That is close
		 * to impossible, but the forget costs nothing: it is a noop if
		 * the entry was never written, and it fails harmlessly if the
		 * bus is still down.
		 */
		lan9645x_mact_forget(lan9645x, mdb_entry->mac,
				     mdb_entry->vid, type);
		lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);
	}

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

	lockdep_assert_held(&lan9645x->mdb_lock);

	mdb_entry = lan9645x_mdb_entry_lookup(lan9645x, addr, vid);
	if (!mdb_entry)
		return -ENOENT;

	if (!(mdb_entry->ports & BIT(chip_port)))
		return 0;

	new_ports = mdb_entry->ports & ~BIT(chip_port);

	if (!new_ports) {
		/* The encoded bytes are not part of the (mac, vid) key used for
		 * lookups in the mactable, for entries of type 2
		 * (IPv4 Multicast) and type 3 (IPv6 Multicast). For these types
		 * the mac used in the key is the 'real' mac e.g.
		 *
		 * Type 2 (IPv4 multicast):
		 * KEY_MAC = 0x01005E000000 | MACLDATA[23:0]
		 *
		 * Type 3 (IPv6 multicast):
		 * KEY_MAC = 0x333300000000 | MACLDATA[31:0]
		 *
		 * This holds for both the datapath and the CPU access path.
		 * Therefore, it is not necessary to encode the mac before a
		 * CMD_FORGET, because the bytes it changes are unused for the
		 * lookup.
		 */
		err = lan9645x_mact_forget(lan9645x, mdb_entry->mac,
					   mdb_entry->vid, type);
		if (err) {
			dev_err(lan9645x->dev,
				"Forgetting %pM vid %u on port %d returned %pe\n",
				mdb_entry->mac, mdb_entry->vid, chip_port,
				ERR_PTR(err));
			mdb_entry->pgid = NULL;
		}
		lan9645x_mdb_entry_dealloc(lan9645x, mdb_entry);
		return 0;
	}

	/* Update PGID ptr for non-IP entries (L2 multicast) */
	new_pgid = lan9645x_mdb_pgid_entry_get(lan9645x, new_ports, type);
	if (!IS_ERR(new_pgid)) {
		lan9645x_mdb_narrow_dest(lan9645x, mdb_entry, type, new_pgid,
					 lan9645x_pgid_idx(new_pgid),
					 new_ports);
		return 0;
	}

	/* Out of pgids for L2 MC.
	 *
	 * PGID is not shared, so we overwrite in place.
	 *
	 * We know the deleted port is not the CPU. Getting here means
	 * lan9645x_mdb_pgid_entry_get() found no PGID holding the narrowed
	 * mask, and for a delete of only the CPU port module bit the mask it
	 * looks up is unchanged, since lan9645x_mdb_pgid_entry_get() strips
	 * that bit. lan9645x_mdb_pgid_entry_lookup() would have returned the
	 * PGID this entry already points at. So the departing port is a front
	 * port, and the mac table entry, which only carries the PGID index and
	 * MAC_CPU_COPY, does not need rewriting.
	 *
	 * refcount_read is safe because mdb_lock serializes every get and put
	 * of a PGID entry.
	 */
	if (mdb_entry->pgid && refcount_read(&mdb_entry->pgid->refcount) == 1) {
		mdb_entry->pgid->ports = new_ports &
					 ~BIT(lan9645x->num_phys_ports);
		mdb_entry->ports = new_ports;

		lan_rmw(ANA_PGID_PGID_SET(mdb_entry->pgid->ports),
			ANA_PGID_PGID,
			lan9645x, ANA_PGID(mdb_entry->pgid->index));

		return 0;
	}

	/* Shared PGID or on flood mask. Point the entry at the L2 MC flood mask
	 * instead. This way our mac table entry survives and MAC_CPU_COPY
	 * keeps host membership working.
	 */
	if (mdb_entry->pgid)
		dev_warn_ratelimited(lan9645x->dev,
				     "No PGID, flooding group %pM vid %u: %pe\n",
				     mdb_entry->mac, mdb_entry->vid, new_pgid);

	lan9645x_mdb_narrow_dest(lan9645x, mdb_entry, type, NULL, PGID_MC,
				 new_ports);
	return 0;
}

int lan9645x_mdb_add(struct lan9645x *lan9645x, int port,
		     const struct switchdev_obj_port_mdb *mdb,
		     struct net_device *bridge)
{
	enum macaccess_entry_type type;
	u16 vid = mdb->vid;
	int err;

	type = lan9645x_mdb_classify(mdb->addr);

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!bridge);

	mutex_lock(&lan9645x->mdb_lock);
	err = __lan9645x_mdb_add(lan9645x, port, mdb->addr, vid, type);
	mutex_unlock(&lan9645x->mdb_lock);
	return err;
}

int lan9645x_mdb_del(struct lan9645x *lan9645x, int port,
		     const struct switchdev_obj_port_mdb *mdb,
		     struct net_device *bridge)
{
	enum macaccess_entry_type type;
	u16 vid = mdb->vid;
	int err;

	type = lan9645x_mdb_classify(mdb->addr);

	if (!vid)
		vid = lan9645x_vlan_unaware_pvid(!!bridge);

	mutex_lock(&lan9645x->mdb_lock);
	err = __lan9645x_mdb_del(lan9645x, port, mdb->addr, vid, type);
	mutex_unlock(&lan9645x->mdb_lock);
	return err;
}

void lan9645x_mdb_deinit(struct lan9645x *lan9645x)
{
	struct lan9645x_pgid_entry *pgid, *pgid_tmp;
	struct lan9645x_mdb_entry *mdb, *tmp;

	mutex_lock(&lan9645x->mdb_lock);
	list_for_each_entry_safe(mdb, tmp, &lan9645x->mdb_entries, list)
		lan9645x_mdb_entry_dealloc(lan9645x, mdb);

	list_for_each_entry_safe(pgid, pgid_tmp, &lan9645x->pgid_entries, list) {
		list_del(&pgid->list);
		kfree(pgid);
	}
	mutex_unlock(&lan9645x->mdb_lock);

	mutex_destroy(&lan9645x->mdb_lock);
}
