// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include "lan9645x_main.h"

/* IPv4/IPv6 types the mac entry dest_idx is not used for forwarding. The
 * datasheet recommends using 0 as the dummy index.
 */
#define IP_ENTRY_PGID		0

struct lan9645x_mdb_entry {
	struct list_head list;
	unsigned char mac[ETH_ALEN];
	u16 vid;
	u16 ports;
	int pgid;
	enum macaccess_entry_type type;
};

void lan9645x_mdb_init(struct lan9645x *lan9645x)
{
	INIT_LIST_HEAD(&lan9645x->mdb_entries);
	bitmap_zero(lan9645x->mdb_pgids, PGID_GP_END);
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

static int lan9645x_mdb_write_ports(struct lan9645x *lan9645x,
				    struct lan9645x_mdb_entry *mdb_entry,
				    u16 ports)
{
	unsigned char mac[ETH_ALEN] __aligned(2);
	bool cpu_copy;

	lockdep_assert_held(&lan9645x->mdb_lock);

	if (mdb_entry->type == ENTRYTYPE_LOCKED) {
		lan_rmw(ANA_PGID_PGID_SET(ports), ANA_PGID_PGID, lan9645x,
			ANA_PGID(mdb_entry->pgid));
		return 0;
	}

	lan9645x_mdb_encode_mac(mac, mdb_entry->mac, ports, mdb_entry->type);
	cpu_copy = !!(ports & BIT(lan9645x->num_phys_ports));

	/* For IP multicast, the hardware lookup uses the DMAC
	 * (01:00:5E:.. / 33:33:..) as the (mac, vid) key, not the encoded mac.
	 * Therefore, this CMD_LEARN will atomically rewrite the existing
	 * hardware entry. We intentionally do not do a forget before learn
	 * sequence, as that would not be atomic, and leave a forwarding gap.
	 */
	return lan9645x_mact_learn(lan9645x, IP_ENTRY_PGID, mac, mdb_entry->vid,
				   mdb_entry->type, cpu_copy);
}

static int lan9645x_mdb_entry_create(struct lan9645x *lan9645x, int chip_port,
				     const unsigned char addr[ETH_ALEN],
				     u16 vid)
{
	struct lan9645x_mdb_entry *mdb_entry;
	int err;

	lockdep_assert_held(&lan9645x->mdb_lock);

	mdb_entry = kzalloc_obj(*mdb_entry);
	if (!mdb_entry)
		return -ENOMEM;

	ether_addr_copy(mdb_entry->mac, addr);
	mdb_entry->vid = vid;
	mdb_entry->ports = BIT(chip_port);
	mdb_entry->pgid = IP_ENTRY_PGID;
	mdb_entry->type = lan9645x_mdb_classify(addr);

	if (mdb_entry->type == ENTRYTYPE_LOCKED) {
		mdb_entry->pgid = find_next_zero_bit(lan9645x->mdb_pgids,
						     PGID_GP_END,
						     PGID_GP_START);
		if (mdb_entry->pgid >= PGID_GP_END) {
			kfree(mdb_entry);
			return -ENOSPC;
		}
	}

	err = lan9645x_mdb_write_ports(lan9645x, mdb_entry, mdb_entry->ports);
	if (!err && mdb_entry->type == ENTRYTYPE_LOCKED)
		err = lan9645x_mact_learn(lan9645x, mdb_entry->pgid, addr, vid,
					  mdb_entry->type, false);
	if (err) {
		kfree(mdb_entry);
		return err;
	}

	if (mdb_entry->type == ENTRYTYPE_LOCKED)
		set_bit(mdb_entry->pgid, lan9645x->mdb_pgids);

	list_add_tail(&mdb_entry->list, &lan9645x->mdb_entries);

	return 0;
}

static void lan9645x_mdb_entry_destroy(struct lan9645x *lan9645x,
				       struct lan9645x_mdb_entry *mdb_entry)
{
	int err;

	lockdep_assert_held(&lan9645x->mdb_lock);

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
	err = lan9645x_mact_forget(lan9645x, mdb_entry->mac, mdb_entry->vid,
				   mdb_entry->type);
	if (err)
		dev_err(lan9645x->dev, "Forgetting %pM vid %u returned %pe\n",
			mdb_entry->mac, mdb_entry->vid, ERR_PTR(err));
	else if (mdb_entry->type == ENTRYTYPE_LOCKED)
		clear_bit(mdb_entry->pgid, lan9645x->mdb_pgids);

	list_del(&mdb_entry->list);
	kfree(mdb_entry);
}

int lan9645x_mdb_add(struct lan9645x *lan9645x, int chip_port,
		     const unsigned char addr[ETH_ALEN], u16 vid)
{
	struct lan9645x_mdb_entry *mdb_entry;
	u16 new_ports;
	int err = 0;

	mutex_lock(&lan9645x->mdb_lock);

	mdb_entry = lan9645x_mdb_entry_lookup(lan9645x, addr, vid);
	if (!mdb_entry) {
		err = lan9645x_mdb_entry_create(lan9645x, chip_port, addr, vid);
		goto out;
	}

	if (mdb_entry->ports & BIT(chip_port))
		goto out;

	new_ports = mdb_entry->ports | BIT(chip_port);
	err = lan9645x_mdb_write_ports(lan9645x, mdb_entry, new_ports);
	if (!err)
		mdb_entry->ports = new_ports;

out:
	mutex_unlock(&lan9645x->mdb_lock);
	return err;
}

void lan9645x_mdb_del(struct lan9645x *lan9645x, int chip_port,
		      const unsigned char addr[ETH_ALEN], u16 vid)
{
	struct lan9645x_mdb_entry *mdb_entry;
	int err;

	mutex_lock(&lan9645x->mdb_lock);

	mdb_entry = lan9645x_mdb_entry_lookup(lan9645x, addr, vid);
	if (!mdb_entry || !(mdb_entry->ports & BIT(chip_port)))
		goto out;

	mdb_entry->ports &= ~BIT(chip_port);

	if (!mdb_entry->ports) {
		lan9645x_mdb_entry_destroy(lan9645x, mdb_entry);
		goto out;
	}

	err = lan9645x_mdb_write_ports(lan9645x, mdb_entry, mdb_entry->ports);
	if (err)
		dev_err(lan9645x->dev,
			"Removing port %d from %pM vid %u returned %pe\n",
			chip_port, mdb_entry->mac, mdb_entry->vid,
			ERR_PTR(err));

out:
	mutex_unlock(&lan9645x->mdb_lock);
}

void lan9645x_mdb_deinit(struct lan9645x *lan9645x)
{
	struct lan9645x_mdb_entry *mdb, *tmp;

	mutex_lock(&lan9645x->mdb_lock);
	list_for_each_entry_safe(mdb, tmp, &lan9645x->mdb_entries, list) {
		list_del(&mdb->list);
		kfree(mdb);
	}
	mutex_unlock(&lan9645x->mdb_lock);

	mutex_destroy(&lan9645x->mdb_lock);
}
