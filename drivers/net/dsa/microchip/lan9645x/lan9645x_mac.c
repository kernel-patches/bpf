// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include "lan9645x_main.h"

#define CMD_IDLE		0
#define CMD_LEARN		1
#define CMD_FORGET		2
#define CMD_AGE			3
#define CMD_GET_NEXT		4
#define CMD_INIT		5
#define CMD_READ		6
#define CMD_WRITE		7
#define CMD_SYNC_GET_NEXT	8

/* The chip has 2048 * 4 = 8192 total entries in the mac table */
#define MACT_ROWS		(FIELD_MAX(ANA_MACTINDX_M_INDEX) + 1)
#define MACT_BUCKETS		(FIELD_MAX(ANA_MACTINDX_BUCKET) + 1)
#define MACT_ENTRIES		(MACT_ROWS * MACT_BUCKETS)
#define MACT_GET_NEXT_MAX	(MACT_ENTRIES + 1)

static int lan9645x_mac_wait_for_completion(struct lan9645x *lan9645x,
					    u32 *maca)
{
	u32 val = 0;
	int err;

	lockdep_assert_held(&lan9645x->mact_lock);

	err = lan9645x_rd_poll_timeout(lan9645x, ANA_MACACCESS, val,
				       ANA_MACACCESS_MAC_TABLE_CMD_GET(val) ==
				       CMD_IDLE);
	if (err)
		return err;

	if (maca)
		*maca = val;

	return 0;
}

static void lan9645x_mac_select(struct lan9645x *lan9645x,
				const unsigned char mac[ETH_ALEN],
				unsigned int vid)
{
	u64 maddr = ether_addr_to_u64(mac);

	lockdep_assert_held(&lan9645x->mact_lock);

	lan_wr(ANA_MACHDATA_VID_SET(vid) |
	       ANA_MACHDATA_MACHDATA_SET(upper_32_bits(maddr)),
	       lan9645x,
	       ANA_MACHDATA);

	lan_wr(lower_32_bits(maddr),
	       lan9645x,
	       ANA_MACLDATA);
}

static int __lan9645x_mact_forget(struct lan9645x *lan9645x,
				  const unsigned char mac[ETH_ALEN],
				  unsigned int vid,
				  enum macaccess_entry_type type)
{
	lockdep_assert_held(&lan9645x->mact_lock);

	lan9645x_mac_select(lan9645x, mac, vid);

	lan_wr(ANA_MACACCESS_ENTRYTYPE_SET(type) |
	       ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_FORGET),
	       lan9645x,
	       ANA_MACACCESS);

	return lan9645x_mac_wait_for_completion(lan9645x, NULL);
}

int lan9645x_mact_forget(struct lan9645x *lan9645x,
			 const unsigned char mac[ETH_ALEN], unsigned int vid,
			 enum macaccess_entry_type type)
{
	int err;

	mutex_lock(&lan9645x->mact_lock);
	err = __lan9645x_mact_forget(lan9645x, mac, vid, type);
	mutex_unlock(&lan9645x->mact_lock);

	return err;
}

static int __lan9645x_mact_learn(struct lan9645x *lan9645x, int port,
				 const unsigned char mac[ETH_ALEN],
				 unsigned int vid,
				 enum macaccess_entry_type type,
				 bool cpu_copy)
{
	lockdep_assert_held(&lan9645x->mact_lock);

	lan9645x_mac_select(lan9645x, mac, vid);

	lan_wr(ANA_MACACCESS_VALID_SET(1) |
	       ANA_MACACCESS_DEST_IDX_SET(port) |
	       ANA_MACACCESS_MAC_CPU_COPY_SET(cpu_copy) |
	       ANA_MACACCESS_ENTRYTYPE_SET(type) |
	       ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_LEARN),
	       lan9645x, ANA_MACACCESS);

	return lan9645x_mac_wait_for_completion(lan9645x, NULL);
}

int lan9645x_mact_learn(struct lan9645x *lan9645x, int port,
			const unsigned char mac[ETH_ALEN], unsigned int vid,
			enum macaccess_entry_type type, bool cpu_copy)
{
	int err;

	mutex_lock(&lan9645x->mact_lock);
	err = __lan9645x_mact_learn(lan9645x, port, mac, vid, type, cpu_copy);
	mutex_unlock(&lan9645x->mact_lock);

	return err;
}

int lan9645x_mact_flush(struct lan9645x *lan9645x, int port)
{
	int err;

	mutex_lock(&lan9645x->mact_lock);
	/* MAC table entries with dst index matching port are aged on scan. */
	lan_wr(ANA_ANAGEFIL_PID_EN_SET(1) |
	       ANA_ANAGEFIL_PID_VAL_SET(port),
	       lan9645x, ANA_ANAGEFIL);

	/* Flushing requires two scans. First sets AGE_FLAG=1, second removes
	 * entries with AGE_FLAG=1.
	 */
	lan_wr(ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_AGE),
	       lan9645x,
	       ANA_MACACCESS);

	err = lan9645x_mac_wait_for_completion(lan9645x, NULL);
	if (err)
		goto mact_unlock;

	lan_wr(ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_AGE),
	       lan9645x,
	       ANA_MACACCESS);

	err = lan9645x_mac_wait_for_completion(lan9645x, NULL);

mact_unlock:
	lan_wr(0, lan9645x, ANA_ANAGEFIL);
	mutex_unlock(&lan9645x->mact_lock);
	return err;
}

int lan9645x_mac_init(struct lan9645x *lan9645x)
{
	u32 val;
	int err;

	/* Clear the MAC table */
	lan_wr(ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_INIT), lan9645x,
	       ANA_MACACCESS);

	err = lan9645x_rd_poll_timeout(lan9645x, ANA_MACACCESS, val,
				       ANA_MACACCESS_MAC_TABLE_CMD_GET(val) ==
				       CMD_IDLE);
	if (err) {
		dev_err(lan9645x->dev, "MAC table clear timeout\n");
		return err;
	}

	mutex_init(&lan9645x->mact_lock);
	return 0;
}

void lan9645x_mac_deinit(struct lan9645x *lan9645x)
{
	mutex_destroy(&lan9645x->mact_lock);
}

int lan9645x_mact_dsa_dump(struct lan9645x *lan9645x, int port,
			   dsa_fdb_dump_cb_t *cb, void *data)
{
	u8 mac[ETH_ALEN] __aligned(2);
	u32 mach, macl, maca;
	int err = 0;
	u64 addr;
	int iter;
	u16 vid;
	u8 type;

	mutex_lock(&lan9645x->mact_lock);

	/* The aging filter works both for aging scans and GET_NEXT table scans.
	 * With it, the HW table iteration only stops at entries matching our
	 * filter. Since DSA calls us for each port on a table dump, this helps
	 * avoid unnecessary work.
	 *
	 * Setup agefilter on our port
	 */
	lan_wr(ANA_ANAGEFIL_PID_EN_SET(1) |
	       ANA_ANAGEFIL_PID_VAL_SET(port),
	       lan9645x, ANA_ANAGEFIL);

	lan_wr(0, lan9645x, ANA_MACHDATA);
	lan_wr(0, lan9645x, ANA_MACLDATA);

	type = ENTRYTYPE_NORMAL;

	for (iter = 0; iter < MACT_GET_NEXT_MAX; iter++) {
		/* CMD_GET_NEXT returns the smallest entry ordered above the one
		 * left in the registers.
		 * We rely on mach, macl and type being set correctly in
		 * the registers from previous round, vis a vis the GET_NEXT
		 * semantics, so locking entire loop is important.
		 */
		lan_wr(ANA_MACACCESS_MAC_TABLE_CMD_SET(CMD_GET_NEXT) |
		       ANA_MACACCESS_ENTRYTYPE_SET(type),
		       lan9645x, ANA_MACACCESS);

		err = lan9645x_mac_wait_for_completion(lan9645x, &maca);
		if (err)
			break;

		if (ANA_MACACCESS_VALID_GET(maca) == 0)
			break;

		type = ANA_MACACCESS_ENTRYTYPE_GET(maca);
		mach = lan_rd(lan9645x, ANA_MACHDATA);
		macl = lan_rd(lan9645x, ANA_MACLDATA);

		/* Only dynamic entries are surfaced through the user port dump.
		 * ENTRYTYPE_LOCKED entries are already reported by the bridge
		 * master's ndo_fdb_dump as NTF_MASTER, so we avoid duplicating
		 * them as NTF_SELF.
		 * Entries toward the host (NTF_SELF) have DEST_IDX == PGID_CPU
		 * and are filtered out by the DEST_IDX check.
		 */
		if (ANA_MACACCESS_DEST_IDX_GET(maca) == port &&
		    type == ENTRYTYPE_NORMAL) {
			addr = (u64)ANA_MACHDATA_MACHDATA_GET(mach) << 32 |
			       macl;
			u64_to_ether_addr(addr, mac);
			vid = ANA_MACHDATA_VID_GET(mach);
			if (vid > VLAN_MAX)
				vid = 0;

			err = cb(mac, vid, false, data);
			if (err)
				break;
		}
	}

	if (iter == MACT_GET_NEXT_MAX) {
		dev_err(lan9645x->dev,
			"MAC table walk on port %d did not terminate\n", port);
		err = -EIO;
	}

	/* Remove aging filters */
	lan_wr(0, lan9645x, ANA_ANAGEFIL);

	mutex_unlock(&lan9645x->mact_lock);

	return err;
}
