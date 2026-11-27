/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Security descriptor decoder and encoder (MS-DTYP 2.4.6) */

#ifndef __KSMBD_SECDESC_H
#define __KSMBD_SECDESC_H

#include <linux/types.h>

#include "../common/smbacl.h"

enum ksmbd_acl_state {
	KSMBD_ACL_ABSENT,	/* DACL_PRESENT or SACL_PRESENT is clear */
	KSMBD_ACL_NULL,		/* the bit is set and there is no ACL */
	KSMBD_ACL_PRESENT,	/* the bit is set and there is an ACL */
};

struct ksmbd_ace {
	u8	type;
	u8	flags;
	u32	mask;
	const struct smb_sid *sid;

	/*
	 * Kept for the encoder, as ksmbd reads neither: the Flags and GUIDs
	 * of an object type (MS-DTYP 2.4.4.3), and what follows the SID,
	 * such as the ApplicationData of a callback type. An ACE is of an
	 * object type if and only if @obj_len is not 0.
	 */
	const u8 *obj __counted_by_ptr(obj_len);
	const u8 *data __counted_by_ptr(data_len);
	u16	obj_len;
	u16	data_len;
};

struct ksmbd_sd {
	const struct smb_sid *owner;
	const struct smb_sid *group;
	/*
	 * The Control bits other than SELF_RELATIVE, DACL_PRESENT, and
	 * SACL_PRESENT. The encoder sets those three itself.
	 */
	u16	control;
	enum ksmbd_acl_state dacl;

	/* Kept for the encoder, as ksmbd reads none of these */
	const u8 *sacl_data __counted_by_ptr(sacl_len);
	u16	sacl_len;
	enum ksmbd_acl_state sacl;
	u8	sbz1;
	u8	dacl_revision;
	u8	dacl_sbz1;
	u16	dacl_sbz2;

	/* The decoder left out a malformed owner, group, or SACL */
	bool	part_dropped;

	unsigned int num_aces;		/* of the DACL */
	struct ksmbd_ace aces[] __counted_by(num_aces);
};

int __must_check ksmbd_sd_decode(const u8 *buf, size_t len,
				 struct ksmbd_sd **out);
int __must_check ksmbd_sd_encode(const struct ksmbd_sd *sd, u8 **buf,
				 size_t *len);

#endif /* __KSMBD_SECDESC_H */
