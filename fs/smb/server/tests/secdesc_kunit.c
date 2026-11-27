// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KUnit tests for the security descriptor decoder and encoder.
 *
 * The SDs are fixed bytes. Most cases use base_sd. t_base_fields() gives the
 * same SD as a struct ksmbd_sd filled in by hand, and a malformed SD is
 * base_sd with one byte changed.
 *
 * base_sd and its parts come first, then the helpers, and then the test
 * cases in the order they run. The data that only one case uses is just
 * above that case.
 */

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <asm/byteorder.h>

#include "../smbacl.h"
#include "../secdesc.h"

/*
 * Offsets of the fields in the structures of MS-DTYP 2.4.6, 2.4.5, 2.4.4,
 * and 2.4.2.2
 */
enum {
	O_SD_REVISION = 0, O_SD_CONTROL = 2, O_SD_OWNER = 4, O_SD_GROUP = 8,
	O_SD_SACL = 12, O_SD_DACL = 16, O_SD_HDR_LEN = 20,
	O_ACL_REVISION = 0, O_ACL_SIZE = 2, O_ACL_COUNT = 4, O_ACL_HDR_LEN = 8,
	O_ACE_TYPE = 0, O_ACE_SIZE = 2, O_ACE_MASK = 4, O_ACE_OBJ_FLAGS = 8,
	O_SID_REVISION = 0, O_SID_COUNT = 1, O_SID_AUTHORITY = 7,
};

/*
 * An SD with every part: an owner, a group, a DACL with a plain allow ACE,
 * a plain deny ACE, an object ACE and a callback ACE, and a SACL with an
 * audit ACE and a label ACE. It is laid out as the encoder writes an SD,
 * which is owner, group, DACL, and SACL.
 */
static const u8 base_sd[] = {
	/*
	 * the header: Control SR|DI|SP|DP, owner at 20, group at 48, SACL
	 * at 204, DACL at 76
	 */
	0x01, 0x00, 0x14, 0x84, 0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
	0xcc, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00,
	/* the owner S-1-5-21-1-2-3-1000 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00,
	/* the group S-1-5-21-1-2-3-513 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x00, 0x00,
	/* the DACL: revision 4, 128 bytes, 4 ACEs */
	0x04, 0x00, 0x80, 0x00, 0x04, 0x00, 0x00, 0x00,
	/* allow, OI|CI, 36 bytes, 0x1f01ff, S-1-5-21-1-2-3-1000 */
	0x00, 0x03, 0x24, 0x00, 0xff, 0x01, 0x1f, 0x00, 0x01, 0x05, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	/* deny, 20 bytes, 0x2, S-1-1-0 */
	0x01, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* allow object, 40 bytes, 0x10, Flags 1 and a GUID, S-1-1-0 */
	0x05, 0x00, 0x28, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	/* allow callback, 24 bytes, 0x1, S-1-1-0, 4 bytes of data */
	0x09, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/* the SACL: revision 2, 48 bytes, 2 ACEs */
	0x02, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00,
	/* audit, 0x80, 20 bytes, 0x10000, S-1-1-0 */
	0x02, 0x80, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* mandatory label, 20 bytes, 0x1, S-1-16-8192 */
	0x11, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00,
};

/* Where the parts of base_sd start */
enum {
	B_OWNER	= 20,
	B_GROUP	= 48,
	B_DACL	= 76,
	B_ACE0	= 84,
	B_ACE1	= 120,
	B_ACE2	= 140,
	B_ACE3	= 180,
	B_SACL	= 204,
	B_SACE0	= 212,
};

static const struct smb_sid base_owner = {
	1, 5, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),
	 cpu_to_le32(1000)} };
static const struct smb_sid base_group = {
	1, 5, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),
	 cpu_to_le32(513)} };
static const struct smb_sid everyone = { 1, 1, {0, 0, 0, 0, 0, 1}, {0} };

/* The object section of ACE 2 of base_sd: Flags 1 and one GUID */
static const u8 base_obj[20] = {
	0x01, 0x00, 0x00, 0x00,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

/* The data after the SID of ACE 3 of base_sd (MS-DTYP 2.4.4.17) */
static const u8 base_data[4] = { 'a', 'r', 't', 'x' };

static void t_sd_free(void *sd)
{
	kvfree(sd);
}

/* Arranges for @sd to be freed when the test case ends, and returns it */
static struct ksmbd_sd *t_keep_sd(struct kunit *test, struct ksmbd_sd *sd)
{
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, t_sd_free, sd), 0);
	return sd;
}

/*
 * Returns a zeroed SD with room for @num_aces ACEs. It is freed when the
 * test case ends.
 */
static struct ksmbd_sd *t_alloc(struct kunit *test, size_t num_aces)
{
	struct ksmbd_sd *sd = kvzalloc(struct_size(sd, aces, num_aces), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, sd);
	sd->num_aces = num_aces;
	return t_keep_sd(test, sd);
}

/* Returns a copy of base_sd that a test can change */
static u8 *t_base_copy(struct kunit *test)
{
	u8 *buf = kunit_kzalloc(test, sizeof(base_sd), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, buf);
	memcpy(buf, base_sd, sizeof(base_sd));
	return buf;
}

/* Returns base_sd as a caller of the encoder would fill it in */
static struct ksmbd_sd *t_base_fields(struct kunit *test)
{
	struct ksmbd_sd *sd = t_alloc(test, 4);

	sd->owner = &base_owner;
	sd->group = &base_group;
	sd->control = DACL_AUTO_INHERITED;
	sd->dacl = KSMBD_ACL_PRESENT;
	sd->dacl_revision = 4;
	sd->aces[0] = (struct ksmbd_ace){
		.type = ACCESS_ALLOWED_ACE_TYPE,
		.flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
		.mask = 0x001f01ff, .sid = &base_owner,
	};
	sd->aces[1] = (struct ksmbd_ace){
		.type = ACCESS_DENIED_ACE_TYPE, .mask = 0x2, .sid = &everyone,
	};
	sd->aces[2] = (struct ksmbd_ace){
		.type = ACCESS_ALLOWED_OBJECT_ACE_TYPE, .mask = 0x10,
		.sid = &everyone, .obj_len = sizeof(base_obj), .obj = base_obj,
	};
	sd->aces[3] = (struct ksmbd_ace){
		.type = ACCESS_ALLOWED_CALLBACK_ACE_TYPE, .mask = 0x1,
		.sid = &everyone, .data_len = sizeof(base_data), .data = base_data,
	};
	sd->sacl = KSMBD_ACL_PRESENT;
	sd->sacl_len = sizeof(base_sd) - B_SACL;
	sd->sacl_data = &base_sd[B_SACL];
	return sd;
}

/* Decodes bytes that the decoder must accept with nothing left out */
static struct ksmbd_sd *t_decode(struct kunit *test, const u8 *buf, size_t len)
{
	struct ksmbd_sd *sd = NULL;

	KUNIT_ASSERT_EQ(test, ksmbd_sd_decode(buf, len, &sd), 0);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_EXPECT_FALSE(test, sd->part_dropped);
	return t_keep_sd(test, sd);
}

/*
 * Calls the encoder and returns what it returns. On an error the encoder
 * must leave no buffer and a length of 0.
 */
static int t_try_encode(struct kunit *test, const struct ksmbd_sd *sd)
{
	u8 *buf = (u8 *)sd;
	size_t len = 7;
	int rc = ksmbd_sd_encode(sd, &buf, &len);

	if (rc) {
		KUNIT_EXPECT_NULL(test, buf);
		KUNIT_EXPECT_EQ(test, len, 0);
	} else {
		kvfree(buf);
	}
	return rc;
}

/* Expects the encoder to write exactly @want for @sd */
static void t_expect_encoding(struct kunit *test, const struct ksmbd_sd *sd,
			      const u8 *want, size_t want_len)
{
	size_t len = 0;
	u8 *buf = NULL;
	int rc = ksmbd_sd_encode(sd, &buf, &len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	if (!rc) {
		KUNIT_EXPECT_EQ(test, len, want_len);
		if (len == want_len)
			KUNIT_EXPECT_MEMEQ(test, buf, want, len);
	}
	kvfree(buf);
}

/* Returns true if both are the same SID, or if neither is there */
static bool t_sid_same(const struct smb_sid *sid, const struct smb_sid *want)
{
	if (!sid || !want)
		return sid == want;
	return sid->num_subauth == want->num_subauth &&
	       !memcmp(sid, want, CIFS_SID_BASE_SIZE + 4 * want->num_subauth);
}

/*
 * Returns true if both are the same bytes. A pointer with no bytes behind
 * it has to be NULL.
 */
static bool t_bytes_same(const u8 *p, size_t len, const u8 *want, size_t want_len)
{
	return len == want_len && !p == !len && (!len || !memcmp(p, want, len));
}

/*
 * Expects @sd to have the fields of @want, and the same bytes behind each
 * pointer
 */
static void t_expect_same(struct kunit *test, const struct ksmbd_sd *sd,
			  const struct ksmbd_sd *want)
{
	unsigned int i;

	KUNIT_EXPECT_TRUE(test, t_sid_same(sd->owner, want->owner));
	KUNIT_EXPECT_TRUE(test, t_sid_same(sd->group, want->group));
	KUNIT_EXPECT_EQ(test, sd->control, want->control);
	KUNIT_EXPECT_EQ(test, sd->sbz1, want->sbz1);
	KUNIT_EXPECT_EQ(test, (int)sd->dacl, (int)want->dacl);
	KUNIT_EXPECT_EQ(test, sd->dacl_revision, want->dacl_revision);
	KUNIT_EXPECT_EQ(test, sd->dacl_sbz1, want->dacl_sbz1);
	KUNIT_EXPECT_EQ(test, sd->dacl_sbz2, want->dacl_sbz2);
	KUNIT_EXPECT_EQ(test, (int)sd->sacl, (int)want->sacl);
	KUNIT_EXPECT_EQ(test, sd->part_dropped, want->part_dropped);
	KUNIT_EXPECT_TRUE(test, t_bytes_same(sd->sacl_data, sd->sacl_len,
					     want->sacl_data, want->sacl_len));
	KUNIT_ASSERT_EQ(test, sd->num_aces, want->num_aces);
	for (i = 0; i < sd->num_aces; i++) {
		const struct ksmbd_ace *a = &sd->aces[i], *w = &want->aces[i];

		KUNIT_EXPECT_TRUE_MSG(test, a->type == w->type &&
				      a->flags == w->flags && a->mask == w->mask &&
				      t_sid_same(a->sid, w->sid), "ACE %u", i);
		KUNIT_EXPECT_TRUE_MSG(test, t_bytes_same(a->obj, a->obj_len,
							 w->obj, w->obj_len),
				      "object section of ACE %u", i);
		KUNIT_EXPECT_TRUE_MSG(test, t_bytes_same(a->data, a->data_len,
							 w->data, w->data_len),
				      "data of ACE %u", i);
	}
}

/*
 * Decode base_sd and compare the result with t_base_fields(). Then encode
 * the struct of t_base_fields(), which no decoder made, and compare the
 * bytes with base_sd.
 */
static void ksmbd_sd_decode_encode_base_test(struct kunit *test)
{
	struct ksmbd_sd *want = t_base_fields(test);

	t_expect_same(test, t_decode(test, base_sd, sizeof(base_sd)), want);
	t_expect_encoding(test, want, base_sd, sizeof(base_sd));
}

/*
 * base_sd in another layout that MS-DTYP 2.4.6 allows. The parts are in
 * the order SACL, DACL, owner, and group, with unused bytes between them
 * and after the last ACE of the DACL, and the DACL has revision 2 although
 * it holds an object ACE. It decodes to the same SD as base_sd.
 */
static const u8 base_other_layout[] = {
	/*
	 * the header: Control SR|DI|SP|DP, owner at 205, group at 241, SACL
	 * at 20, DACL at 71
	 */
	0x01, 0x00, 0x14, 0x84, 0xcd, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00,
	0x14, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00,
	/* the SACL: revision 2, 48 bytes, 2 ACEs */
	0x02, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00,
	/* audit, 0x80, 20 bytes, 0x10000, S-1-1-0 */
	0x02, 0x80, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* mandatory label, 20 bytes, 0x1, S-1-16-8192 */
	0x11, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00,
	/* 3 unused bytes */
	0xa5, 0xa5, 0xa5,
	/* the DACL: revision 2, 134 bytes, 4 ACEs */
	0x02, 0x00, 0x86, 0x00, 0x04, 0x00, 0x00, 0x00,
	/* allow, OI|CI, 36 bytes, 0x1f01ff, S-1-5-21-1-2-3-1000 */
	0x00, 0x03, 0x24, 0x00, 0xff, 0x01, 0x1f, 0x00, 0x01, 0x05, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	/* deny, 20 bytes, 0x2, S-1-1-0 */
	0x01, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* allow object, 40 bytes, 0x10, Flags 1 and a GUID, S-1-1-0 */
	0x05, 0x00, 0x28, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	/* allow callback, 24 bytes, 0x1, S-1-1-0, 4 bytes of data */
	0x09, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/* 6 unused bytes of the DACL */
	0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
	/* the owner S-1-5-21-1-2-3-1000 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00,
	/* 8 unused bytes */
	0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
	/* the group S-1-5-21-1-2-3-513 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x00, 0x00,
	/* 5 unused bytes */
	0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
};

/*
 * DACL_PRESENT with no DACL, and OWNER_DEFAULTED and GROUP_DEFAULTED with no
 * SID
 */
static const u8 null_dacl_sd[] = {
	/*
	 * the header: Control SR|DP|GD|OD, no owner, no group, no SACL, no
	 * DACL
	 */
	0x01, 0x00, 0x07, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* No DACL, an owner, a nonzero Sbz1, and every Control bit that is kept */
static const u8 no_dacl_sd[] = {
	/*
	 * the header: Control 0xffeb, Sbz1 0x5a, owner at 20, no group, no
	 * SACL, no DACL
	 */
	0x01, 0x5a, 0xeb, 0xff, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* the owner S-1-5-21-1-2-3-1000 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00,
};

/* A group, a DACL with no ACE, and SACL_PRESENT with no SACL */
static const u8 empty_dacl_sd[] = {
	/*
	 * the header: Control SR|SP|DP, no owner, group at 20, no SACL,
	 * DACL at 48
	 */
	0x01, 0x00, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
	/* the group S-1-5-21-1-2-3-513 */
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x00, 0x00,
	/* the DACL: revision 2, 8 bytes, 0 ACEs */
	0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * An owner and a group with 15 sub-authorities each, ACEs whose SIDs have
 * none and 15, and an empty SACL with two unused bytes
 */
static const u8 sids_sd[] = {
	/*
	 * the header: Control SR|SP|DP, owner at 20, group at 88, SACL at
	 * 256, DACL at 156
	 */
	0x01, 0x00, 0x14, 0x80, 0x14, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00,
	/* the owner S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15 */
	0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
	0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
	0x0e, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
	/* the group S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15 */
	0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
	0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
	0x0e, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
	/* the DACL: revision 2, 100 bytes, 2 ACEs */
	0x02, 0x00, 0x64, 0x00, 0x02, 0x00, 0x00, 0x00,
	/* allow, 16 bytes, 0x1, S-1-5 */
	0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05,
	/* deny, 76 bytes, 0x2, S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15 */
	0x01, 0x00, 0x4c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
	0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
	0x0f, 0x00, 0x00, 0x00,
	/* the SACL: revision 2, 10 bytes, 0 ACEs */
	0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 2 unused bytes of the SACL */
	0xee, 0xee,
	/* 2 unused bytes */
	0x00, 0x00,
};

/*
 * A plain ACE with data after its SID and with the one AceFlags bit that
 * MS-DTYP 2.4.4.1 does not define (0x20), and nonzero reserved fields in
 * the DACL
 */
static const u8 ace_fields_sd[] = {
	/* the header: Control SR|DP, no owner, no group, no SACL, DACL at 20 */
	0x01, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	/* the DACL: revision 2, 52 bytes, 2 ACEs, Sbz1 7, Sbz2 0x1234 */
	0x02, 0x07, 0x34, 0x00, 0x02, 0x00, 0x34, 0x12,
	/* allow, 0xa0, 24 bytes, 0x120089, S-1-1-0, 4 bytes of data */
	0x00, 0xa0, 0x18, 0x00, 0x89, 0x00, 0x12, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/* deny, CI|IO, 20 bytes, 0x10000, S-1-3-4 */
	0x01, 0x0a, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00,
};

/*
 * The object and callback layouts (MS-DTYP 2.4.4.3 and 2.4.4.5 to 2.4.4.9):
 * object ACEs with no GUID, one GUID of each kind, and both, with and
 * without data
 */
static const u8 layouts_sd[] = {
	/* the header: Control SR|DP, no owner, no group, no SACL, DACL at 20 */
	0x01, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	/* the DACL: revision 4, 220 bytes, 6 ACEs */
	0x04, 0x00, 0xdc, 0x00, 0x06, 0x00, 0x00, 0x00,
	/* deny object, 24 bytes, 0x1, Flags 0 and no GUID, S-1-3-4 */
	0x06, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00,
	/*
	 * allow callback object, 60 bytes, 0x2, Flags 3 and two GUIDs,
	 * S-1-1-0, 4 bytes of data
	 */
	0x0b, 0x00, 0x3c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/* deny callback, 24 bytes, 0x4, S-1-1-0, 4 bytes of data */
	0x0a, 0x00, 0x18, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/*
	 * deny callback object, 28 bytes, 0x8, Flags 0 and no GUID,
	 * S-1-1-0, 4 bytes of data
	 */
	0x0c, 0x00, 0x1c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x61, 0x72, 0x74, 0x78,
	/*
	 * allow object, 56 bytes, 0x10, Flags 2 and a GUID,
	 * S-1-5-21-1-2-3-1000
	 */
	0x05, 0x00, 0x38, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
	0x4c, 0x4d, 0x4e, 0x4f, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	/* allow, 20 bytes, 0x20, S-1-3-4 */
	0x00, 0x00, 0x14, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00,
};

/*
 * The seven ACE types meant for a SACL (MS-DTYP 2.4.4.10 to 2.4.4.16), in a
 * DACL
 */
static const u8 sacl_types_sd[] = {
	/* the header: Control SR|DP, no owner, no group, no SACL, DACL at 20 */
	0x01, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	/* the DACL: revision 4, 184 bytes, 7 ACEs */
	0x04, 0x00, 0xb8, 0x00, 0x07, 0x00, 0x00, 0x00,
	/* audit, 0xc0, 20 bytes, 0x10000, S-1-1-0 */
	0x02, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* audit object, 40 bytes, 0x1, Flags 2 and a GUID, S-1-1-0 */
	0x07, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
	0x4c, 0x4d, 0x4e, 0x4f, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	/* audit callback, 24 bytes, 0x1, S-1-1-0, 4 bytes of data */
	0x0d, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/*
	 * audit callback object, 28 bytes, 0x1, Flags 0 and no GUID,
	 * S-1-1-0, 4 bytes of data
	 */
	0x0f, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x61, 0x72, 0x74, 0x78,
	/* resource attribute, 24 bytes, 0x0, S-1-1-0, 4 bytes of data */
	0x12, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x74, 0x78,
	/* scoped policy, 20 bytes, 0x0, S-1-17-9 */
	0x13, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x11, 0x09, 0x00, 0x00, 0x00,
	/* mandatory label, 20 bytes, 0x7, S-1-16-28672 */
	0x11, 0x00, 0x14, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x70, 0x00, 0x00,
};

/*
 * An SD the decoder accepts, with the states and ACE count it decodes to.
 * The SDs are rows of a table so that one test function runs for each and
 * KUnit reports each as its own case, by name.
 */
struct t_accept {
	const char *name;
	const u8 *sd;
	size_t	len;
	/* What the encoder writes for it, if not the same bytes */
	const u8 *encoded;
	size_t	encoded_len;
	u8	dacl, sacl;
	u16	num_aces;
};

static const struct t_accept accepts[] = {
	{ .name = "2.4.6 any order and unused bytes, 2.4.5 revision 2",
	  .sd = base_other_layout, .len = sizeof(base_other_layout),
	  .encoded = base_sd, .encoded_len = sizeof(base_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_PRESENT, .num_aces = 4 },
	{ .name = "2.4.6 NULL DACL",
	  .sd = null_dacl_sd, .len = sizeof(null_dacl_sd),
	  .dacl = KSMBD_ACL_NULL, .sacl = KSMBD_ACL_ABSENT, .num_aces = 0 },
	{ .name = "2.4.6 no DACL, every other Control bit",
	  .sd = no_dacl_sd, .len = sizeof(no_dacl_sd),
	  .dacl = KSMBD_ACL_ABSENT, .sacl = KSMBD_ACL_ABSENT, .num_aces = 0 },
	{ .name = "2.4.5 empty DACL, NULL SACL",
	  .sd = empty_dacl_sd, .len = sizeof(empty_dacl_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_NULL, .num_aces = 0 },
	{ .name = "2.4.2.2 0 and 15 sub-authorities, empty SACL",
	  .sd = sids_sd, .len = sizeof(sids_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_PRESENT, .num_aces = 2 },
	{ .name = "2.4.4.1 ACE data, undefined AceFlags, reserved fields",
	  .sd = ace_fields_sd, .len = sizeof(ace_fields_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_ABSENT, .num_aces = 2 },
	{ .name = "2.4.4 object and callback layouts",
	  .sd = layouts_sd, .len = sizeof(layouts_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_ABSENT, .num_aces = 6 },
	{ .name = "2.4.4 SACL types in a DACL",
	  .sd = sacl_types_sd, .len = sizeof(sacl_types_sd),
	  .dacl = KSMBD_ACL_PRESENT, .sacl = KSMBD_ACL_ABSENT, .num_aces = 7 },
};

KUNIT_ARRAY_PARAM_DESC(accept, accepts, name);

/*
 * Each SD is decoded, and the decoded SD is encoded again. The encoder
 * must write the same bytes, or the bytes given for an SD that is not laid
 * out as the encoder lays one out. Nothing the SD holds may be lost on
 * the way.
 */
static void ksmbd_sd_decode_accept_test(struct kunit *test)
{
	const struct t_accept *a = test->param_value;
	struct ksmbd_sd *sd = t_decode(test, a->sd, a->len);

	KUNIT_EXPECT_EQ(test, (int)sd->dacl, a->dacl);
	KUNIT_EXPECT_EQ(test, (int)sd->sacl, a->sacl);
	KUNIT_EXPECT_EQ(test, sd->num_aces, a->num_aces);
	if (a->encoded)
		t_expect_encoding(test, sd, a->encoded, a->encoded_len);
	else
		t_expect_encoding(test, sd, a->sd, a->len);
}

/* What changing one byte of base_sd is expected to do */
enum t_effect {
	REFUSED,	/* the decoder returns -EBADMSG */
	/* The SD decodes without that part, and part_dropped is set */
	NO_OWNER,
	NO_GROUP,
	NO_SACL,
	SACL_UNREAD,	/* the SD decodes without its SACL, which was not read */
	AS_BASE,	/* the SD decodes to base_sd, unchanged */
};

struct t_change {
	const char *name;	/* the change and the MS-DTYP section it breaks */
	u8	off;
	u8	new;
	u8	effect;
};

static const struct t_change changes[] = {
	{ "2.4.6 Revision MUST be 1", O_SD_REVISION, 2, REFUSED },
	{ "2.4.6 OffsetDacl inside the header", O_SD_DACL, 16, REFUSED },
	{ "2.4.6 OffsetDacl past the end", O_SD_DACL + 1, 1, REFUSED },
	{ "2.4.6 OffsetDacl MUST be 0 without DP",
	  O_SD_CONTROL, 0x10, REFUSED },
	{ "2.4.5 DACL AclRevision 3", B_DACL + O_ACL_REVISION, 3, REFUSED },
	{ "2.4.5 DACL AclSize below 8", B_DACL + O_ACL_SIZE, 4, REFUSED },
	{ "2.4.5 DACL AclSize past the end",
	  B_DACL + O_ACL_SIZE + 1, 1, REFUSED },
	{ "2.4.5 DACL AceCount more than fits",
	  B_DACL + O_ACL_COUNT, 8, REFUSED },
	{ "2.4.5 DACL AceCount past its ACEs",
	  B_DACL + O_ACL_COUNT, 5, REFUSED },
	{ "2.4.4.1 AceSize not a multiple of 4", B_ACE3 + O_ACE_SIZE, 23, REFUSED },
	{ "2.4.4.1 AceSize past AclSize", B_ACE3 + O_ACE_SIZE, 28, REFUSED },
	{ "2.4.4.1 AceType above 0x13", B_ACE1 + O_ACE_TYPE, 0x14, REFUSED },
	{ "2.4.4.1 AceType 0x03 reserved", B_ACE1 + O_ACE_TYPE, 0x03, REFUSED },
	{ "2.4.4.1 ACE SID count runs past AceSize",
	  B_ACE1 + 8 + O_SID_COUNT, 2, REFUSED },
	{ "2.4.4.3 object GUIDs past AceSize",
	  B_ACE2 + O_ACE_OBJ_FLAGS, 3, REFUSED },
	{ "2.4.4.3 object ACE too short for its Flags",
	  B_ACE2 + O_ACE_SIZE, 8, REFUSED },
	{ "2.4.4.3 object Flags bit that names no GUID",
	  B_ACE2 + O_ACE_OBJ_FLAGS, 5, REFUSED },

	/* A malformed owner, group, or SACL is left out */
	{ "2.4.6 OffsetOwner past the end", O_SD_OWNER + 1, 1, NO_OWNER },
	{ "2.4.2.2 owner SID Revision MUST be 1",
	  B_OWNER + O_SID_REVISION, 2, NO_OWNER },
	{ "2.4.2.2 owner SID more than 15 sub-authorities",
	  B_OWNER + O_SID_COUNT, 16, NO_OWNER },
	{ "2.4.2.2 group SID Revision MUST be 1",
	  B_GROUP + O_SID_REVISION, 2, NO_GROUP },
	{ "2.4.6 OffsetSacl inside the header", O_SD_SACL, 12, NO_SACL },
	{ "2.4.5 SACL AclRevision 0", B_SACL + O_ACL_REVISION, 0, NO_SACL },
	{ "2.4.4.1 SACL AceSize not a multiple of 4",
	  B_SACE0 + O_ACE_SIZE, 21, NO_SACL },
	/* An OffsetSacl is not read when SACL_PRESENT is clear */
	{ "2.4.6 OffsetSacl set without SP", O_SD_CONTROL, 0x04, SACL_UNREAD },

	/*
	 * Requirements that MS-DTYP states with MUST and the decoder does
	 * not enforce
	 */
	{ "2.4.6 SR not set", O_SD_CONTROL + 1, 0x04, AS_BASE },
};

KUNIT_ARRAY_PARAM_DESC(change, changes, name);

static void ksmbd_sd_decode_byte_change_test(struct kunit *test)
{
	const struct t_change *c = test->param_value;
	struct ksmbd_sd *want = t_base_fields(test);
	u8 *buf = t_base_copy(test);
	struct ksmbd_sd *sd = (void *)1;
	int rc;

	/* A case whose new byte equals the old one would test nothing */
	KUNIT_ASSERT_TRUE(test, buf[c->off] != c->new);
	buf[c->off] = c->new;

	rc = ksmbd_sd_decode(buf, sizeof(base_sd), &sd);
	if (c->effect == REFUSED) {
		KUNIT_EXPECT_EQ(test, rc, -EBADMSG);
		KUNIT_EXPECT_NULL(test, sd);
		if (!rc)
			kvfree(sd);
		return;
	}
	KUNIT_ASSERT_EQ(test, rc, 0);
	t_keep_sd(test, sd);
	want->part_dropped = c->effect == NO_OWNER || c->effect == NO_GROUP ||
			     c->effect == NO_SACL;
	if (c->effect == NO_OWNER)
		want->owner = NULL;
	if (c->effect == NO_GROUP)
		want->group = NULL;
	if (c->effect == NO_SACL || c->effect == SACL_UNREAD) {
		want->sacl = KSMBD_ACL_ABSENT;
		want->sacl_len = 0;
		want->sacl_data = NULL;
	}
	t_expect_same(test, sd, want);
}

/*
 * An owner or a group whose offset points into the header of the SD
 * (MS-DTYP 2.4.6) is left out, even when the bytes there read as a SID. With
 * SACL_PRESENT clear OffsetSacl is not read, so here it is set to 1. The
 * header then holds the bytes of a SID with no sub-authority at offset 12.
 */
static void ksmbd_sd_decode_offset_in_header_test(struct kunit *test)
{
	const size_t len = sizeof(base_sd);
	struct ksmbd_sd *sd = NULL;
	u8 *buf = t_base_copy(test);

	buf[O_SD_CONTROL] &= ~SACL_PRESENT;
	put_unaligned_le32(1, &buf[O_SD_SACL]);
	KUNIT_ASSERT_EQ(test, ksmbd_sd_decode(buf, len, &sd), 0);
	kvfree(sd);

	buf[O_SD_OWNER] = O_SD_SACL;
	KUNIT_ASSERT_EQ(test, ksmbd_sd_decode(buf, len, &sd), 0);
	KUNIT_EXPECT_NULL(test, sd->owner);
	KUNIT_EXPECT_NOT_NULL(test, sd->group);
	KUNIT_EXPECT_TRUE(test, sd->part_dropped);
	kvfree(sd);

	buf[O_SD_OWNER] = B_OWNER;
	buf[O_SD_GROUP] = O_SD_SACL;
	KUNIT_ASSERT_EQ(test, ksmbd_sd_decode(buf, len, &sd), 0);
	KUNIT_EXPECT_NOT_NULL(test, sd->owner);
	KUNIT_EXPECT_NULL(test, sd->group);
	KUNIT_EXPECT_TRUE(test, sd->part_dropped);
	kvfree(sd);

	/* An SD shorter than its header is refused */
	KUNIT_EXPECT_EQ(test, ksmbd_sd_decode(buf, O_SD_HDR_LEN - 1, &sd), -EBADMSG);
}

/* Returns an SD with one ACE, which the encoder accepts */
static struct ksmbd_sd *t_one_ace(struct kunit *test)
{
	struct ksmbd_sd *sd = t_alloc(test, 1);

	sd->dacl = KSMBD_ACL_PRESENT;
	sd->aces[0] = (struct ksmbd_ace){
		.type = ACCESS_DENIED_ACE_TYPE, .flags = 0x13, .mask = 0x1f01ff,
		.sid = &everyone,
	};
	KUNIT_ASSERT_EQ(test, t_try_encode(test, sd), 0);
	return sd;
}

/* Makes one change to an SD the encoder accepts, and expects -EINVAL */
#define T_REFUSES(what, change)						\
	do {								\
		struct ksmbd_sd *sd = t_one_ace(test);			\
		struct ksmbd_ace *ace = &sd->aces[0];			\
									\
		(void)ace;						\
		change;							\
		KUNIT_EXPECT_EQ_MSG(test, t_try_encode(test, sd), -EINVAL, what); \
	} while (0)

/*
 * The encoder returns -EINVAL for a struct ksmbd_sd that would encode to a
 * malformed SD. Each T_REFUSES line makes one such change to a valid SD.
 */
static void ksmbd_sd_encode_refuse_test(struct kunit *test)
{
	static const u8 flags_undefined[4] = { 4 }, flags_one_guid[4] = { 1 };
	static const u8 acl_rev3[8] = { 3, 0, 8 }, acl_and_more[12] = { 2, 0, 8 };
	static const u8 data[4];
	struct smb_sid rev2 = { .revision = 2, .num_subauth = 1 };
	struct smb_sid sub16 = { .revision = 1, .num_subauth = 16 };

	T_REFUSES("a Control bit the encoder derives", sd->control = DACL_PRESENT);
	T_REFUSES("an owner SID of revision 2", sd->owner = &rev2);
	T_REFUSES("a group SID of 16 sub-authorities", sd->group = &sub16);
	T_REFUSES("a DACL state that is not one of the three", sd->dacl = 3);
	T_REFUSES("ACEs with a NULL DACL", sd->dacl = KSMBD_ACL_NULL);
	T_REFUSES("a DACL revision of 3", sd->dacl_revision = 3);
	T_REFUSES("a SACL state that is not one of the three", sd->sacl = 3);
	T_REFUSES("SACL bytes with no SACL",
		  sd->sacl_data = acl_and_more; sd->sacl_len = 8);
	T_REFUSES("a SACL with no bytes", sd->sacl = KSMBD_ACL_PRESENT);
	T_REFUSES("a SACL that the decoder would refuse",
		  sd->sacl = KSMBD_ACL_PRESENT; sd->sacl_data = acl_rev3;
		  sd->sacl_len = sizeof(acl_rev3));
	T_REFUSES("bytes after the SACL",
		  sd->sacl = KSMBD_ACL_PRESENT; sd->sacl_data = acl_and_more;
		  sd->sacl_len = sizeof(acl_and_more));

	T_REFUSES("an ACE type with no layout", ace->type = 0x03);
	T_REFUSES("an ACE with no SID", ace->sid = NULL);
	T_REFUSES("an ACE SID of revision 2", ace->sid = &rev2);
	T_REFUSES("ACE data that is not a multiple of 4 bytes",
		  ace->data = data; ace->data_len = 3);
	T_REFUSES("an ACE data length with no data", ace->data_len = 4);
	T_REFUSES("an object section in an ACE that is not an object ACE",
		  ace->obj = flags_one_guid; ace->obj_len = 4);
	T_REFUSES("an object ACE with no object section",
		  ace->type = ACCESS_ALLOWED_OBJECT_ACE_TYPE; ace->obj_len = 20);
	T_REFUSES("an object ACE with an undefined flag",
		  ace->type = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
		  ace->obj = flags_undefined; ace->obj_len = 4);
	T_REFUSES("an object section shorter than its Flags say",
		  ace->type = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
		  ace->obj = flags_one_guid; ace->obj_len = 4);
}

#define T_MAX_ACES	((U16_MAX - 8) / 16)

/*
 * AclSize is 16 bits wide (MS-DTYP 2.4.5), so a DACL holds at most U16_MAX
 * bytes, and at most 4095 ACEs since the smallest ACE is 16 bytes. The decoder
 * accepts a DACL of 4095 ACEs and the encoder writes it again. The encoder
 * refuses a DACL with one ACE more, which would be too large.
 */
static void ksmbd_sd_decode_encode_max_dacl_test(struct kunit *test)
{
	const size_t n = T_MAX_ACES, len = O_SD_HDR_LEN + U16_MAX;
	struct ksmbd_sd *sd = NULL, *more;
	size_t i;
	u8 *buf;

	/*
	 * A DACL of 4095 ACEs whose SIDs have no sub-authority, followed by
	 * 7 unused bytes
	 */
	buf = kunit_kzalloc(test, len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	buf[O_SD_REVISION] = 1;
	put_unaligned_le16(SELF_RELATIVE | DACL_PRESENT, &buf[O_SD_CONTROL]);
	put_unaligned_le32(O_SD_HDR_LEN, &buf[O_SD_DACL]);
	buf[O_SD_HDR_LEN + O_ACL_REVISION] = 2;
	put_unaligned_le16(U16_MAX, &buf[O_SD_HDR_LEN + O_ACL_SIZE]);
	put_unaligned_le16(n, &buf[O_SD_HDR_LEN + O_ACL_COUNT]);
	for (i = 0; i < n; i++) {
		u8 *ace = &buf[O_SD_HDR_LEN + O_ACL_HDR_LEN + 16 * i];

		put_unaligned_le16(16, &ace[O_ACE_SIZE]);
		put_unaligned_le32(i + 1, &ace[O_ACE_MASK]);
		ace[8 + O_SID_REVISION] = 1;
		ace[8 + O_SID_AUTHORITY] = 5;
	}
	sd = t_decode(test, buf, len);
	KUNIT_ASSERT_EQ(test, sd->num_aces, n);
	KUNIT_EXPECT_EQ(test, sd->aces[n - 1].mask, n);
	KUNIT_EXPECT_EQ(test, t_try_encode(test, sd), 0);
	/* One ACE more makes the DACL too large for the encoder */
	more = t_alloc(test, n + 1);
	more->dacl = KSMBD_ACL_PRESENT;
	memcpy(more->aces, sd->aces, flex_array_size(sd, aces, n));
	more->aces[n] = sd->aces[0];
	KUNIT_EXPECT_EQ(test, t_try_encode(test, more), -E2BIG);
	more->num_aces = n;
	KUNIT_EXPECT_EQ(test, t_try_encode(test, more), 0);
}

static struct kunit_case ksmbd_secdesc_test_cases[] = {
	KUNIT_CASE(ksmbd_sd_decode_encode_base_test),
	KUNIT_CASE_PARAM(ksmbd_sd_decode_accept_test, accept_gen_params),
	KUNIT_CASE_PARAM(ksmbd_sd_decode_byte_change_test, change_gen_params),
	KUNIT_CASE(ksmbd_sd_decode_offset_in_header_test),
	KUNIT_CASE(ksmbd_sd_encode_refuse_test),
	KUNIT_CASE(ksmbd_sd_decode_encode_max_dacl_test),
	{}
};

static struct kunit_suite ksmbd_secdesc_test_suite = {
	.name = "ksmbd_secdesc",
	.test_cases = ksmbd_secdesc_test_cases,
};

kunit_test_suite(ksmbd_secdesc_test_suite);

MODULE_DESCRIPTION("KUnit tests for the ksmbd security descriptor codec");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
