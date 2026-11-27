// SPDX-License-Identifier: GPL-2.0-or-later
/* Security descriptor decoder and encoder (MS-DTYP 2.4.6) */

#include <linux/align.h>
#include <linux/array_size.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/uuid.h>
#include <asm/byteorder.h>
#include <kunit/visibility.h>

#include "glob.h"
#include "smbacl.h"
#include "secdesc.h"

/*
 * The 16-bit revision field of struct smb_ntsd and of struct smb_acl holds
 * the Revision byte in its low half and the Sbz1 byte in its high half.
 */
#define SD_REVISION_MASK	0xff
#define SD_SBZ1_SHIFT		8

/* The part of an ACE before its SID, or before its object section */
#define SD_ACE_HDR_SIZE		offsetof(struct smb_ace, sid)
#define SD_ACE_MIN_SIZE		(SD_ACE_HDR_SIZE + CIFS_SID_BASE_SIZE)

#define SD_SID_REVISION		1
#define SD_ACL_REVISION		2
#define SD_ACL_REVISION_DS	4

#define SD_ALIGN		4

/* Control bits that the encoder sets from the SD, not from sd->control */
#define SD_CONTROL_DERIVED	(SELF_RELATIVE | DACL_PRESENT | SACL_PRESENT)

/*
 * An encoded SID is 8 bytes plus 4 bytes per sub-authority, but struct
 * smb_sid always has room for 15 sub-authorities. The decoder pads its
 * allocation by the difference, so that a short SID at the end of the
 * allocation can be read through a struct smb_sid pointer without going
 * out of bounds.
 */
#define SD_SID_SLACK	(sizeof(struct smb_sid) - CIFS_SID_BASE_SIZE)

/*
 * The Flags of an object ACE (MS-DTYP 2.4.4.3). Each one says that a GUID
 * is present before the SID.
 */
#define ACE_OBJECT_TYPE_PRESENT			0x1
#define ACE_INHERITED_OBJECT_TYPE_PRESENT	0x2
#define SD_OBJ_GUID_FLAGS \
	(ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT)

enum sd_ace_layout {
	SD_ACE_NONE,
	SD_ACE_PLAIN,
	SD_ACE_OBJECT,
};

struct sd_in {
	const u8 *p __counted_by_ptr(len);
	size_t len;
};

struct sd_parsed {
	u16 control;
	u8 sbz1;
	struct sd_in owner;
	struct sd_in group;
	enum ksmbd_acl_state dacl_state;
	struct sd_in dacl;
	struct smb_acl dacl_hdr;
	enum ksmbd_acl_state sacl_state;
	struct sd_in sacl;
	bool part_dropped;
};

struct sd_writer {
	u8 *p __counted_by_ptr(cap);
	size_t cap;
	size_t pos;
	bool bad;
};

struct sd_layout {
	bool object;
	/* Each offset is 0 if the SD does not have that part */
	size_t owner_off, group_off, dacl_off, sacl_off;
	size_t dacl_size;
	size_t total;
};

/*
 * Every ACE type that MS-DTYP defines a structure for (2.4.4.2 to
 * 2.4.4.16). The types meant for a SACL are included because a client can
 * put them in a DACL, and ksmbd has always accepted a DACL that has them.
 */
static const u8 sd_ace_layouts[] = {
	[ACCESS_ALLOWED_ACE_TYPE]		  = SD_ACE_PLAIN,
	[ACCESS_DENIED_ACE_TYPE]		  = SD_ACE_PLAIN,
	[SYSTEM_AUDIT_ACE_TYPE]			  = SD_ACE_PLAIN,
	[ACCESS_ALLOWED_OBJECT_ACE_TYPE]	  = SD_ACE_OBJECT,
	[ACCESS_DENIED_OBJECT_ACE_TYPE]		  = SD_ACE_OBJECT,
	[SYSTEM_AUDIT_OBJECT_ACE_TYPE]		  = SD_ACE_OBJECT,
	[ACCESS_ALLOWED_CALLBACK_ACE_TYPE]	  = SD_ACE_PLAIN,
	[ACCESS_DENIED_CALLBACK_ACE_TYPE]	  = SD_ACE_PLAIN,
	[ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE] = SD_ACE_OBJECT,
	[ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE]  = SD_ACE_OBJECT,
	[SYSTEM_AUDIT_CALLBACK_ACE_TYPE]	  = SD_ACE_PLAIN,
	[SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE]	  = SD_ACE_OBJECT,
	[SYSTEM_MANDATORY_LABEL_ACE_TYPE]	  = SD_ACE_PLAIN,
	[SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE]	  = SD_ACE_PLAIN,
	[SYSTEM_SCOPED_POLICY_ID_ACE_TYPE]	  = SD_ACE_PLAIN,
};

static enum sd_ace_layout sd_ace_layout(u8 type)
{
	return type < ARRAY_SIZE(sd_ace_layouts) ? sd_ace_layouts[type] :
						   SD_ACE_NONE;
}

static size_t sd_sid_len(unsigned int num_subauth)
{
	return CIFS_SID_BASE_SIZE + num_subauth * sizeof(__le32);
}

/*
 * In an object ACE, the mask is followed by a Flags field, then by an
 * ObjectType GUID if ACE_OBJECT_TYPE_PRESENT is set, then by an
 * InheritedObjectType GUID if ACE_INHERITED_OBJECT_TYPE_PRESENT is set, and
 * then by the SID (MS-DTYP 2.4.4.3). Returns the size of what lies between
 * the mask and the SID, which is the Flags field and the GUIDs.
 */
static size_t sd_obj_len(u32 obj_flags)
{
	unsigned int num_guids = hweight32(obj_flags & SD_OBJ_GUID_FLAGS);

	return sizeof(obj_flags) + num_guids * sizeof(guid_t);
}

static const u8 *sd_in_at(const struct sd_in *input, size_t off, size_t len)
{
	if (!len || off > input->len || len > input->len - off)
		return NULL;
	return input->p + off;
}

static int sd_malformed(const char *why)
{
	ksmbd_debug(SMB, "malformed security descriptor: %s\n", why);
	return -EBADMSG;
}

/* On success, *@sid points to the SID at @off */
static int sd_check_sid(const struct sd_in *input, size_t off,
			const struct smb_sid **sid)
{
	const struct smb_sid *candidate;

	candidate = (const void *)sd_in_at(input, off, CIFS_SID_BASE_SIZE);
	if (!candidate)
		return sd_malformed("SID out of bounds");
	if (candidate->revision != SD_SID_REVISION)
		return sd_malformed("SID revision is not 1");
	if (candidate->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return sd_malformed("SID has more than 15 sub-authorities");
	if (!sd_in_at(input, off, sd_sid_len(candidate->num_subauth)))
		return sd_malformed("SID out of bounds");
	*sid = candidate;
	return 0;
}

/*
 * Validates the ACE at @pos and returns its size in *@size. If @out is not
 * NULL, the ACE is decoded into it, and its pointers point into @aces.
 * This is forced inline because the decoder calls it once for every ACE.
 */
static __always_inline int
sd_parse_ace(const struct sd_in *aces, size_t pos, struct ksmbd_ace *out,
	     size_t *size)
{
	size_t len, end, off = SD_ACE_HDR_SIZE;
	enum sd_ace_layout layout;
	const struct smb_sid *sid;
	struct sd_in ace;
	const u8 *p;
	int rc;

	p = sd_in_at(aces, pos, SD_ACE_HDR_SIZE);
	if (!p)
		return sd_malformed("ACE count exceeds ACL size");
	len = get_unaligned_le16(&p[offsetof(struct smb_ace, size)]);
	if (len % SD_ALIGN)
		return sd_malformed("ACE size not a multiple of 4");
	if (!sd_in_at(aces, pos, len))
		return sd_malformed("ACE out of bounds");
	ace = (struct sd_in){ .len = len, .p = p };
	layout = sd_ace_layout(p[offsetof(struct smb_ace, type)]);
	if (layout == SD_ACE_NONE)
		return sd_malformed("unknown ACE type");

	if (layout == SD_ACE_OBJECT) {
		u32 obj_flags;

		p = sd_in_at(&ace, off, sizeof(obj_flags));
		if (!p)
			return sd_malformed("object ACE flags out of bounds");
		obj_flags = get_unaligned_le32(p);
		if (obj_flags & ~(u32)SD_OBJ_GUID_FLAGS)
			return sd_malformed("undefined object ACE flags");
		off += sd_obj_len(obj_flags);
	}

	rc = sd_check_sid(&ace, off, &sid);
	if (rc)
		return rc;
	*size = len;
	if (!out)
		return 0;

	end = off + sd_sid_len(sid->num_subauth);
	*out = (struct ksmbd_ace){
		.type = ace.p[offsetof(struct smb_ace, type)],
		.flags = ace.p[offsetof(struct smb_ace, flags)],
		.mask = get_unaligned_le32(&ace.p[offsetof(struct smb_ace, access_req)]),
		.sid = sid,
		.obj_len = off - SD_ACE_HDR_SIZE,
		.data_len = len - end,
		.obj = off > SD_ACE_HDR_SIZE ? &ace.p[SD_ACE_HDR_SIZE] : NULL,
		.data = len > end ? &ace.p[end] : NULL,
	};
	return 0;
}

static int sd_parse_acl(const struct sd_in *src, size_t off,
			struct sd_in *acl, struct smb_acl *hdr)
{
	const u8 *p = sd_in_at(src, off, sizeof(*hdr));
	unsigned int size, rev;

	if (!p)
		return sd_malformed("ACL header out of bounds");
	memcpy(hdr, p, sizeof(*hdr));
	rev = le16_to_cpu(hdr->revision) & SD_REVISION_MASK;
	if (rev != SD_ACL_REVISION && rev != SD_ACL_REVISION_DS)
		return sd_malformed("ACL revision is not 2 or 4");
	size = le16_to_cpu(hdr->size);
	if (size < sizeof(*hdr) || !sd_in_at(src, off, size))
		return sd_malformed("ACL size out of bounds");
	if (le16_to_cpu(hdr->num_aces) > (size - sizeof(*hdr)) / SD_ACE_MIN_SIZE)
		return sd_malformed("ACE count exceeds ACL size");
	*acl = (struct sd_in){ .len = size, .p = p };
	return 0;
}

static struct sd_in sd_acl_aces(const struct sd_in *acl)
{
	struct sd_in aces = { .len = acl->len - sizeof(struct smb_acl) };

	aces.p = sd_in_at(acl, sizeof(struct smb_acl), aces.len);
	return aces;
}

/*
 * Validates an ACL without decoding it. This is for the SACL, which is kept
 * as raw bytes.
 */
static int sd_check_acl(const struct sd_in *src)
{
	struct sd_in acl, aces;
	size_t pos = 0, size;
	struct smb_acl hdr;
	unsigned int i;
	int rc;

	rc = sd_parse_acl(src, 0, &acl, &hdr);
	if (rc)
		return rc;
	aces = sd_acl_aces(&acl);
	for (i = 0; i < le16_to_cpu(hdr.num_aces); i++) {
		rc = sd_parse_ace(&aces, pos, NULL, &size);
		if (rc)
			return rc;
		pos += size;
	}
	return 0;
}

static int sd_parse_sid_at(const struct sd_in *src, size_t off,
			   struct sd_in *sid)
{
	const struct smb_sid *checked;
	int rc;

	rc = sd_check_sid(src, off, &checked);
	if (!rc)
		*sid = (struct sd_in){ .len = sd_sid_len(checked->num_subauth),
				       .p = (const u8 *)checked };
	return rc;
}

static void sd_parse_owner_or_group(const struct sd_in *src, u32 off,
				    struct sd_parsed *parsed,
				    struct sd_in *sid)
{
	if (!off)
		return;
	if (off < sizeof(struct smb_ntsd)) {
		sd_malformed("owner or group offset inside header");
		parsed->part_dropped = true;
	} else if (sd_parse_sid_at(src, off, sid)) {
		parsed->part_dropped = true;
	}
}

static int sd_parse_header(const struct sd_in *src,
			   struct sd_parsed *parsed)
{
	const u8 *p = sd_in_at(src, 0, sizeof(struct smb_ntsd));
	u32 owner, group, dacl, sacl;
	struct smb_acl sacl_hdr;
	struct smb_ntsd hdr;
	u16 rev;
	int rc;

	if (!p)
		return sd_malformed("header out of bounds");
	memcpy(&hdr, p, sizeof(hdr));
	rev = le16_to_cpu(hdr.revision);
	if ((rev & SD_REVISION_MASK) != SD_REVISION)
		return sd_malformed("revision is not 1");
	parsed->sbz1 = rev >> SD_SBZ1_SHIFT;
	parsed->control = le16_to_cpu(hdr.type);
	owner = le32_to_cpu(hdr.osidoffset);
	group = le32_to_cpu(hdr.gsidoffset);
	dacl = le32_to_cpu(hdr.dacloffset);
	if (dacl && dacl < sizeof(hdr))
		return sd_malformed("DACL offset inside header");

	/*
	 * A malformed owner, group, or SACL does not fail the decode. The SD
	 * is decoded without that part and part_dropped is set.
	 */
	sd_parse_owner_or_group(src, owner, parsed, &parsed->owner);
	sd_parse_owner_or_group(src, group, parsed, &parsed->group);

	/*
	 * A nonzero OffsetDacl with DACL_PRESENT clear is refused, because
	 * the two fields disagree about whether the SD has a DACL (MS-DTYP
	 * 2.4.6).
	 */
	if (!(parsed->control & DACL_PRESENT)) {
		if (dacl)
			return sd_malformed("DACL offset without DACL_PRESENT");
	} else if (!dacl) {
		parsed->dacl_state = KSMBD_ACL_NULL;
	} else {
		parsed->dacl_state = KSMBD_ACL_PRESENT;
		rc = sd_parse_acl(src, dacl, &parsed->dacl, &parsed->dacl_hdr);
		if (rc)
			return rc;
	}

	/*
	 * OffsetSacl is ignored when SACL_PRESENT is clear, as ksmbd has
	 * always done.
	 */
	sacl = le32_to_cpu(hdr.sacloffset);
	if (!(parsed->control & SACL_PRESENT))
		return 0;
	if (!sacl) {
		parsed->sacl_state = KSMBD_ACL_NULL;
	} else if (sacl < sizeof(hdr)) {
		sd_malformed("SACL offset inside header");
		parsed->part_dropped = true;
	} else if (sd_parse_acl(src, sacl, &parsed->sacl, &sacl_hdr)) {
		parsed->part_dropped = true;
	} else {
		parsed->sacl_state = KSMBD_ACL_PRESENT;
	}
	return 0;
}

/*
 * Copies the ACEs of the DACL to @kept and decodes the copy, so that the
 * bytes that were validated are the bytes the SD keeps.
 */
static int sd_decode_dacl(struct ksmbd_sd *sd,
			  const struct sd_parsed *parsed,
			  const struct sd_in *wire, u8 *kept)
{
	struct sd_in aces = { .len = wire->len, .p = kept };
	u16 rev = le16_to_cpu(parsed->dacl_hdr.revision);
	size_t pos = 0, size;
	bool object = false;
	unsigned int i;
	int rc;

	if (wire->len)
		memcpy(kept, wire->p, wire->len);
	for (i = 0; i < sd->num_aces; i++) {
		rc = sd_parse_ace(&aces, pos, &sd->aces[i], &size);
		if (rc)
			return rc;
		if (sd->aces[i].obj_len)
			object = true;
		pos += size;
	}
	/* A DACL that contains an object ACE has revision 4 (MS-DTYP 2.4.5) */
	sd->dacl_revision = object ? SD_ACL_REVISION_DS : rev & SD_REVISION_MASK;
	sd->dacl_sbz1 = rev >> SD_SBZ1_SHIFT;
	sd->dacl_sbz2 = le16_to_cpu(parsed->dacl_hdr.reserved);
	return 0;
}

static const struct smb_sid *sd_keep_sid(const struct sd_in *sid, u8 *kept)
{
	if (!sid->len)
		return NULL;
	return memcpy(kept, sid->p, sid->len);
}

/**
 * ksmbd_sd_decode() - decode a self-relative security descriptor
 * @buf:	the encoded SD, which must not change during the call
 * @len:	the length of @buf in bytes
 * @out:	set to the decoded SD on success and to NULL on error. The
 *		caller frees it with kvfree().
 *
 * The SD is read as self-relative whether or not SELF_RELATIVE is set in
 * its Control field. ksmbd has stored SDs with the bit clear, and those
 * must still decode.
 *
 * The decoded SD is a single allocation, and every pointer in it points
 * into that allocation and not into @buf.
 *
 * A well-formed SACL is kept as bytes in sacl_data. A malformed owner SID,
 * group SID, or SACL does not fail the decode. In that case only, the
 * decoded SD is without that part and part_dropped is set.
 *
 * Return: 0 on success, -EBADMSG if the header or the DACL is malformed, or
 * -ENOMEM.
 */
int ksmbd_sd_decode(const u8 *buf, size_t len, struct ksmbd_sd **out)
{
	struct ksmbd_sd *sd __free(kvfree) = NULL;
	struct sd_in src = { .len = len, .p = buf };
	struct sd_parsed parsed = {};
	struct sd_in wire = {};
	size_t fixed, kept_len;
	unsigned int num_aces;
	u8 *kept;
	int rc;

	*out = NULL;
	rc = sd_parse_header(&src, &parsed);
	if (rc)
		return rc;
	if (parsed.dacl_state == KSMBD_ACL_PRESENT)
		wire = sd_acl_aces(&parsed.dacl);
	num_aces = le16_to_cpu(parsed.dacl_hdr.num_aces);

	/*
	 * The allocation holds the struct and its array of ACEs, followed by
	 * copies of the owner SID, the group SID, the ACEs of the DACL, and
	 * the SACL.
	 */
	fixed = struct_size(sd, aces, num_aces);
	kept_len = parsed.owner.len + parsed.group.len + wire.len +
		   parsed.sacl.len;
	sd = kvmalloc(size_add(fixed, kept_len + SD_SID_SLACK), KSMBD_DEFAULT_GFP);
	if (!sd)
		return -ENOMEM;
	kept = (u8 *)sd + fixed;
	memset(kept + kept_len, 0, SD_SID_SLACK);

	sd->num_aces = num_aces;
	sd->control = parsed.control & ~SD_CONTROL_DERIVED;
	sd->sbz1 = parsed.sbz1;
	sd->dacl = parsed.dacl_state;
	sd->dacl_revision = 0;
	sd->dacl_sbz1 = 0;
	sd->dacl_sbz2 = 0;
	sd->sacl = parsed.sacl_state;
	sd->sacl_len = 0;
	sd->sacl_data = NULL;
	sd->part_dropped = parsed.part_dropped;

	sd->owner = sd_keep_sid(&parsed.owner, kept);
	kept += parsed.owner.len;
	sd->group = sd_keep_sid(&parsed.group, kept);
	kept += parsed.group.len;
	if (parsed.dacl_state == KSMBD_ACL_PRESENT) {
		rc = sd_decode_dacl(sd, &parsed, &wire, kept);
		if (rc)
			return rc;
	}
	kept += wire.len;
	if (parsed.sacl.len) {
		struct sd_in copy = { .len = parsed.sacl.len, .p = kept };

		memcpy(kept, parsed.sacl.p, parsed.sacl.len);
		if (sd_check_acl(&copy)) {
			sd->sacl = KSMBD_ACL_ABSENT;
			sd->part_dropped = true;
		} else {
			sd->sacl_len = parsed.sacl.len;
			sd->sacl_data = kept;
		}
	}

	*out = no_free_ptr(sd);
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_sd_decode);

/*
 * Appends @len bytes to the output. A write that does not fit sets
 * writer->bad instead, and every later write is skipped.
 */
static void sd_put(struct sd_writer *writer, const void *src, size_t len)
{
	if (!len || writer->bad)
		return;
	if (WARN_ON_ONCE(writer->pos > writer->cap ||
			 len > writer->cap - writer->pos)) {
		writer->bad = true;
		return;
	}
	memcpy(&writer->p[writer->pos], src, len);
	writer->pos += len;
}

static bool sd_sid_fits(const struct smb_sid *sid)
{
	return sid->revision == SD_SID_REVISION &&
	       sid->num_subauth <= SID_MAX_SUB_AUTHORITIES;
}

/*
 * Returns true if the encoder can write @ace. An object ACE must have an
 * object section whose length matches its Flags, and any other ACE must
 * have no object section.
 */
static bool sd_ace_fits(const struct ksmbd_ace *ace)
{
	enum sd_ace_layout layout = sd_ace_layout(ace->type);
	u32 obj_flags;

	if (layout == SD_ACE_NONE || !ace->sid || !sd_sid_fits(ace->sid) ||
	    ace->data_len % SD_ALIGN || (ace->data_len && !ace->data))
		return false;
	if (layout != SD_ACE_OBJECT)
		return !ace->obj_len;
	if (!ace->obj || ace->obj_len < sizeof(obj_flags))
		return false;
	obj_flags = get_unaligned_le32(ace->obj);
	return !(obj_flags & ~(u32)SD_OBJ_GUID_FLAGS) &&
	       ace->obj_len == sd_obj_len(obj_flags);
}

static size_t sd_ace_size(const struct ksmbd_ace *ace)
{
	return SD_ACE_HDR_SIZE + ace->obj_len +
	       sd_sid_len(ace->sid->num_subauth) + ace->data_len;
}

/*
 * Returns true if the SACL bytes are exactly one ACL that the decoder would
 * accept, with nothing after it.
 */
static bool sd_sacl_fits(const struct ksmbd_sd *sd)
{
	struct sd_in sacl = { .len = sd->sacl_len, .p = sd->sacl_data };
	const u8 *p;

	if (!sd->sacl_data || sd_check_acl(&sacl))
		return false;
	p = sd_in_at(&sacl, offsetof(struct smb_acl, size), sizeof(__le16));
	return p && get_unaligned_le16(p) == sd->sacl_len;
}

static int __must_check sd_lay_out(const struct ksmbd_sd *sd,
				   struct sd_layout *layout)
{
	size_t off = sizeof(struct smb_ntsd), dacl_size = sizeof(struct smb_acl);
	unsigned int i;
	size_t size;

	*layout = (struct sd_layout){};
	if (sd->control & SD_CONTROL_DERIVED)
		return -EINVAL;
	if ((sd->owner && !sd_sid_fits(sd->owner)) ||
	    (sd->group && !sd_sid_fits(sd->group)))
		return -EINVAL;
	if (sd->dacl > KSMBD_ACL_PRESENT ||
	    (sd->dacl != KSMBD_ACL_PRESENT && sd->num_aces))
		return -EINVAL;
	if (sd->dacl_revision && sd->dacl_revision != SD_ACL_REVISION &&
	    sd->dacl_revision != SD_ACL_REVISION_DS)
		return -EINVAL;
	if (sd->sacl > KSMBD_ACL_PRESENT ||
	    (sd->sacl != KSMBD_ACL_PRESENT && sd->sacl_len) ||
	    (sd->sacl == KSMBD_ACL_PRESENT && !sd_sacl_fits(sd)))
		return -EINVAL;

	for (i = 0; i < sd->num_aces; i++) {
		const struct ksmbd_ace *ace = &sd->aces[i];

		if (!sd_ace_fits(ace))
			return -EINVAL;
		size = sd_ace_size(ace);
		if (size > U16_MAX - dacl_size)
			return -E2BIG;
		dacl_size += size;
		if (ace->obj_len)
			layout->object = true;
	}
	if (sd->dacl_revision == SD_ACL_REVISION_DS)
		layout->object = true;

	if (sd->owner) {
		layout->owner_off = off;
		off += sd_sid_len(sd->owner->num_subauth);
	}
	if (sd->group) {
		layout->group_off = off;
		off += sd_sid_len(sd->group->num_subauth);
	}
	if (sd->dacl == KSMBD_ACL_PRESENT) {
		layout->dacl_size = dacl_size;
		layout->dacl_off = off;
		off += dacl_size;
	}
	if (sd->sacl == KSMBD_ACL_PRESENT) {
		layout->sacl_off = off;
		off += ALIGN(sd->sacl_len, SD_ALIGN);
	}
	layout->total = off;
	return 0;
}

static void sd_put_header(struct sd_writer *writer, const struct ksmbd_sd *sd,
			  const struct sd_layout *layout)
{
	u16 control = SELF_RELATIVE | sd->control;
	struct smb_ntsd hdr;

	if (sd->dacl != KSMBD_ACL_ABSENT)
		control |= DACL_PRESENT;
	if (sd->sacl != KSMBD_ACL_ABSENT)
		control |= SACL_PRESENT;
	hdr = (struct smb_ntsd){
		.revision = cpu_to_le16(SD_REVISION | sd->sbz1 << SD_SBZ1_SHIFT),
		.type = cpu_to_le16(control),
		.osidoffset = cpu_to_le32(layout->owner_off),
		.gsidoffset = cpu_to_le32(layout->group_off),
		.sacloffset = cpu_to_le32(layout->sacl_off),
		.dacloffset = cpu_to_le32(layout->dacl_off),
	};
	sd_put(writer, &hdr, sizeof(hdr));
}

static void sd_put_ace(struct sd_writer *writer, const struct ksmbd_ace *ace)
{
	size_t sid_len = sd_sid_len(ace->sid->num_subauth);
	size_t size = sd_ace_size(ace);
	u8 *p;

	if (writer->bad)
		return;
	if (WARN_ON_ONCE(writer->pos > writer->cap ||
			 size > writer->cap - writer->pos)) {
		writer->bad = true;
		return;
	}
	p = &writer->p[writer->pos];
	p[offsetof(struct smb_ace, type)] = ace->type;
	p[offsetof(struct smb_ace, flags)] = ace->flags;
	put_unaligned_le16(size, &p[offsetof(struct smb_ace, size)]);
	put_unaligned_le32(ace->mask, &p[offsetof(struct smb_ace, access_req)]);
	p += SD_ACE_HDR_SIZE;
	if (ace->obj_len) {
		memcpy(p, ace->obj, ace->obj_len);
		p += ace->obj_len;
	}
	memcpy(p, ace->sid, sid_len);
	if (ace->data_len)
		memcpy(p + sid_len, ace->data, ace->data_len);
	writer->pos += size;
}

static void sd_put_dacl(struct sd_writer *writer, const struct ksmbd_sd *sd,
			const struct sd_layout *layout)
{
	u16 rev = layout->object ? SD_ACL_REVISION_DS : SD_ACL_REVISION;
	const struct smb_acl acl = {
		.revision = cpu_to_le16(rev | sd->dacl_sbz1 << SD_SBZ1_SHIFT),
		.size = cpu_to_le16(layout->dacl_size),
		.num_aces = cpu_to_le16(sd->num_aces),
		.reserved = cpu_to_le16(sd->dacl_sbz2),
	};
	unsigned int i;

	sd_put(writer, &acl, sizeof(acl));
	for (i = 0; i < sd->num_aces; i++)
		sd_put_ace(writer, &sd->aces[i]);
}

/**
 * ksmbd_sd_encode() - encode a security descriptor
 * @sd:		the SD to encode, which must not change during the call
 * @buf:	set to the encoded SD on success and to NULL on error. The
 *		caller frees it with kvfree().
 * @len:	set to the length of *@buf in bytes on success and to 0 on
 *		error
 *
 * The owner and the group are written if @sd has them. An ACL is written
 * if its state is KSMBD_ACL_PRESENT.
 *
 * The Control field is written as the bits in @sd plus SELF_RELATIVE, plus
 * DACL_PRESENT and SACL_PRESENT for each ACL whose state is not
 * KSMBD_ACL_ABSENT.
 *
 * The DACL is written with revision 4 if it contains an object ACE or if
 * dacl_revision in @sd is 4, and with revision 2 otherwise.
 *
 * Return:
 * * 0 - success
 * * -EINVAL - @sd is not valid. It has a field that is out of range, an ACE
 *   with no SID, a SID, ACE, or SACL that the decoder would refuse, or ACEs
 *   or SACL bytes for an ACL whose state is not KSMBD_ACL_PRESENT.
 * * -E2BIG - the DACL would be larger than U16_MAX bytes
 * * -ENOMEM - the output buffer could not be allocated
 * * -EIO - the bytes written do not match the layout that was computed,
 *   which means a bug in the encoder or a change to @sd during the call.
 *   A warning is logged.
 */
int ksmbd_sd_encode(const struct ksmbd_sd *sd, u8 **buf, size_t *len)
{
	struct sd_layout layout;
	struct sd_writer writer;
	u8 *bytes;
	int rc;

	*buf = NULL;
	*len = 0;
	rc = sd_lay_out(sd, &layout);
	if (rc)
		return rc;
	bytes = kvzalloc(layout.total, KSMBD_DEFAULT_GFP);
	if (!bytes)
		return -ENOMEM;
	writer = (struct sd_writer){ .cap = layout.total, .p = bytes };
	sd_put_header(&writer, sd, &layout);
	if (layout.owner_off)
		sd_put(&writer, sd->owner, sd_sid_len(sd->owner->num_subauth));
	if (layout.group_off)
		sd_put(&writer, sd->group, sd_sid_len(sd->group->num_subauth));
	if (layout.dacl_off)
		sd_put_dacl(&writer, sd, &layout);
	if (layout.sacl_off) {
		sd_put(&writer, sd->sacl_data, sd->sacl_len);
		/* The padding is already zero, because the buffer was zeroed */
		writer.pos = ALIGN(writer.pos, SD_ALIGN);
	}
	if (WARN_ON_ONCE(writer.bad || writer.pos != layout.total)) {
		kvfree(bytes);
		return -EIO;
	}
	*buf = bytes;
	*len = layout.total;
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_sd_encode);
