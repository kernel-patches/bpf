// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/cleanup.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <kunit/visibility.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mnt_idmapping.h>
#include <linux/mount.h>

#include "smbacl.h"
#include "smb_common.h"
#include "server.h"
#include "misc.h"
#include "mgmt/share_config.h"
#include "secdesc.h"

static const struct smb_sid domain = {1, 4, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* security id for everyone/world system group */
static const struct smb_sid creator_owner = {
	1, 1, {0, 0, 0, 0, 0, 3}, {0} };
/* security id for everyone/world system group */
static const struct smb_sid creator_group = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };
/* security id for owner rights */
static const struct smb_sid sid_owner_rights = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(4)} };

/* security id for everyone/world system group */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* security id for Authenticated Users system group */
static const struct smb_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Apple style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct smb_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct smb_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct smb_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * if the two SIDs (roughly equivalent to a UUID for a user or group) are
 * the same returns zero, if they do not match returns non-zero.
 */
int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if (!ctsid || !cwsid)
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		else
			return -1;
	}

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			else
				return -1;
		}
	}

	/* compare all of the subauth values if any */
	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = min(num_sat, num_saw);
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (le32_to_cpu(ctsid->sub_auth[i]) >
				    le32_to_cpu(cwsid->sub_auth[i]))
					return 1;
				else
					return -1;
			}
		}
	}

	return 0; /* sids compare/match */
}

static void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)
{
	int i;

	dst->revision = src->revision;
	dst->num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < NUM_AUTHS; ++i)
		dst->authority[i] = src->authority[i];
	for (i = 0; i < dst->num_subauth; ++i)
		dst->sub_auth[i] = src->sub_auth[i];
}

/*
 * change posix mode to reflect permissions
 * pmode is the existing mode (we only want to overwrite part of this
 * bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007
 */
static umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,
				    int type)
{
	__u32 flags = le32_to_cpu(ace_flags);
	umode_t mode = 0;

	if (flags & GENERIC_ALL) {
		mode = 0777;
		ksmbd_debug(SMB, "all perms\n");
		return mode;
	}

	if ((flags & GENERIC_READ) || (flags & FILE_READ_RIGHTS))
		mode = 0444;
	if ((flags & GENERIC_WRITE) || (flags & FILE_WRITE_RIGHTS)) {
		mode |= 0222;
		if (S_ISDIR(fattr->cf_mode))
			mode |= 0111;
	}
	if ((flags & GENERIC_EXECUTE) || (flags & FILE_EXEC_RIGHTS))
		mode |= 0111;

	if (type == ACCESS_DENIED_ACE_TYPE || type == ACCESS_DENIED_OBJECT_ACE_TYPE)
		mode = ~mode;

	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, mode);

	return mode;
}

/*
 * Generate access flags to reflect permissions mode is the existing mode.
 * This function is called for every ACE in the DACL whose SID matches
 * with either owner or group or everyone.
 */
static void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
				 __u32 *pace_flags)
{
	/* reset access mask */
	*pace_flags = 0x0;

	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */
	mode &= bits_to_use;

	/*
	 * check for R/W/X UGO since we do not know whose flags
	 * is this but we have cleared all the bits sans RWX for
	 * either user or group or other as per bits_to_use
	 */
	if (mode & 0444)
		*pace_flags |= SET_FILE_READ_RIGHTS;
	if (mode & 0222)
		*pace_flags |= FILE_WRITE_RIGHTS;
	if (mode & 0111)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	ksmbd_debug(SMB, "mode: %o, access flags now 0x%x\n",
		    mode, *pace_flags);
}

static void fill_ace_for_sid(struct ksmbd_ace *pntace,
			     const struct smb_sid *psid, int type, int flags,
			     umode_t mode, umode_t bits)
{
	__u32 access_req = 0;

	pntace->type = type;
	pntace->flags = flags;
	mode_to_access_flags(mode, bits, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pntace->mask = access_req;
	pntace->sid = psid;
}

void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
{
	switch (sidtype) {
	case SIDOWNER:
		smb_copy_sid(ssid, &server_conf.domain_sid);
		break;
	case SIDUNIX_USER:
		smb_copy_sid(ssid, &sid_unix_users);
		break;
	case SIDUNIX_GROUP:
		smb_copy_sid(ssid, &sid_unix_groups);
		break;
	case SIDCREATOR_OWNER:
		smb_copy_sid(ssid, &creator_owner);
		return;
	case SIDCREATOR_GROUP:
		smb_copy_sid(ssid, &creator_group);
		return;
	case SIDNFS_USER:
		smb_copy_sid(ssid, &sid_unix_NFS_users);
		break;
	case SIDNFS_GROUP:
		smb_copy_sid(ssid, &sid_unix_NFS_groups);
		break;
	case SIDNFS_MODE:
		smb_copy_sid(ssid, &sid_unix_NFS_mode);
		break;
	default:
		return;
	}

	/* RID */
	ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);
	ssid->num_subauth++;
}

static int sid_to_id(const struct mnt_idmap *idmap,
		     const struct smb_sid *psid, uint sidtype,
		     struct smb_fattr *fattr)
{
	const struct smb_sid *sid_prefix;
	int rc = -EINVAL;

	/*
	 * If we have too many subauthorities, then something is really wrong.
	 * Just return an error.
	 */
	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		pr_err("%s: %u subauthorities is too many!\n",
		       __func__, psid->num_subauth);
		return -EIO;
	}

	if (psid->num_subauth == 0) {
		pr_err("%s: zero subauthorities!\n", __func__);
		return -EIO;
	}

	if (sidtype == SIDOWNER) {
		kuid_t uid;
		uid_t id;

		/* Only the server domain RID has a local uid representation. */
		sid_prefix = &server_conf.domain_sid;
		if (psid->num_subauth != sid_prefix->num_subauth + 1 ||
		    compare_sids(psid, sid_prefix))
			return -EINVAL;

		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		uid = KUIDT_INIT(id);
		uid = from_vfsuid(idmap, &init_user_ns, VFSUIDT_INIT(uid));
		if (uid_valid(uid)) {
			fattr->cf_uid = uid;
			rc = 0;
		}
	} else {
		kgid_t gid;
		gid_t id;

		/* Local gids are represented by S-1-22-2-<gid>. */
		sid_prefix = &sid_unix_groups;
		if (psid->num_subauth != sid_prefix->num_subauth + 1 ||
		    compare_sids(psid, sid_prefix))
			return -EINVAL;

		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		gid = KGIDT_INIT(id);
		gid = from_vfsgid(idmap, &init_user_ns, VFSGIDT_INIT(gid));
		if (gid_valid(gid)) {
			fattr->cf_gid = gid;
			rc = 0;
		}
	}

	return rc;
}

void posix_state_to_acl(struct posix_acl_state *state,
			struct posix_acl_entry *pace)
{
	int i;

	pace->e_tag = ACL_USER_OBJ;
	pace->e_perm = state->owner.allow;
	for (i = 0; i < state->users->n; i++) {
		pace++;
		pace->e_tag = ACL_USER;
		pace->e_uid = state->users->aces[i].uid;
		pace->e_perm = state->users->aces[i].perms.allow;
	}

	pace++;
	pace->e_tag = ACL_GROUP_OBJ;
	pace->e_perm = state->group.allow;

	for (i = 0; i < state->groups->n; i++) {
		pace++;
		pace->e_tag = ACL_GROUP;
		pace->e_gid = state->groups->aces[i].gid;
		pace->e_perm = state->groups->aces[i].perms.allow;
	}

	if (state->users->n || state->groups->n) {
		pace++;
		pace->e_tag = ACL_MASK;
		pace->e_perm = state->mask.allow;
	}

	pace++;
	pace->e_tag = ACL_OTHER;
	pace->e_perm = state->other.allow;
}

int init_acl_state(struct posix_acl_state *state, u16 cnt)
{
	int alloc;

	memset(state, 0, sizeof(struct posix_acl_state));
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't know which, so we allocate
	 * enough space for either:
	 */
	alloc = sizeof(struct posix_ace_state_array)
		+ cnt * sizeof(struct posix_user_ace_state);
	state->users = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->users)
		return -ENOMEM;
	state->groups = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->groups) {
		kfree(state->users);
		return -ENOMEM;
	}
	return 0;
}

void free_acl_state(struct posix_acl_state *state)
{
	kfree(state->users);
	kfree(state->groups);
}

/* Whether two SIDs are the same SID */
static bool smb_sid_equal(const struct smb_sid *a, const struct smb_sid *b)
{
	return a->num_subauth == b->num_subauth && !compare_sids(a, b);
}

static int parse_dacl(const struct mnt_idmap *idmap,
		      struct ksmbd_sd *sd,
		      const struct smb_sid *pownersid,
		      const struct smb_sid *pgrpsid, struct smb_fattr *fattr)
{
	int i, ret;
	u16 num_aces = 0;
	struct ksmbd_ace *ace;
	struct posix_acl_entry *cf_pace, *cf_pdace;
	struct posix_acl_state acl_state, default_acl_state;
	umode_t mode = 0, acl_mode;
	bool owner_found = false, group_found = false, others_found = false;
	bool nfs_mode_found = false;

	num_aces = sd->num_aces;
	if (num_aces <= 0)
		return 0;

	ret = init_acl_state(&acl_state, num_aces);
	if (ret)
		return ret;
	ret = init_acl_state(&default_acl_state, num_aces);
	if (ret) {
		free_acl_state(&acl_state);
		return ret;
	}

	/*
	 * reset rwx permissions for user/group/other.
	 * Also, if num_aces is 0 i.e. DACL has no ACEs,
	 * user/group/other have no permissions
	 */
	for (i = 0; i < num_aces; ++i) {
		ace = &sd->aces[i];
		/* ksmbd maps no object ACE, so an SD that has one is refused */
		if (ace->obj_len || ace->sid->num_subauth == 0) {
			ret = -EINVAL;
			goto out;
		}

		ace->mask = le32_to_cpu(smb_map_generic_desired_access(cpu_to_le32(ace->mask)));

		/* ACEs after an NFS mode ACE do not change the POSIX mapping */
		if (nfs_mode_found)
			continue;

		if (ace->type == ACCESS_ALLOWED &&
		    ace->sid->num_subauth == 3 &&
		    !(compare_sids(ace->sid, &sid_unix_NFS_mode))) {
			fattr->cf_mode =
				le32_to_cpu(ace->sid->sub_auth[2]);
			fattr->cf_posix_mode = true;
			nfs_mode_found = true;
		} else if (pownersid && smb_sid_equal(ace->sid, pownersid)) {
			acl_mode = access_flags_to_mode(fattr,
							cpu_to_le32(ace->mask),
							ace->type);
			acl_mode &= 0700;

			if (!owner_found) {
				mode &= ~(0700);
				mode |= acl_mode;
			}
			owner_found = true;
		} else if ((pgrpsid && smb_sid_equal(ace->sid, pgrpsid)) ||
			   ace->sid->sub_auth[ace->sid->num_subauth - 1] ==
			    DOMAIN_USER_RID_LE) {
			acl_mode = access_flags_to_mode(fattr,
							cpu_to_le32(ace->mask),
							ace->type);
			acl_mode &= 0070;
			if (!group_found) {
				mode &= ~(0070);
				mode |= acl_mode;
			}
			group_found = true;
		} else if (smb_sid_equal(ace->sid, &sid_everyone)) {
			acl_mode = access_flags_to_mode(fattr,
							cpu_to_le32(ace->mask),
							ace->type);
			acl_mode &= 0007;
			if (!others_found) {
				mode &= ~(0007);
				mode |= acl_mode;
			}
			others_found = true;
		} else if (smb_sid_equal(ace->sid, &creator_owner)) {
			continue;
		} else if (smb_sid_equal(ace->sid, &creator_group)) {
			continue;
		} else if (smb_sid_equal(ace->sid, &sid_authusers)) {
			continue;
		} else {
			struct smb_fattr temp_fattr;

			acl_mode = access_flags_to_mode(fattr, cpu_to_le32(ace->mask),
							ace->type);
			temp_fattr.cf_uid = INVALID_UID;
			ret = sid_to_id(idmap, ace->sid, SIDOWNER, &temp_fattr);
			if (ret || uid_eq(temp_fattr.cf_uid, INVALID_UID)) {
				pr_err_ratelimited("%s: Error %d mapping Owner SID to uid\n",
						   __func__, ret);
				continue;
			}

			acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;
			acl_state.users->aces[acl_state.users->n].uid =
				temp_fattr.cf_uid;
			acl_state.users->aces[acl_state.users->n++].perms.allow =
				((acl_mode & 0700) >> 6) | 0004;
			default_acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;
			default_acl_state.users->aces[default_acl_state.users->n].uid =
				temp_fattr.cf_uid;
			default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =
				((acl_mode & 0700) >> 6) | 0004;
		}
	}
	if (fattr->cf_posix_mode) {
		ret = 0;
		goto out;
	}

	if (owner_found) {
		/* The owner must be set to at least read-only. */
		acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;
		acl_state.users->aces[acl_state.users->n].uid = fattr->cf_uid;
		acl_state.users->aces[acl_state.users->n++].perms.allow =
			((mode & 0700) >> 6) | 0004;
		default_acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;
		default_acl_state.users->aces[default_acl_state.users->n].uid =
			fattr->cf_uid;
		default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =
			((mode & 0700) >> 6) | 0004;
	}

	if (group_found) {
		acl_state.group.allow = (mode & 0070) >> 3;
		acl_state.groups->aces[acl_state.groups->n].gid =
			fattr->cf_gid;
		acl_state.groups->aces[acl_state.groups->n++].perms.allow =
			(mode & 0070) >> 3;
		default_acl_state.group.allow = (mode & 0070) >> 3;
		default_acl_state.groups->aces[default_acl_state.groups->n].gid =
			fattr->cf_gid;
		default_acl_state.groups->aces[default_acl_state.groups->n++].perms.allow =
			(mode & 0070) >> 3;
	}

	if (others_found) {
		fattr->cf_mode &= ~(0007);
		fattr->cf_mode |= mode & 0007;

		acl_state.other.allow = mode & 0007;
		default_acl_state.other.allow = mode & 0007;
	}

	if (acl_state.users->n || acl_state.groups->n) {
		acl_state.mask.allow = 0x07;

		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
			fattr->cf_acls =
				posix_acl_alloc(acl_state.users->n +
					acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);
			if (!fattr->cf_acls) {
				ret = -ENOMEM;
				goto out;
			}
			cf_pace = fattr->cf_acls->a_entries;
			posix_state_to_acl(&acl_state, cf_pace);
		}
	}

	if (default_acl_state.users->n || default_acl_state.groups->n) {
		default_acl_state.mask.allow = 0x07;

		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
			fattr->cf_dacls =
				posix_acl_alloc(default_acl_state.users->n +
				default_acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);
			if (!fattr->cf_dacls) {
				ret = -ENOMEM;
				goto out;
			}
			cf_pdace = fattr->cf_dacls->a_entries;
			posix_state_to_acl(&default_acl_state, cf_pdace);
		}
	}
	ret = 0;
out:
	free_acl_state(&acl_state);
	free_acl_state(&default_acl_state);
	return ret;
}

/*
 * Whether a stored ACE is for the principal of a POSIX ACL entry. The entry
 * for uid 0 is shown as S-1-22-1-0. sid_to_id() also maps the server domain
 * SID with RID 0 to uid 0, so a stored ACE with that SID counts as well.
 */
static bool ace_is_for_entry(const struct smb_sid *ace_sid,
			     const struct smb_sid *sid, bool root)
{
	const struct smb_sid *dom = &server_conf.domain_sid;

	if (ace_sid->num_subauth == sid->num_subauth &&
	    !compare_sids(ace_sid, sid))
		return true;

	return root && ace_sid->num_subauth == dom->num_subauth + 1 &&
	       !compare_sids(ace_sid, dom) &&
	       !ace_sid->sub_auth[dom->num_subauth];
}

static void set_posix_acl_entries_dacl(const struct mnt_idmap *idmap,
				       struct ksmbd_sd *sd,
				       struct smb_fattr *fattr, u16 *num_aces,
				       u16 existing_nt_aces, bool had_nt_aces,
				       struct smb_sid *sids)
{
	struct posix_acl_entry *pace;
	struct smb_sid *sid;
	struct ksmbd_ace *ntace;
	int i, j;

	if (!fattr->cf_acls)
		goto posix_default_acl;

	pace = fattr->cf_acls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {
		int flags = 0;
		bool root = false;

		sid = sids++;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;
			unsigned int sid_type = SIDOWNER;

			uid = posix_acl_uid_translate(idmap, pace);
			if (!uid) {
				sid_type = SIDUNIX_USER;
				root = true;
			}
			id_to_sid(uid, sid_type, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = posix_acl_gid_translate(idmap, pace);
			id_to_sid(gid, SIDUNIX_GROUP, sid);
		} else if (pace->e_tag == ACL_OTHER && !had_nt_aces) {
			smb_copy_sid(sid, &sid_everyone);
		} else {
			continue;
		}
		for (j = 0; j < existing_nt_aces; j++) {
			if (ace_is_for_entry(sd->aces[j].sid, sid, root))
				break;
		}
		if (j < existing_nt_aces)
			continue;

		if (S_ISDIR(fattr->cf_mode) && pace->e_tag == ACL_OTHER)
			flags = 0x03;

		ntace = &sd->aces[*num_aces];
		fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED, flags,
				 pace->e_perm, 0777);
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->mask |=
				le32_to_cpu(FILE_DELETE_LE | FILE_DELETE_CHILD_LE);

		if (S_ISDIR(fattr->cf_mode) &&
		    (pace->e_tag == ACL_USER || pace->e_tag == ACL_GROUP)) {
			ntace = &sd->aces[*num_aces];
			fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,
					 0x03, pace->e_perm, 0777);
			(*num_aces)++;
			if (pace->e_tag == ACL_USER)
				ntace->mask |=
					le32_to_cpu(FILE_DELETE_LE | FILE_DELETE_CHILD_LE);
		}
	}

	if (had_nt_aces)
		return;

posix_default_acl:
	if (!fattr->cf_dacls)
		return;

	pace = fattr->cf_dacls->a_entries;
	for (i = 0; i < fattr->cf_dacls->a_count; i++, pace++) {
		sid = sids++;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;

			uid = posix_acl_uid_translate(idmap, pace);
			id_to_sid(uid, SIDCREATOR_OWNER, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = posix_acl_gid_translate(idmap, pace);
			id_to_sid(gid, SIDCREATOR_GROUP, sid);
		} else {
			continue;
		}

		ntace = &sd->aces[*num_aces];
		fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED, 0x0b,
				 pace->e_perm, 0777);
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->mask |=
				le32_to_cpu(FILE_DELETE_LE | FILE_DELETE_CHILD_LE);
	}
}

static void set_ntacl_dacl(const struct mnt_idmap *idmap,
			   struct ksmbd_sd *sd,
			   const struct ksmbd_sd *nt_sd,
			   struct smb_fattr *fattr, struct smb_sid *sids)
{
	u16 nt_num_aces = nt_sd->num_aces, num_aces = 0;
	u16 copied_nt_aces;
	int i;

	for (i = 0; i < nt_num_aces; i++) {
		/* ksmbd leaves an object ACE out of the reply */
		if (nt_sd->aces[i].obj_len ||
		    nt_sd->aces[i].sid->num_subauth == 0)
			continue;
		sd->aces[num_aces++] = nt_sd->aces[i];
	}

	copied_nt_aces = num_aces;
	set_posix_acl_entries_dacl(idmap, sd, fattr,
				   &num_aces, copied_nt_aces,
				   nt_num_aces != 0, sids);
	sd->num_aces = num_aces;
}

static void set_mode_dacl(const struct mnt_idmap *idmap,
			  struct ksmbd_sd *sd,
			  const struct smb_sid *pownersid,
			  const struct smb_sid *pgrpsid,
			  struct smb_fattr *fattr, struct smb_sid *sids)
{
	struct ksmbd_ace *pace;
	u16 num_aces = 0;

	pace = sd->aces;

	if (fattr->cf_acls) {
		set_posix_acl_entries_dacl(idmap, sd, fattr,
					   &num_aces, num_aces, false, sids);
		goto out;
	}

	/* owner RID */
	fill_ace_for_sid(pace++, pownersid, ACCESS_ALLOWED, 0,
			 fattr->cf_mode, 0700);

	/* Group RID */
	fill_ace_for_sid(pace++, pgrpsid,
			 ACCESS_ALLOWED, 0, fattr->cf_mode, 0070);
	num_aces = 3;

	if (S_ISDIR(fattr->cf_mode)) {
		/* creator owner */
		fill_ace_for_sid(pace++, &creator_owner, ACCESS_ALLOWED,
				 0x0b, fattr->cf_mode, 0700);

		/* creator group */
		fill_ace_for_sid(pace++, &creator_group, ACCESS_ALLOWED,
				 0x0b, fattr->cf_mode, 0070);
		num_aces = 5;
	}

	/* other */
	fill_ace_for_sid(pace, &sid_everyone, ACCESS_ALLOWED, 0,
			 fattr->cf_mode, 0007);

out:
	sd->num_aces = num_aces;
}

/* Convert CIFS ACL to POSIX form */
int parse_sec_desc(const struct mnt_idmap *idmap, struct smb_ntsd *pntsd,
		   int acl_len, struct smb_fattr *fattr, struct ksmbd_sd **psd)
{
	int rc = 0;
	const struct smb_sid *owner_sid_ptr = NULL, *group_sid_ptr = NULL;
	struct ksmbd_sd *sd __free(kvfree) = NULL;
	int pntsd_type;

	if (!pntsd)
		return -EIO;

	if (acl_len < (int)sizeof(struct smb_ntsd))
		return -EINVAL;

	/* Refuse an SD from a client if the decoder left a part out */
	rc = ksmbd_sd_decode((u8 *)pntsd, acl_len, &sd);
	if (rc == -EBADMSG || (!rc && sd->part_dropped))
		rc = -EINVAL;
	if (rc)
		return rc;

	pntsd_type = sd->control;
	if (sd->dacl == KSMBD_ACL_ABSENT) {
		ksmbd_debug(SMB, "DACL_PRESENT in DACL type is not set\n");
		*psd = no_free_ptr(sd);
		return rc;
	}

	/* The stored SD keeps only the Control bits set below and no SACL */
	sd->control = 0;
	sd->sacl = KSMBD_ACL_ABSENT;
	sd->sacl_len = 0;

	if (sd->owner) {
		owner_sid_ptr = sd->owner;
		rc = sid_to_id(idmap, owner_sid_ptr, SIDOWNER, fattr);
		if (rc) {
			ksmbd_debug(SMB, "Owner SID has no Unix uid mapping\n");
			owner_sid_ptr = NULL;
			rc = 0;
		}
	}

	if (sd->group) {
		group_sid_ptr = sd->group;
		rc = sid_to_id(idmap, group_sid_ptr, SIDUNIX_GROUP, fattr);
		if (rc) {
			ksmbd_debug(SMB, "Group SID has no Unix gid mapping\n");
			group_sid_ptr = NULL;
			rc = 0;
		}
	}

	if ((pntsd_type & (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ)) ==
	    (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ))
		sd->control |= DACL_AUTO_INHERITED;
	if (pntsd_type & DACL_PROTECTED)
		sd->control |= DACL_PROTECTED;

	rc = parse_dacl(idmap, sd, owner_sid_ptr, group_sid_ptr, fattr);
	if (rc)
		return rc;

	*psd = no_free_ptr(sd);
	return 0;
}

/* Convert permission bits from mode to equivalent CIFS ACL */
int build_sec_desc(const struct mnt_idmap *idmap,
		   struct smb_ntsd **pntsd, const struct ksmbd_sd *ppntsd,
		   int addition_info, __u32 *secdesclen,
		   struct smb_fattr *fattr)
{
	int rc = 0;
	struct smb_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct smb_sid *sids = NULL;
	struct ksmbd_sd *sd = NULL;
	size_t num_aces = 0, num_sids = 0, len = 0;
	uid_t uid;
	gid_t gid;
	unsigned int sid_type = SIDOWNER;

	*pntsd = NULL;
	nowner_sid_ptr = kmalloc_obj(struct smb_sid, KSMBD_DEFAULT_GFP);
	if (!nowner_sid_ptr)
		return -ENOMEM;

	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	if (!uid)
		sid_type = SIDUNIX_USER;
	id_to_sid(uid, sid_type, nowner_sid_ptr);

	ngroup_sid_ptr = kmalloc_obj(struct smb_sid, KSMBD_DEFAULT_GFP);
	if (!ngroup_sid_ptr) {
		kfree(nowner_sid_ptr);
		return -ENOMEM;
	}

	gid = from_kgid(&init_user_ns, fattr->cf_gid);
	id_to_sid(gid, SIDUNIX_GROUP, ngroup_sid_ptr);

	/* Room for every ACE that set_mode_dacl() or set_ntacl_dacl() adds */
	if (addition_info & DACL_SECINFO) {
		if (ppntsd)
			num_aces = ppntsd->num_aces;
		if (fattr->cf_acls) {
			num_aces += 2 * fattr->cf_acls->a_count;
			num_sids = fattr->cf_acls->a_count;
		} else if (!ppntsd) {
			num_aces = 5;
		}
		if (fattr->cf_dacls) {
			num_aces += fattr->cf_dacls->a_count;
			num_sids += fattr->cf_dacls->a_count;
		}
	}

	sd = kvzalloc(struct_size(sd, aces, num_aces), KSMBD_DEFAULT_GFP);
	sids = kvmalloc_array(num_sids, sizeof(*sids), KSMBD_DEFAULT_GFP);
	if (!sd || !sids) {
		rc = -ENOMEM;
		goto out;
	}
	sd->num_aces = num_aces;

	if (ppntsd) {
		u16 flags = 0;

		/* Return the stored flags only of the parts in the reply */
		if (addition_info & OWNER_SECINFO)
			flags |= OWNER_DEFAULTED;
		if (addition_info & GROUP_SECINFO)
			flags |= GROUP_DEFAULTED;
		if (addition_info & DACL_SECINFO)
			flags |= DACL_DEFAULTED | DACL_AUTO_INHERITED |
				 DACL_PROTECTED;
		sd->control |= ppntsd->control & flags;
	}

	if (addition_info & OWNER_SECINFO)
		sd->owner = nowner_sid_ptr;

	if (addition_info & GROUP_SECINFO)
		sd->group = ngroup_sid_ptr;

	if (addition_info & DACL_SECINFO) {
		if (!ppntsd) {
			sd->dacl = KSMBD_ACL_PRESENT;
			set_mode_dacl(idmap, sd, nowner_sid_ptr, ngroup_sid_ptr,
				      fattr, sids);
		} else if (ppntsd->dacl == KSMBD_ACL_PRESENT) {
			sd->dacl = KSMBD_ACL_PRESENT;
			set_ntacl_dacl(idmap, sd, ppntsd, fattr, sids);
		} else {
			sd->dacl = KSMBD_ACL_NULL;
		}
	}
	if (sd->dacl != KSMBD_ACL_PRESENT)
		sd->num_aces = 0;

	rc = ksmbd_sd_encode(sd, (u8 **)pntsd, &len);
	*secdesclen = len;
out:
	kfree(nowner_sid_ptr);
	kfree(ngroup_sid_ptr);
	kvfree(sids);
	kvfree(sd);
	return rc;
}

static void smb_append_inherited_ace(struct ksmbd_sd *sd, u16 *ace_cnt,
				     const struct ksmbd_ace *parent_ace,
				     const struct smb_sid *sid, u8 flags)
{
	struct ksmbd_ace *ace = &sd->aces[(*ace_cnt)++];

	*ace = *parent_ace;
	ace->flags = flags;
	ace->sid = sid;
}

int smb_inherit_dacl(struct ksmbd_conn *conn,
		     const struct path *path,
		     unsigned int uid, unsigned int gid)
{
	const struct smb_sid *psid, *creator = NULL;
	const struct ksmbd_ace *parent_aces;
	struct ksmbd_sd *parent_pntsd = NULL, *sd;
	struct smb_sid owner_sid, group_sid;
	struct dentry *parent;
	const struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	int inherited_flags = 0, flags = 0, i;
	int rc;
	u16 num_aces, ace_cnt = 0;
	bool is_dir = S_ISDIR(d_inode(path->dentry)->i_mode);

	parent = dget_parent(path->dentry);
	if (!d_inode(parent)) {
		dput(parent);
		return -ENOENT;
	}
	rc = ksmbd_vfs_get_sd_xattr(conn, idmap, parent, &parent_pntsd);
	dput(parent);
	if (rc)
		return -ENOENT;

	if (parent_pntsd->dacl != KSMBD_ACL_PRESENT) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	num_aces = parent_pntsd->num_aces;
	sd = kvzalloc(struct_size(sd, aces, num_aces * 2), KSMBD_DEFAULT_GFP);
	if (!sd) {
		rc = -ENOMEM;
		goto free_parent_pntsd;
	}
	sd->num_aces = num_aces * 2;

	if (parent_pntsd->control & DACL_AUTO_INHERITED)
		inherited_flags = INHERITED_ACE;

	for (i = 0; i < num_aces; i++) {
		parent_aces = &parent_pntsd->aces[i];
		flags = parent_aces->flags;
		if (!smb_inherit_flags(flags, is_dir))
			continue;
		if (is_dir) {
			flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);
			if (!(flags & CONTAINER_INHERIT_ACE))
				flags |= INHERIT_ONLY_ACE;
			if (flags & NO_PROPAGATE_INHERIT_ACE)
				flags = 0;
		} else {
			flags = 0;
		}

		if (smb_sid_equal(&creator_owner, parent_aces->sid)) {
			creator = &creator_owner;
			id_to_sid(uid, SIDOWNER, &owner_sid);
			psid = &owner_sid;
		} else if (smb_sid_equal(&creator_group, parent_aces->sid)) {
			creator = &creator_group;
			id_to_sid(gid, SIDUNIX_GROUP, &group_sid);
			psid = &group_sid;
		} else {
			creator = NULL;
			psid = parent_aces->sid;
		}

		if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {
			smb_append_inherited_ace(sd, &ace_cnt, parent_aces,
						 psid, inherited_flags);
			flags |= INHERIT_ONLY_ACE;
			psid = creator;
		} else if (is_dir && !(parent_aces->flags & NO_PROPAGATE_INHERIT_ACE)) {
			psid = parent_aces->sid;
		}

		smb_append_inherited_ace(sd, &ace_cnt, parent_aces, psid,
					 flags | inherited_flags);
	}

	if (ace_cnt) {
		size_t pntsd_size;
		u8 *pntsd;

		sd->num_aces = ace_cnt;
		sd->dacl = KSMBD_ACL_PRESENT;
		sd->control = parent_pntsd->control & DACL_AUTO_INHERITED;
		sd->owner = parent_pntsd->owner;
		sd->group = parent_pntsd->group;
		rc = ksmbd_sd_encode(sd, &pntsd, &pntsd_size);
		if (rc)
			goto free_aces_base;

		/*
		 * If the filesystem refuses this SD, the caller tries the SD
		 * built from the inode, which may fit.
		 */
		rc = ksmbd_vfs_set_sd_xattr(conn, idmap, path, pntsd, pntsd_size);
		kvfree(pntsd);
	}
free_aces_base:
	kvfree(sd);
free_parent_pntsd:
	kvfree(parent_pntsd);
	return rc;
}

bool smb_inherit_flags(int flags, bool is_dir)
{
	if (!is_dir)
		return (flags & OBJECT_INHERIT_ACE) != 0;

	if (flags & OBJECT_INHERIT_ACE && !(flags & NO_PROPAGATE_INHERIT_ACE))
		return true;

	if (flags & CONTAINER_INHERIT_ACE)
		return true;
	return false;
}

/* Whether the caller's credentials hold the group of an S-1-22-2-<gid> SID */
static bool smb_sid_in_group(const struct smb_sid *sid)
{
	gid_t gid;

	if (sid->num_subauth != sid_unix_groups.num_subauth + 1 ||
	    compare_sids(sid, &sid_unix_groups))
		return false;
	gid = le32_to_cpu(sid->sub_auth[sid->num_subauth - 1]);
	/*
	 * ksmbd_override_fsids() builds the caller's credentials with
	 * make_kgid(&init_user_ns, ...), so the group membership test must
	 * compare in that space. Applying the mount idmap here (as when
	 * resolving a SID to an on-disk gid) would mismatch on idmapped
	 * mounts.
	 */
	return in_group_p(make_kgid(&init_user_ns, gid));
}

/*
 * compare_sids() compares only the sub-authorities both SIDs have, so it
 * also matches a shorter or longer SID, such as S-1-3 or S-1-3-4-777
 */
static bool smb_sid_is_owner_rights(const struct smb_sid *sid)
{
	return sid->num_subauth == sid_owner_rights.num_subauth &&
	       !compare_sids(sid, &sid_owner_rights);
}

static unsigned int smb_parent_derived_rights(struct ksmbd_conn *conn,
					      const struct path *path, int uid,
					      bool authenticated,
					      unsigned int want);

int smb_check_perm_dacl(struct ksmbd_conn *conn, const struct path *path,
			__le32 *pdaccess, __le32 raw_daccess, int uid,
			bool authenticated, bool strict)
{
	const struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	struct ksmbd_sd *sd = NULL;
	struct posix_acl *posix_acls;
	int rc;
	struct smb_sid sid;
	int requested = le32_to_cpu(*pdaccess & ~FILE_MAXIMAL_ACCESS_LE);
	int granted = requested;
	const struct ksmbd_ace *ace;
	int i, found = 0;
	unsigned int access_bits = 0, denied = 0, grp_granted = 0;
	unsigned int grp_allowed = 0, grp_denied = 0, bits;
	const struct ksmbd_ace *others_ace = NULL;
	bool or_ace = false, obj_deny = false, au_ace = false, member, counted;
	bool grp_ace = false;
	struct posix_acl_entry *pa_entry;
	unsigned int sid_type = SIDOWNER;
	bool is_owner, owner_rights = false;
	bool maximal = *pdaccess & FILE_MAXIMAL_ACCESS_LE;
	/*
	 * MAXIMUM_ALLOWED requests that are not strict match every session
	 * against Authenticated Users and do not count ACEs for the
	 * caller's groups. Strict ones match SIDs as explicit requests do.
	 */
	bool open_max = maximal && !strict;
	bool authusers = authenticated || open_max;
	vfsuid_t vfsuid;

	ksmbd_debug(SMB, "check permission using windows acl\n");
	rc = ksmbd_vfs_get_sd_xattr(conn, idmap, path->dentry, &sd);
	if (rc) {
		if (smb_no_stored_sd(rc))
			rc = 0;
		else if (rc != -ENOMEM)
			rc = -EACCES;
		goto err_out;
	}

	if (sd->dacl != KSMBD_ACL_PRESENT)
		goto err_out;

	if (!uid)
		sid_type = SIDUNIX_USER;
	id_to_sid(uid, sid_type, &sid);
	vfsuid = i_uid_into_vfsuid(idmap, d_inode(path->dentry));
	is_owner = uid == from_kuid(&init_user_ns, vfsuid_into_kuid(vfsuid));

	if (!sd->num_aces) {
		unsigned int allowed = 0;

		/*
		 * An empty (present, zero-ACE) DACL grants no access to
		 * anyone except the object owner's implicit READ_CONTROL
		 * and WRITE_DAC (MS-DTYP 2.5.3.2), besides what the parent
		 * grants. Deny every other right, and do not let trailing
		 * bytes after a zero-ACE DACL become an implicit grant.
		 */
		if (is_owner)
			allowed = READ_CONTROL | WRITE_DAC;
		if (!strict)
			allowed |= smb_parent_derived_rights(conn, path, uid,
							     authenticated,
							     requested & ~allowed);
		if (maximal)
			requested |= allowed;
		if (!allowed || requested & ~allowed)
			rc = -EACCES;
		else
			*pdaccess = cpu_to_le32(requested);
		goto err_out;
	}

	/*
	 * Evaluate the DACL in order (MS-DTYP 2.5.3.2). access_bits collects
	 * the result for the ACEs that apply to the caller, without its groups
	 * for a MAXIMUM_ALLOWED request that is not strict. grp_granted
	 * collects what ACEs for the caller's groups, or OWNER RIGHTS for the
	 * owner, grant. It is used when the SID lookup and POSIX ACL fallback
	 * below do not decide.
	 */
	for (i = 0; i < sd->num_aces; i++) {
		ace = &sd->aces[i];
		if ((ace->type == ACCESS_DENIED_OBJECT_ACE_TYPE ||
		     ace->type == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) &&
		    !(ace->flags & INHERIT_ONLY_ACE))
			obj_deny = true;
		/* An object ACE or a SID with no sub-authority matches no one */
		if (ace->obj_len || !ace->sid->num_subauth)
			continue;

		if (!compare_sids(&sid_owner_rights, ace->sid)) {
			owner_rights = true;
			if (!is_owner)
				continue;
		}

		member = smb_sid_in_group(ace->sid);
		/* The grp_ masks count groups and OWNER RIGHTS only */
		counted = member ||
			  (is_owner && smb_sid_is_owner_rights(ace->sid));
		if (ace->flags & INHERIT_ONLY_ACE ||
		    (compare_sids(&sid, ace->sid) &&
		     compare_sids(&sid_unix_NFS_mode, ace->sid) &&
		     compare_sids(&sid_everyone, ace->sid) &&
		     (!authusers ||
		      compare_sids(&sid_authusers, ace->sid)) &&
		     compare_sids(&sid_owner_rights, ace->sid) &&
		     !member))
			continue;
		/* Other requests count only SIDs that match exactly */
		if (!open_max && !member &&
		    !smb_sid_equal(&sid, ace->sid) &&
		    !smb_sid_equal(&sid_everyone, ace->sid) &&
		    !(authusers && smb_sid_equal(&sid_authusers, ace->sid)) &&
		    !smb_sid_is_owner_rights(ace->sid))
			continue;

		bits = ace->mask;
		switch (ace->type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			grp_ace |= counted;
			if (counted)
				grp_allowed |= bits;
			/* An open's MAXIMUM_ALLOWED takes no group grants */
			if (open_max && member)
				break;
			if (counted)
				grp_granted |= bits;
			access_bits |= bits;
			break;
		case ACCESS_DENIED_ACE_TYPE:
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			grp_ace |= counted;
			if (counted)
				grp_denied |= ~grp_allowed & bits;
			/* nor group denials */
			if (!(open_max && member))
				denied |= ~access_bits & bits;
			break;
		}
	}

	/* Keep only file rights, not MAXIMUM_ALLOWED or generic bits */
	grp_granted &= GENERIC_ALL_FLAGS & ~grp_denied;
	if (maximal) {
		if (is_owner && !owner_rights)
			access_bits |= READ_CONTROL | WRITE_DAC |
				FILE_READ_ATTRIBUTES | DELETE;
		access_bits &= ~denied;
		/* An object deny ACE could deny the parent's rights */
		if (!open_max && obj_deny)
			access_bits = 0;
		if ((raw_daccess & FILE_GENERIC_EXECUTE_LE) &&
		    S_ISREG(d_inode(path->dentry)->i_mode) &&
		    (access_bits & GENERIC_READ_FLAGS) == GENERIC_READ_FLAGS)
			access_bits |= FILE_EXECUTE;
		granted = requested | access_bits;
	} else if (!obj_deny) {
		/* An explicit request takes the ordered result */
		access_bits &= ~denied;
	} else {
		/*
		 * ksmbd does not parse object deny ACEs, so with one present an
		 * explicit request keeps the answer of the ACE found below
		 */
		access_bits = 0;
	}

	for (i = 0; i < sd->num_aces; i++) {
		ace = &sd->aces[i];
		if (ace->obj_len || !ace->sid->num_subauth)
			continue;
		if (!compare_sids(&sid, ace->sid) ||
		    !compare_sids(&sid_unix_NFS_mode, ace->sid)) {
			found = 1;
			break;
		}
		if (!compare_sids(&sid_owner_rights, ace->sid) &&
		    !(ace->flags & INHERIT_ONLY_ACE))
			or_ace = true;
		if (!compare_sids(&sid_everyone, ace->sid) ||
		    (authusers &&
		     !compare_sids(&sid_authusers, ace->sid)))
			others_ace = ace;
		if (!compare_sids(&sid_authusers, ace->sid))
			au_ace = true;
	}

	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
		posix_acls = get_inode_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);
		/*
		 * An Authenticated Users ACE keeps the POSIX ACL from deciding,
		 * also for sessions that it does not match. For a strict
		 * MAXIMUM_ALLOWED request, ACEs for the caller's groups or
		 * OWNER RIGHTS decide before the POSIX ACL, unless the DACL has
		 * an object deny ACE, which ksmbd does not parse.
		 */
		if (!IS_ERR_OR_NULL(posix_acls) && !found && !others_ace &&
		    !au_ace && !(strict && maximal && grp_ace && !obj_deny)) {
			unsigned int id = -1;

			pa_entry = posix_acls->a_entries;
			for (i = 0; i < posix_acls->a_count; i++, pa_entry++) {
				if (pa_entry->e_tag == ACL_USER)
					id = posix_acl_uid_translate(idmap, pa_entry);
				else if (pa_entry->e_tag == ACL_GROUP)
					id = posix_acl_gid_translate(idmap, pa_entry);
				else
					continue;

				/* A group entry grants only to the group's members */
				if (id == uid &&
				    (pa_entry->e_tag == ACL_USER ||
				     in_group_p(make_kgid(&init_user_ns, id)))) {
					mode_to_access_flags(pa_entry->e_perm,
							     0777,
							     &access_bits);
					if (!access_bits)
						access_bits =
							SET_MINIMUM_RIGHTS;
					/*
					 * Only ACEs for the caller's groups,
					 * or OWNER RIGHTS for the owner, apply
					 * here. The POSIX ACL entry does not
					 * grant an explicitly requested right
					 * that they deny first in DACL order.
					 */
					access_bits &= ~(grp_denied &
							 requested);
					posix_acl_release(posix_acls);
					goto check_access_bits;
				}
			}
		}
		if (!IS_ERR_OR_NULL(posix_acls))
			posix_acl_release(posix_acls);
	}

	if (!found) {
		if (others_ace) {
			ace = others_ace;
		} else {
			unsigned int allowed = 0;

			/*
			 * No ACE names the owner, who may still read and
			 * change the DACL unless OWNER RIGHTS applies
			 * (MS-DTYP 2.5.3.2).
			 */
			if (is_owner && !or_ace)
				allowed = READ_CONTROL | WRITE_DAC;
			/*
			 * Add what ACEs for the caller's groups, or OWNER
			 * RIGHTS for the owner, grant in DACL order, unless an
			 * object deny ACE, which ksmbd does not parse, could
			 * apply.
			 */
			if (!obj_deny)
				allowed |= grp_granted;
			if (!strict)
				allowed |= smb_parent_derived_rights(conn, path, uid,
								     authenticated,
								     requested & ~allowed);
			if (maximal)
				requested |= allowed;
			if (!allowed || requested & ~allowed) {
				ksmbd_debug(SMB, "Can't find corresponding sid\n");
				rc = -EACCES;
				goto err_out;
			}
			*pdaccess = cpu_to_le32(requested);
			goto err_out;
		}
	}

	if (!maximal && obj_deny) {
		switch (ace->type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			access_bits = ace->mask;
			break;
		case ACCESS_DENIED_ACE_TYPE:
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			access_bits = ~ace->mask;
			break;
		}
	}

check_access_bits:
	if (strict) {
		access_bits &= granted;
	} else {
		access_bits |= FILE_READ_ATTRIBUTES | READ_CONTROL |
			WRITE_DAC | DELETE;
	}

	if (granted & ~access_bits) {
		ksmbd_debug(SMB, "Access denied with winACL, requested : %x, allowed : %x\n",
			    granted, access_bits);
		rc = -EACCES;
		goto err_out;
	}

	*pdaccess = cpu_to_le32(granted);
err_out:
	kvfree(sd);
	return rc;
}
EXPORT_SYMBOL_IF_KUNIT(smb_check_perm_dacl);

/*
 * Return the rights in @want that @path gets from its parent directory:
 * DELETE if the parent's DACL grants FILE_DELETE_CHILD, and
 * FILE_READ_ATTRIBUTES if it grants FILE_LIST_DIRECTORY
 * (MS-FSA 2.1.5.1.2.1). A parent with no DACL, or with one that ksmbd
 * cannot read, gives nothing. Callers pass only rights that the request
 * names.
 */
static unsigned int smb_parent_derived_rights(struct ksmbd_conn *conn,
					      const struct path *path, int uid,
					      bool authenticated,
					      unsigned int want)
{
	struct path parent = { .mnt = path->mnt };
	__le32 granted = FILE_MAXIMAL_ACCESS_LE;
	unsigned int rights = 0;
	int rc;

	if (!(want & (DELETE | FILE_READ_ATTRIBUTES)))
		return 0;

	/* The root of the mount, or a disconnected dentry, has no parent */
	if (path->dentry == path->mnt->mnt_root || IS_ROOT(path->dentry))
		return 0;

	parent.dentry = dget_parent(path->dentry);
	/* Strict, so the parent's own parent is not consulted */
	rc = smb_check_perm_dacl(conn, &parent, &granted, 0, uid,
				 authenticated, true);
	dput(parent.dentry);
	if (rc || granted == FILE_MAXIMAL_ACCESS_LE)
		return 0;
	if (granted & FILE_DELETE_CHILD_LE)
		rights |= DELETE;
	if (granted & FILE_LIST_DIRECTORY_LE)
		rights |= FILE_READ_ATTRIBUTES;
	return rights & want;
}

int set_info_sec(struct ksmbd_conn *conn, struct ksmbd_tree_connect *tcon,
		 const struct path *path, struct smb_ntsd *pntsd, int ntsd_len,
		 bool type_check, bool posix_open,
		 bool dacl_requested)
{
	int rc;
	struct ksmbd_sd *sd = NULL;
	size_t store_len;
	u8 *store = NULL;
	bool store_sd;
	struct smb_fattr fattr = {{0}};
	struct inode *inode = d_inode(path->dentry);
	const struct mnt_idmap *idmap = mnt_idmap(path->mnt);
	struct iattr newattrs;

	fattr.cf_uid = INVALID_UID;
	fattr.cf_gid = INVALID_GID;
	fattr.cf_mode = inode->i_mode;

	rc = parse_sec_desc(idmap, pntsd, ntsd_len, &fattr, &sd);
	if (rc)
		goto out;
	if (fattr.cf_posix_mode && !dacl_requested) {
		fattr.cf_posix_mode = false;
		fattr.cf_mode = inode->i_mode;
	}
	if (fattr.cf_posix_mode && !posix_open) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	/*
	 * Encode the SD to store before anything is changed. The SD of a
	 * CREATE context (type_check) is stored only if it has a DACL.
	 */
	store_sd = test_share_config_flag(tcon->share_conf,
					  KSMBD_SHARE_FLAG_ACL_XATTR) &&
		   !(type_check && sd->dacl == KSMBD_ACL_ABSENT);
	if (store_sd) {
		rc = ksmbd_sd_encode(sd, &store, &store_len);
		if (rc)
			goto out;
	}

	newattrs.ia_valid = ATTR_CTIME;
	if (!uid_eq(fattr.cf_uid, INVALID_UID)) {
		newattrs.ia_valid |= ATTR_UID;
		newattrs.ia_uid = fattr.cf_uid;
	}
	if (!gid_eq(fattr.cf_gid, INVALID_GID)) {
		newattrs.ia_valid |= ATTR_GID;
		newattrs.ia_gid = fattr.cf_gid;
	}
	newattrs.ia_valid |= ATTR_MODE;
	if (fattr.cf_posix_mode)
		newattrs.ia_mode = (inode->i_mode & ~07777) |
				   (fattr.cf_mode & 07777);
	else
		newattrs.ia_mode = (inode->i_mode & ~0777) |
				   (fattr.cf_mode & 0777);

	ksmbd_vfs_remove_acl_xattrs(idmap, path);
	rc = mnt_want_write(path->mnt);
	if (rc)
		goto out;

	/* Update posix acls */
	if (IS_ENABLED(CONFIG_FS_POSIX_ACL) && fattr.cf_dacls) {
		rc = set_posix_acl(idmap, path->dentry,
				   ACL_TYPE_ACCESS, fattr.cf_acls);
		if (rc < 0)
			ksmbd_debug(SMB,
				    "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				    rc);
		if (S_ISDIR(inode->i_mode) && fattr.cf_dacls) {
			rc = set_posix_acl(idmap, path->dentry,
					   ACL_TYPE_DEFAULT, fattr.cf_dacls);
			if (rc)
				ksmbd_debug(SMB,
					    "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					    rc);
		}
	}

	inode_lock(inode);
	rc = notify_change(idmap, path->dentry, &newattrs, NULL);
	inode_unlock(inode);
	mnt_drop_write(path->mnt);
	if (rc)
		goto out;

	if (store_sd) {
		/* Update WinACL in xattr */
		ksmbd_vfs_remove_sd_xattrs(idmap, path);
		rc = ksmbd_vfs_set_sd_xattr(conn, idmap, path, store, store_len);
		/*
		 * The CREATE context (type_check) stays best effort because
		 * the file exists already. A filesystem without the xattr is
		 * not an error either.
		 */
		if (type_check || rc == -EOPNOTSUPP)
			rc = 0;
	}

out:
	kvfree(store);
	kvfree(sd);
	posix_acl_release(fattr.cf_acls);
	posix_acl_release(fattr.cf_dacls);
	return rc;
}

void ksmbd_init_domain(u32 *sub_auth)
{
	int i;

	memcpy(&server_conf.domain_sid, &domain, sizeof(struct smb_sid));
	for (i = 0; i < 3; ++i)
		server_conf.domain_sid.sub_auth[i + 1] = cpu_to_le32(sub_auth[i]);
}
