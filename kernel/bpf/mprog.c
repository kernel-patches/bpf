// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_mprog.h>
#include <linux/filter.h>

static int bpf_mprog_tuple_relative(struct bpf_tuple *tuple,
				    u32 object, u32 flags,
				    enum bpf_prog_type type)
{
	struct bpf_prog *prog;
	struct bpf_link *link;

	memset(tuple, 0, sizeof(*tuple));
	if (!(flags & (BPF_F_REPLACE | BPF_F_BEFORE | BPF_F_AFTER)))
		return object || (flags & (BPF_F_ID | BPF_F_LINK)) ?
		       -EINVAL : 0;
	if (flags & BPF_F_LINK) {
		if (flags & BPF_F_ID)
			link = bpf_link_by_id(object);
		else
			link = bpf_link_get_from_fd(object);
		if (IS_ERR(link))
			return PTR_ERR(link);
		if (type && link->prog->type != type) {
			bpf_link_put(link);
			return -EINVAL;
		}
		tuple->link = link;
		tuple->prog = link->prog;
	} else {
		if (flags & BPF_F_ID)
			prog = bpf_prog_by_id(object);
		else
			prog = bpf_prog_get(object);
		if (IS_ERR(prog)) {
			if (!object &&
			    !(flags & BPF_F_ID))
				return 0;
			return PTR_ERR(prog);
		}
		if (type && prog->type != type) {
			bpf_prog_put(prog);
			return -EINVAL;
		}
		tuple->link = NULL;
		tuple->prog = prog;
	}
	return 0;
}

static void bpf_mprog_tuple_put(struct bpf_tuple *tuple)
{
	if (tuple->link)
		bpf_link_put(tuple->link);
	else if (tuple->prog)
		bpf_prog_put(tuple->prog);
}

static int bpf_mprog_replace(struct bpf_mprog_entry *entry,
			     struct bpf_tuple *ntuple,
			     struct bpf_tuple *rtuple, u32 rflags)
{
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	struct bpf_prog *oprog;
	u32 iflags;
	int i;

	if (rflags & (BPF_F_BEFORE | BPF_F_AFTER | BPF_F_LINK))
		return -EINVAL;
	if (rtuple->prog != ntuple->prog &&
	    bpf_mprog_exists(entry, ntuple->prog))
		return -EEXIST;
	for (i = 0; i < bpf_mprog_max(); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		oprog = READ_ONCE(fp->prog);
		if (!oprog)
			break;
		if (oprog != rtuple->prog)
			continue;
		if (cp->link != ntuple->link)
			return -EBUSY;
		iflags = cp->flags;
		if ((iflags & BPF_F_FIRST) !=
		    (rflags & BPF_F_FIRST)) {
			iflags = bpf_mprog_flags(iflags, rflags,
						 BPF_F_FIRST);
			if ((iflags & BPF_F_FIRST) &&
			    rtuple->prog != bpf_mprog_first(entry))
				return -EACCES;
		}
		if ((iflags & BPF_F_LAST) !=
		    (rflags & BPF_F_LAST)) {
			iflags = bpf_mprog_flags(iflags, rflags,
						 BPF_F_LAST);
			if ((iflags & BPF_F_LAST) &&
			    rtuple->prog != bpf_mprog_last(entry))
				return -EACCES;
		}
		bpf_mprog_write(fp, cp, ntuple, iflags);
		if (!ntuple->link)
			bpf_prog_put(oprog);
		return 0;
	}
	return -ENOENT;
}

static int bpf_mprog_head_tail(struct bpf_mprog_entry *entry,
			       struct bpf_tuple *ntuple,
			       struct bpf_tuple *rtuple, u32 aflags)
{
	struct bpf_mprog_entry *peer;
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	struct bpf_prog *oprog;
	u32 iflags, items;

	if (bpf_mprog_exists(entry, ntuple->prog))
		return -EEXIST;
	items = bpf_mprog_total(entry);
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	if (aflags & BPF_F_FIRST) {
		if (aflags & BPF_F_AFTER)
			return -EINVAL;
		bpf_mprog_read(entry, 0, &fp, &cp);
		iflags = cp->flags;
		if (iflags & BPF_F_FIRST)
			return -EBUSY;
		if (aflags & BPF_F_LAST) {
			if (aflags & BPF_F_BEFORE)
				return -EINVAL;
			if (items)
				return -EBUSY;
			bpf_mprog_read(peer, 0, &fp, &cp);
			bpf_mprog_write(fp, cp, ntuple,
					BPF_F_FIRST | BPF_F_LAST);
			return BPF_MPROG_SWAP;
		}
		if (aflags & BPF_F_BEFORE) {
			oprog = READ_ONCE(fp->prog);
			if (oprog != rtuple->prog ||
			    (rtuple->link &&
			     rtuple->link != cp->link))
				return -EBUSY;
		}
		if (items >= bpf_mprog_max())
			return -ENOSPC;
		bpf_mprog_read(peer, 0, &fp, &cp);
		bpf_mprog_write(fp, cp, ntuple, BPF_F_FIRST);
		bpf_mprog_copy_range(peer, entry, 1, 0, items);
		return BPF_MPROG_SWAP;
	}
	if (aflags & BPF_F_LAST) {
		if (aflags & BPF_F_BEFORE)
			return -EINVAL;
		if (items) {
			bpf_mprog_read(entry, items - 1, &fp, &cp);
			iflags = cp->flags;
			if (iflags & BPF_F_LAST)
				return -EBUSY;
			if (aflags & BPF_F_AFTER) {
				oprog = READ_ONCE(fp->prog);
				if (oprog != rtuple->prog ||
				    (rtuple->link &&
				     rtuple->link != cp->link))
					return -EBUSY;
			}
			if (items >= bpf_mprog_max())
				return -ENOSPC;
		} else {
			if (aflags & BPF_F_AFTER)
				return -EBUSY;
		}
		bpf_mprog_read(peer, items, &fp, &cp);
		bpf_mprog_write(fp, cp, ntuple, BPF_F_LAST);
		bpf_mprog_copy_range(peer, entry, 0, 0, items);
		return BPF_MPROG_SWAP;
	}
	return -ENOENT;
}

static int bpf_mprog_add(struct bpf_mprog_entry *entry,
			 struct bpf_tuple *ntuple,
			 struct bpf_tuple *rtuple, u32 aflags)
{
	struct bpf_mprog_fp *fp_dst, *fp_src;
	struct bpf_mprog_cp *cp_dst, *cp_src;
	struct bpf_mprog_entry *peer;
	struct bpf_prog *oprog;
	bool found = false;
	u32 items;
	int i, j;

	items = bpf_mprog_total(entry);
	if (items >= bpf_mprog_max())
		return -ENOSPC;
	if ((aflags & (BPF_F_BEFORE | BPF_F_AFTER)) ==
	    (BPF_F_BEFORE | BPF_F_AFTER))
		return -EINVAL;
	if (bpf_mprog_exists(entry, ntuple->prog))
		return -EEXIST;
	if (!rtuple->prog && (aflags & (BPF_F_BEFORE | BPF_F_AFTER))) {
		if (!items)
			aflags &= ~(BPF_F_AFTER | BPF_F_BEFORE);
		if (aflags & BPF_F_BEFORE)
			rtuple->prog = bpf_mprog_first_reg(entry);
		if (aflags & BPF_F_AFTER)
			rtuple->prog = bpf_mprog_last_reg(entry);
		if (!rtuple->prog)
			aflags &= ~(BPF_F_AFTER | BPF_F_BEFORE);
		else
			bpf_prog_inc(rtuple->prog);
	}
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	for (i = 0, j = 0; i < bpf_mprog_max(); i++, j++) {
		bpf_mprog_read(entry, i, &fp_src, &cp_src);
		bpf_mprog_read(peer,  j, &fp_dst, &cp_dst);
		oprog = READ_ONCE(fp_src->prog);
		if (!oprog) {
			if (i != j)
				break;
			if (i > 0) {
				bpf_mprog_read(entry, i - 1,
					       &fp_src, &cp_src);
				if (cp_src->flags & BPF_F_LAST) {
					if (cp_src->flags & BPF_F_FIRST)
						return -EBUSY;
					bpf_mprog_copy(fp_dst, cp_dst,
						       fp_src, cp_src);
					bpf_mprog_read(peer, --j,
						       &fp_dst, &cp_dst);
				}
			}
			bpf_mprog_write(fp_dst, cp_dst, ntuple, 0);
			break;
		}
		if (aflags & (BPF_F_BEFORE | BPF_F_AFTER)) {
			if (rtuple->prog != oprog ||
			    (rtuple->link &&
			     rtuple->link != cp_src->link))
				goto next;
			found = true;
			if (aflags & BPF_F_BEFORE) {
				if (cp_src->flags & BPF_F_FIRST)
					return -EBUSY;
				bpf_mprog_write(fp_dst, cp_dst, ntuple, 0);
				bpf_mprog_read(peer, ++j, &fp_dst, &cp_dst);
				goto next;
			}
			if (aflags & BPF_F_AFTER) {
				if (cp_src->flags & BPF_F_LAST)
					return -EBUSY;
				bpf_mprog_copy(fp_dst, cp_dst,
					       fp_src, cp_src);
				bpf_mprog_read(peer, ++j, &fp_dst, &cp_dst);
				bpf_mprog_write(fp_dst, cp_dst, ntuple, 0);
				continue;
			}
		}
next:
		bpf_mprog_copy(fp_dst, cp_dst,
			       fp_src, cp_src);
	}
	if (rtuple->prog && !found)
		return -ENOENT;
	return BPF_MPROG_SWAP;
}

static int bpf_mprog_del(struct bpf_mprog_entry *entry,
			 struct bpf_tuple *dtuple,
			 struct bpf_tuple *rtuple, u32 dflags)
{
	struct bpf_mprog_fp *fp_dst, *fp_src;
	struct bpf_mprog_cp *cp_dst, *cp_src;
	struct bpf_mprog_entry *peer;
	struct bpf_prog *oprog;
	bool found = false;
	int i, j, ret;

	if (dflags & BPF_F_REPLACE)
		return -EINVAL;
	if (dflags & BPF_F_FIRST) {
		oprog = bpf_mprog_first(entry);
		if (dtuple->prog &&
		    dtuple->prog != oprog)
			return -ENOENT;
		dtuple->prog = oprog;
	}
	if (dflags & BPF_F_LAST) {
		oprog = bpf_mprog_last(entry);
		if (dtuple->prog &&
		    dtuple->prog != oprog)
			return -ENOENT;
		dtuple->prog = oprog;
	}
	if (!rtuple->prog && (dflags & (BPF_F_BEFORE | BPF_F_AFTER))) {
		if (dtuple->prog)
			return -EINVAL;
		if (dflags & BPF_F_BEFORE)
			dtuple->prog = bpf_mprog_first_reg(entry);
		if (dflags & BPF_F_AFTER)
			dtuple->prog = bpf_mprog_last_reg(entry);
		if (dtuple->prog)
			dflags &= ~(BPF_F_AFTER | BPF_F_BEFORE);
	}
	for (i = 0; i < bpf_mprog_max(); i++) {
		bpf_mprog_read(entry, i, &fp_src, &cp_src);
		oprog = READ_ONCE(fp_src->prog);
		if (!oprog)
			break;
		if (dflags & (BPF_F_BEFORE | BPF_F_AFTER)) {
			if (rtuple->prog != oprog ||
			    (rtuple->link &&
			     rtuple->link != cp_src->link))
				continue;
			found = true;
			if (dflags & BPF_F_BEFORE) {
				if (!i)
					return -ENOENT;
				bpf_mprog_read(entry, i - 1,
					       &fp_src, &cp_src);
				oprog = READ_ONCE(fp_src->prog);
				if (dtuple->prog &&
				    dtuple->prog != oprog)
					return -ENOENT;
				dtuple->prog = oprog;
				break;
			}
			if (dflags & BPF_F_AFTER) {
				bpf_mprog_read(entry, i + 1,
					       &fp_src, &cp_src);
				oprog = READ_ONCE(fp_src->prog);
				if (dtuple->prog &&
				    dtuple->prog != oprog)
					return -ENOENT;
				dtuple->prog = oprog;
				break;
			}
		}
	}
	if (!dtuple->prog || (rtuple->prog && !found))
		return -ENOENT;
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	ret = -ENOENT;
	for (i = 0, j = 0; i < bpf_mprog_max(); i++) {
		bpf_mprog_read(entry, i, &fp_src, &cp_src);
		bpf_mprog_read(peer,  j, &fp_dst, &cp_dst);
		oprog = READ_ONCE(fp_src->prog);
		if (!oprog)
			break;
		if (oprog != dtuple->prog) {
			bpf_mprog_copy(fp_dst, cp_dst,
				       fp_src, cp_src);
			j++;
		} else {
			if (cp_src->link != dtuple->link)
				return -EBUSY;
			if (!cp_src->link)
				bpf_mprog_mark_ref(entry, dtuple->prog);
			ret = BPF_MPROG_SWAP;
		}
	}
	if (!bpf_mprog_total(peer))
		ret = BPF_MPROG_FREE;
	return ret;
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object,
		     u32 expected_revision)
{
	struct bpf_tuple rtuple, ntuple = {
		.prog = prog,
		.link = link,
	};
	int ret;

	if (expected_revision &&
	    expected_revision != bpf_mprog_revision(entry))
		return -ESTALE;
	ret = bpf_mprog_tuple_relative(&rtuple, object, flags, prog->type);
	if (ret)
		return ret;
	if (flags & BPF_F_REPLACE)
		ret = bpf_mprog_replace(entry, &ntuple, &rtuple, flags);
	else if (flags & (BPF_F_FIRST | BPF_F_LAST))
		ret = bpf_mprog_head_tail(entry, &ntuple, &rtuple, flags);
	else
		ret = bpf_mprog_add(entry, &ntuple, &rtuple, flags);
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object,
		     u32 expected_revision)
{
	struct bpf_tuple rtuple, dtuple = {
		.prog = prog,
		.link = link,
	};
	int ret;

	if (expected_revision &&
	    expected_revision != bpf_mprog_revision(entry))
		return -ESTALE;
	ret = bpf_mprog_tuple_relative(&rtuple, object, flags,
				       prog ? prog->type :
				       BPF_PROG_TYPE_UNSPEC);
	if (ret)
		return ret;
	ret = bpf_mprog_del(entry, &dtuple, &rtuple, flags);
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry)
{
	u32 i, id, flags = 0, count, revision;
	u32 __user *uprog_id, *uprog_af;
	u32 __user *ulink_id, *ulink_af;
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	struct bpf_prog *prog;
	int ret = 0;

	if (attr->query.query_flags || attr->query.attach_flags)
		return -EINVAL;
	revision = bpf_mprog_revision(entry);
	count = bpf_mprog_total(entry);
	if (copy_to_user(&uattr->query.attach_flags, &flags, sizeof(flags)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.revision, &revision, sizeof(revision)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.count, &count, sizeof(count)))
		return -EFAULT;
	uprog_id = u64_to_user_ptr(attr->query.prog_ids);
	if (attr->query.count == 0 || !uprog_id || !count)
		return 0;
	if (attr->query.count < count) {
		count = attr->query.count;
		ret = -ENOSPC;
	}
	uprog_af = u64_to_user_ptr(attr->query.prog_attach_flags);
	ulink_id = u64_to_user_ptr(attr->query.link_ids);
	ulink_af = u64_to_user_ptr(attr->query.link_attach_flags);
	for (i = 0; i < ARRAY_SIZE(entry->fp_items); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		prog = READ_ONCE(fp->prog);
		if (!prog)
			break;
		id = prog->aux->id;
		if (copy_to_user(uprog_id + i, &id, sizeof(id)))
			return -EFAULT;
		id = cp->link ? cp->link->id : 0;
		if (ulink_id &&
		    copy_to_user(ulink_id + i, &id, sizeof(id)))
			return -EFAULT;
		flags = cp->flags;
		if (uprog_af && !id &&
		    copy_to_user(uprog_af + i, &flags, sizeof(flags)))
			return -EFAULT;
		if (ulink_af && id &&
		    copy_to_user(ulink_af + i, &flags, sizeof(flags)))
			return -EFAULT;
		if (i + 1 == count)
			break;
	}
	return ret;
}
