// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_mprog.h>

static int bpf_mprog_link(struct bpf_tuple *tuple,
			  u32 object, u32 flags,
			  enum bpf_prog_type type)
{
	bool id = flags & BPF_F_ID;
	struct bpf_link *link;

	if (id)
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
	return 0;
}

static int bpf_mprog_prog(struct bpf_tuple *tuple,
			  u32 object, u32 flags,
			  enum bpf_prog_type type)
{
	bool id = flags & BPF_F_ID;
	struct bpf_prog *prog;

	if (id)
		prog = bpf_prog_by_id(object);
	else
		prog = bpf_prog_get(object);
	if (IS_ERR(prog)) {
		if (!object && !id)
			return 0;
		return PTR_ERR(prog);
	}
	if (type && prog->type != type) {
		bpf_prog_put(prog);
		return -EINVAL;
	}

	tuple->link = NULL;
	tuple->prog = prog;
	return 0;
}

static int bpf_mprog_tuple_relative(struct bpf_tuple *tuple,
				    u32 object, u32 flags,
				    enum bpf_prog_type type)
{
	memset(tuple, 0, sizeof(*tuple));
	if (flags & BPF_F_LINK)
		return bpf_mprog_link(tuple, object, flags, type);
	return bpf_mprog_prog(tuple, object, flags, type);
}

static void bpf_mprog_tuple_put(struct bpf_tuple *tuple)
{
	if (tuple->link)
		bpf_link_put(tuple->link);
	else if (tuple->prog)
		bpf_prog_put(tuple->prog);
}

static int bpf_mprog_replace(struct bpf_mprog_entry *entry,
			     struct bpf_tuple *ntuple, int idx)
{
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	struct bpf_prog *oprog;

	bpf_mprog_read(entry, idx, &fp, &cp);
	oprog = READ_ONCE(fp->prog);
	bpf_mprog_write(fp, cp, ntuple);
	if (!ntuple->link) {
		WARN_ON_ONCE(cp->link);
		bpf_prog_put(oprog);
	}
	return BPF_MPROG_KEEP;
}

static int bpf_mprog_insert(struct bpf_mprog_entry *entry,
			    struct bpf_tuple *ntuple, int idx, u32 flags)
{
	int i, j = 0, total = bpf_mprog_total(entry);
	struct bpf_mprog_cp *cp, cpp[BPF_MPROG_MAX] = {};
	struct bpf_mprog_fp *fp, *fpp;
	struct bpf_mprog_entry *peer;

	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	if (idx < 0) {
		bpf_mprog_read_fp(peer, j, &fpp);
		bpf_mprog_write_fp(fpp, ntuple);
		bpf_mprog_write_cp(&cpp[j], ntuple);
		j++;
	}
	for (i = 0; i <= total; i++) {
		bpf_mprog_read_fp(peer, j, &fpp);
		if (idx == i && (flags & BPF_F_AFTER)) {
			bpf_mprog_write(fpp, &cpp[j], ntuple);
			j++;
			bpf_mprog_read_fp(peer, j, &fpp);
		}
		if (i < total) {
			bpf_mprog_read(entry, i, &fp, &cp);
			bpf_mprog_copy(fpp, &cpp[j], fp, cp);
			j++;
		}
		if (idx == i && (flags & BPF_F_BEFORE)) {
			bpf_mprog_read_fp(peer, j, &fpp);
			bpf_mprog_write(fpp, &cpp[j], ntuple);
			j++;
		}
	}
	bpf_mprog_commit_cp(peer, cpp);
	bpf_mprog_inc(peer);
	return BPF_MPROG_SWAP;
}

static int bpf_mprog_tuple_confirm(struct bpf_mprog_entry *entry,
				   struct bpf_tuple *dtuple, int idx)
{
	int first = 0, last = bpf_mprog_total(entry) - 1;
	struct bpf_mprog_cp *cp;
	struct bpf_mprog_fp *fp;
	struct bpf_prog *prog;
	struct bpf_link *link;

	if (idx <= first)
		bpf_mprog_read(entry, first, &fp, &cp);
	else if (idx >= last)
		bpf_mprog_read(entry, last, &fp, &cp);
	else
		bpf_mprog_read(entry, idx, &fp, &cp);

	prog = READ_ONCE(fp->prog);
	link = cp->link;
	if (!dtuple->link && link)
		return -EBUSY;

	WARN_ON_ONCE(dtuple->prog && dtuple->prog != prog);
	WARN_ON_ONCE(dtuple->link && dtuple->link != link);

	dtuple->prog = prog;
	dtuple->link = link;
	return 0;
}

static int bpf_mprog_delete(struct bpf_mprog_entry *entry,
			    struct bpf_tuple *dtuple, int idx)
{
	int i = 0, j, ret, total = bpf_mprog_total(entry);
	struct bpf_mprog_cp *cp, cpp[BPF_MPROG_MAX] = {};
	struct bpf_mprog_fp *fp, *fpp;
	struct bpf_mprog_entry *peer;

	ret = bpf_mprog_tuple_confirm(entry, dtuple, idx);
	if (ret)
		return ret;
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	if (idx < 0)
		i++;
	if (idx == total)
		total--;
	for (j = 0; i < total; i++) {
		if (idx == i)
			continue;
		bpf_mprog_read_fp(peer, j, &fpp);
		bpf_mprog_read(entry, i, &fp, &cp);
		bpf_mprog_copy(fpp, &cpp[j], fp, cp);
		j++;
	}
	bpf_mprog_commit_cp(peer, cpp);
	bpf_mprog_dec(peer);
	bpf_mprog_mark_ref(peer, dtuple);
	return bpf_mprog_total(peer) ?
	       BPF_MPROG_SWAP : BPF_MPROG_FREE;
}

/* In bpf_mprog_pos_*() we evaluate the target position for the BPF
 * program/link that needs to be replaced, inserted or deleted for
 * each "rule" independently. If all rules agree on that position
 * or existing element, then enact replacement, addition or deletion.
 * If this is not the case, then the request cannot be satisfied and
 * we bail out with an error.
 */
static int bpf_mprog_pos_exact(struct bpf_mprog_entry *entry,
			       struct bpf_tuple *tuple)
{
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	int i;

	for (i = 0; i < bpf_mprog_total(entry); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		if (tuple->prog == READ_ONCE(fp->prog))
			return tuple->link == cp->link ? i : -EBUSY;
	}
	return -ENOENT;
}

static int bpf_mprog_pos_before(struct bpf_mprog_entry *entry,
				struct bpf_tuple *tuple)
{
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	int i;

	for (i = 0; i < bpf_mprog_total(entry); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		if (tuple->prog == READ_ONCE(fp->prog) &&
		    (!tuple->link || tuple->link == cp->link))
			return i - 1;
	}
	return tuple->prog ? -ENOENT : -1;
}

static int bpf_mprog_pos_after(struct bpf_mprog_entry *entry,
			       struct bpf_tuple *tuple)
{
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	int i;

	for (i = 0; i < bpf_mprog_total(entry); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		if (tuple->prog == READ_ONCE(fp->prog) &&
		    (!tuple->link || tuple->link == cp->link))
			return i + 1;
	}
	return tuple->prog ? -ENOENT : bpf_mprog_total(entry);
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *prog_new,
		     struct bpf_link *link, struct bpf_prog *prog_old,
		     u32 flags, u32 object, u64 revision)
{
	struct bpf_tuple rtuple, ntuple = {
		.prog = prog_new,
		.link = link,
	}, otuple = {
		.prog = prog_old,
		.link = link,
	};
	int ret, idx = -2, tidx;

	if (revision && revision != bpf_mprog_revision(entry))
		return -ESTALE;
	if (bpf_mprog_exists(entry, prog_new))
		return -EEXIST;
	ret = bpf_mprog_tuple_relative(&rtuple, object,
				       flags & ~BPF_F_REPLACE,
				       prog_new->type);
	if (ret)
		return ret;
	if (flags & BPF_F_REPLACE) {
		tidx = bpf_mprog_pos_exact(entry, &otuple);
		if (tidx < 0) {
			ret = tidx;
			goto out;
		}
		idx = tidx;
	}
	if (flags & BPF_F_BEFORE) {
		tidx = bpf_mprog_pos_before(entry, &rtuple);
		if (tidx < -1 || (idx >= -1 && tidx != idx)) {
			ret = tidx < -1 ? tidx : -EDOM;
			goto out;
		}
		idx = tidx;
	}
	if (flags & BPF_F_AFTER) {
		tidx = bpf_mprog_pos_after(entry, &rtuple);
		if (tidx < -1 || (idx >= -1 && tidx != idx)) {
			ret = tidx < 0 ? tidx : -EDOM;
			goto out;
		}
		idx = tidx;
	}
	if (idx < -1) {
		if (rtuple.prog || flags) {
			ret = -EINVAL;
			goto out;
		}
		idx = bpf_mprog_total(entry);
		flags = BPF_F_AFTER;
	}
	if (idx >= bpf_mprog_max()) {
		ret = -EDOM;
		goto out;
	}
	if (flags & BPF_F_REPLACE)
		ret = bpf_mprog_replace(entry, &ntuple, idx);
	else
		ret = bpf_mprog_insert(entry, &ntuple, idx, flags);
out:
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object, u64 revision)
{
	struct bpf_tuple rtuple, dtuple = {
		.prog = prog,
		.link = link,
	};
	int ret, idx = -2, tidx;

	if (flags & BPF_F_REPLACE)
		return -EINVAL;
	if (revision && revision != bpf_mprog_revision(entry))
		return -ESTALE;
	ret = bpf_mprog_tuple_relative(&rtuple, object, flags,
				       prog ? prog->type :
				       BPF_PROG_TYPE_UNSPEC);
	if (ret)
		return ret;
	if (dtuple.prog) {
		tidx = bpf_mprog_pos_exact(entry, &dtuple);
		if (tidx < 0) {
			ret = tidx;
			goto out;
		}
		idx = tidx;
	}
	if (flags & BPF_F_BEFORE) {
		tidx = bpf_mprog_pos_before(entry, &rtuple);
		if (tidx < -1 || (idx >= -1 && tidx != idx)) {
			ret = tidx < -1 ? tidx : -EDOM;
			goto out;
		}
		idx = tidx;
	}
	if (flags & BPF_F_AFTER) {
		tidx = bpf_mprog_pos_after(entry, &rtuple);
		if (tidx < -1 || (idx >= -1 && tidx != idx)) {
			ret = tidx < 0 ? tidx : -EDOM;
			goto out;
		}
		idx = tidx;
	}
	if (idx < -1) {
		if (rtuple.prog || flags) {
			ret = -EINVAL;
			goto out;
		}
		idx = bpf_mprog_total(entry);
		flags = BPF_F_AFTER;
	}
	if (idx >= bpf_mprog_max()) {
		ret = -EDOM;
		goto out;
	}
	ret = bpf_mprog_delete(entry, &dtuple, idx);
out:
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry)
{
	u32 __user *uprog_flags, *ulink_flags;
	u32 __user *uprog_id, *ulink_id;
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;
	struct bpf_prog *prog;
	const u32 flags = 0;
	int i, ret = 0;
	u32 id, count;
	u64 revision;

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
	uprog_flags = u64_to_user_ptr(attr->query.prog_attach_flags);
	ulink_id = u64_to_user_ptr(attr->query.link_ids);
	ulink_flags = u64_to_user_ptr(attr->query.link_attach_flags);
	if (attr->query.count == 0 || !uprog_id || !count)
		return 0;
	if (attr->query.count < count) {
		count = attr->query.count;
		ret = -ENOSPC;
	}
	for (i = 0; i < bpf_mprog_max(); i++) {
		bpf_mprog_read(entry, i, &fp, &cp);
		prog = READ_ONCE(fp->prog);
		if (!prog)
			break;
		id = prog->aux->id;
		if (copy_to_user(uprog_id + i, &id, sizeof(id)))
			return -EFAULT;
		if (uprog_flags &&
		    copy_to_user(uprog_flags + i, &flags, sizeof(flags)))
			return -EFAULT;
		id = cp->link ? cp->link->id : 0;
		if (ulink_id &&
		    copy_to_user(ulink_id + i, &id, sizeof(id)))
			return -EFAULT;
		if (ulink_flags &&
		    copy_to_user(ulink_flags + i, &flags, sizeof(flags)))
			return -EFAULT;
		if (i + 1 == count)
			break;
	}
	return ret;
}
