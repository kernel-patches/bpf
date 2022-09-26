// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF: Filesystem in Userspace with BPF
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/fdtable.h>
#include <linux/filter.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/bpf_fuse.h>

struct bpf_prog *fuse_get_bpf_prog(struct file *file)
{
	struct bpf_prog *bpf_prog = ERR_PTR(-EINVAL);

	if (!file || IS_ERR(file))
		return bpf_prog;

	if (file->f_op != &bpf_prog_fops)
		return bpf_prog;

	bpf_prog = file->private_data;
	if (bpf_prog->type == BPF_PROG_TYPE_FUSE)
		bpf_prog_inc(bpf_prog);
	else
		bpf_prog = ERR_PTR(-EINVAL);

	return bpf_prog;
}

void fuse_get_backing_path(struct file *file, struct path *path)
{
	path_get(&file->f_path);
	*path = file->f_path;
}

int parse_fuse_entry_bpf(struct fuse_entry_bpf *feb)
{
	struct fuse_entry_bpf_out *febo = &feb->out;
	struct bpf_prog *bpf;
	struct file *file;
	int err = 0;

	if (febo->backing_action == FUSE_ACTION_REPLACE) {
		file = fget(febo->backing_fd);
		if (!file) {
			err = -EBADF;
			goto out_err;
		}
		fuse_get_backing_path(file, &feb->backing_path);
		fput(file);
	}
	if (febo->bpf_action == FUSE_ACTION_REPLACE) {
		file = fget(febo->bpf_fd);
		if (!file) {
			err = -EBADF;
			goto out_put;
		}
		bpf = fuse_get_bpf_prog(file);
		if (IS_ERR(bpf)) {
			err = PTR_ERR(bpf);
			goto out_fput;
		}
		feb->bpf = bpf;
		fput(file);
	}

	return 0;
out_fput:
	fput(file);
out_put:
	path_put_init(&feb->backing_path);
out_err:
	return err;
}

int fuse_lseek_initialize_in(struct bpf_fuse_args *fa, struct fuse_lseek_io *flio,
			     struct file *file, loff_t offset, int whence)
{
	struct fuse_file *fuse_file = file->private_data;

	flio->fli = (struct fuse_lseek_in) {
		.fh = fuse_file->fh,
		.offset = offset,
		.whence = whence,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(file->f_inode),
		.opcode = FUSE_LSEEK,
		.in_numargs = 1,
		.in_args[0].size = sizeof(flio->fli),
		.in_args[0].value = &flio->fli,
	};

	return 0;
}

int fuse_lseek_initialize_out(struct bpf_fuse_args *fa, struct fuse_lseek_io *flio,
			      struct file *file, loff_t offset, int whence)
{
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(flio->flo);
	fa->out_args[0].value = &flio->flo;

	return 0;
}

int fuse_lseek_backing(struct bpf_fuse_args *fa, loff_t *out,
		       struct file *file, loff_t offset, int whence)
{
	const struct fuse_lseek_in *fli = fa->in_args[0].value;
	struct fuse_lseek_out *flo = fa->out_args[0].value;
	struct fuse_file *fuse_file = file->private_data;
	struct file *backing_file = fuse_file->backing_file;

	/* TODO: Handle changing of the file handle */
	if (offset == 0) {
		if (whence == SEEK_CUR) {
			flo->offset = file->f_pos;
			*out = flo->offset;
			return 0;
		}

		if (whence == SEEK_SET) {
			flo->offset = vfs_setpos(file, 0, 0);
			*out = flo->offset;
			return 0;
		}
	}

	inode_lock(file->f_inode);
	backing_file->f_pos = file->f_pos;
	*out = vfs_llseek(backing_file, fli->offset, fli->whence);
	flo->offset = *out;
	inode_unlock(file->f_inode);
	return 0;
}

int fuse_lseek_finalize(struct bpf_fuse_args *fa, loff_t *out,
			struct file *file, loff_t offset, int whence)
{
	struct fuse_lseek_out *flo = fa->out_args[0].value;

	if (!fa->error_in)
		file->f_pos = flo->offset;
	*out = flo->offset;
	return 0;
}

ssize_t fuse_backing_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct fuse_file *ff = file->private_data;
	struct inode *fuse_inode = file_inode(file);
	struct file *backing_file = ff->backing_file;
	struct inode *backing_inode = file_inode(backing_file);

	if (!backing_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(backing_file);

	ret = call_mmap(vma->vm_file, vma);

	if (ret)
		fput(backing_file);
	else
		fput(file);

	if (file->f_flags & O_NOATIME)
		return ret;

	if ((!timespec64_equal(&fuse_inode->i_mtime, &backing_inode->i_mtime) ||
	     !timespec64_equal(&fuse_inode->i_ctime,
			       &backing_inode->i_ctime))) {
		fuse_inode->i_mtime = backing_inode->i_mtime;
		fuse_inode->i_ctime = backing_inode->i_ctime;
	}
	touch_atime(&file->f_path);

	return ret;
}

int fuse_file_fallocate_initialize_in(struct bpf_fuse_args *fa,
				      struct fuse_fallocate_in *ffi,
				      struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;

	*ffi = (struct fuse_fallocate_in) {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode,
	};

	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_FALLOCATE,
		.nodeid = ff->nodeid,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*ffi),
		.in_args[0].value = ffi,
	};

	return 0;
}

int fuse_file_fallocate_initialize_out(struct bpf_fuse_args *fa,
				       struct fuse_fallocate_in *ffi,
				       struct file *file, int mode, loff_t offset, loff_t length)
{
	return 0;
}

int fuse_file_fallocate_backing(struct bpf_fuse_args *fa, int *out,
				struct file *file, int mode, loff_t offset, loff_t length)
{
	const struct fuse_fallocate_in *ffi = fa->in_args[0].value;
	struct fuse_file *ff = file->private_data;

	*out = vfs_fallocate(ff->backing_file, ffi->mode, ffi->offset,
			     ffi->length);
	return 0;
}

int fuse_file_fallocate_finalize(struct bpf_fuse_args *fa, int *out,
				 struct file *file, int mode, loff_t offset, loff_t length)
{
	return 0;
}

/*******************************************************************************
 * Directory operations after here                                             *
 ******************************************************************************/

int fuse_lookup_initialize_in(struct bpf_fuse_args *fa, struct fuse_lookup_io *fli,
			      struct inode *dir, struct dentry *entry, unsigned int flags)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dir)->nodeid,
		.opcode = FUSE_LOOKUP,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_lookup_initialize_out(struct bpf_fuse_args *fa, struct fuse_lookup_io *fli,
			       struct inode *dir, struct dentry *entry, unsigned int flags)
{
	fa->out_numargs = 2;
	fa->flags = FUSE_BPF_OUT_ARGVAR | FUSE_BPF_IS_LOOKUP;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(fli->feo),
		.value = &fli->feo,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = sizeof(fli->feb.out),
		.value = &fli->feb.out,
	};

	return 0;
}

int fuse_lookup_backing(struct bpf_fuse_args *fa, struct dentry **out, struct inode *dir,
			struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fuse_entry = get_fuse_dentry(entry);
	struct fuse_dentry *dir_fuse_entry = get_fuse_dentry(entry->d_parent);
	struct dentry *dir_backing_entry = dir_fuse_entry->backing_path.dentry;
	struct inode *dir_backing_inode = dir_backing_entry->d_inode;
	struct dentry *backing_entry;
	const char *name;
	int len;

	/* TODO this will not handle lookups over mount points */
	inode_lock_nested(dir_backing_inode, I_MUTEX_PARENT);
	if (fa->in_args[0].flags & BPF_FUSE_MODIFIED) {
		name = (char *)fa->in_args[0].value;
		len = strnlen(name, fa->in_args[0].size);
	} else {
		name = entry->d_name.name;
		len = entry->d_name.len;
	}
	backing_entry = lookup_one_len(name, dir_backing_entry, len);
	inode_unlock(dir_backing_inode);

	if (IS_ERR(backing_entry))
		return PTR_ERR(backing_entry);

	fuse_entry->backing_path = (struct path) {
		.dentry = backing_entry,
		.mnt = dir_fuse_entry->backing_path.mnt,
	};

	mntget(fuse_entry->backing_path.mnt);
	return 0;
}

int fuse_handle_backing(struct fuse_entry_bpf *feb, struct path *backing_path)
{
	switch (feb->out.backing_action) {
	case FUSE_ACTION_KEEP:
		/* backing inode/path are added in fuse_lookup_backing */
		break;

	case FUSE_ACTION_REMOVE:
		path_put_init(backing_path);
		break;

	case FUSE_ACTION_REPLACE: {
		if (!feb->backing_path.dentry)
			return -EINVAL;

		path_put(backing_path);
		*backing_path = feb->backing_path;
		feb->backing_path.dentry = NULL;
		feb->backing_path.mnt = NULL;

		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

int fuse_handle_bpf_prog(struct fuse_entry_bpf *feb, struct inode *parent,
			 struct bpf_prog **bpf)
{
	struct fuse_inode *pi;

	// Parent isn't presented, but we want to keep
	// Don't touch bpf program at all in this case
	if (feb->out.bpf_action == FUSE_ACTION_KEEP && !parent)
		goto out;

	if (*bpf) {
		bpf_prog_put(*bpf);
		*bpf = NULL;
	}

	switch (feb->out.bpf_action) {
	case FUSE_ACTION_KEEP:
		pi = get_fuse_inode(parent);
		*bpf = pi->bpf;
		if (*bpf)
			bpf_prog_inc(*bpf);
		break;

	case FUSE_ACTION_REMOVE:
		break;

	case FUSE_ACTION_REPLACE: {
		struct bpf_prog *bpf_prog = feb->bpf;

		if (IS_ERR(bpf_prog))
			return PTR_ERR(bpf_prog);

		*bpf = bpf_prog;
		break;
	}

	default:
		return -EINVAL;
	}

out:
	return 0;
}

int fuse_lookup_finalize(struct bpf_fuse_args *fa, struct dentry **out,
			 struct inode *dir, struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fd;
	struct dentry *backing_dentry;
	struct inode *inode, *backing_inode;
	struct inode *d_inode = entry->d_inode;
	struct fuse_entry_out *feo = fa->out_args[0].value;
	struct fuse_entry_bpf_out *febo = fa->out_args[1].value;
	struct fuse_entry_bpf *feb = container_of(febo, struct fuse_entry_bpf, out);
	int error = -1;
	u64 target_nodeid = 0;

	fd = get_fuse_dentry(entry);
	if (!fd)
		return -EIO;
	error = fuse_handle_backing(feb, &fd->backing_path);
	if (error)
		return error;
	backing_dentry = fd->backing_path.dentry;
	if (!backing_dentry)
		return -ENOENT;
	backing_inode = backing_dentry->d_inode;
	if (!backing_inode) {
		*out = 0;
		return 0;
	}

	if (d_inode)
		target_nodeid = get_fuse_inode(d_inode)->nodeid;

	inode = fuse_iget_backing(dir->i_sb, target_nodeid, backing_inode);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	error = fuse_handle_bpf_prog(feb, dir, &get_fuse_inode(inode)->bpf);
	if (error)
		return error;

	get_fuse_inode(inode)->nodeid = feo->nodeid;

	*out = d_splice_alias(inode, entry);
	return 0;
}

int fuse_revalidate_backing(struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fuse_dentry = get_fuse_dentry(entry);
	struct dentry *backing_entry = fuse_dentry->backing_path.dentry;

	spin_lock(&backing_entry->d_lock);
	if (d_unhashed(backing_entry)) {
		spin_unlock(&backing_entry->d_lock);
		return 0;
	}
	spin_unlock(&backing_entry->d_lock);

	if (unlikely(backing_entry->d_flags & DCACHE_OP_REVALIDATE))
		return backing_entry->d_op->d_revalidate(backing_entry, flags);
	return 1;
}

int fuse_access_initialize_in(struct bpf_fuse_args *fa, struct fuse_access_in *fai,
			      struct inode *inode, int mask)
{
	*fai = (struct fuse_access_in) {
		.mask = mask,
	};

	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_ACCESS,
		.nodeid = get_node_id(inode),
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fai),
		.in_args[0].value = fai,
	};

	return 0;
}

int fuse_access_initialize_out(struct bpf_fuse_args *fa, struct fuse_access_in *fai,
			       struct inode *inode, int mask)
{
	return 0;
}

int fuse_access_backing(struct bpf_fuse_args *fa, int *out, struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	const struct fuse_access_in *fai = fa->in_args[0].value;

	*out = inode_permission(&init_user_ns, fi->backing_inode, fai->mask);
	return 0;
}

int fuse_access_finalize(struct bpf_fuse_args *fa, int *out, struct inode *inode, int mask)
{
	return 0;
}

