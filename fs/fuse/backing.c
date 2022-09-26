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

#define FUSE_BPF_IOCB_MASK (IOCB_APPEND | IOCB_DSYNC | IOCB_HIPRI | IOCB_NOWAIT | IOCB_SYNC)

struct fuse_bpf_aio_req {
	struct kiocb iocb;
	refcount_t ref;
	struct kiocb *iocb_orig;
};

static struct kmem_cache *fuse_bpf_aio_request_cachep;

static void fuse_file_accessed(struct file *dst_file, struct file *src_file)
{
	struct inode *dst_inode;
	struct inode *src_inode;

	if (dst_file->f_flags & O_NOATIME)
		return;

	dst_inode = file_inode(dst_file);
	src_inode = file_inode(src_file);

	if ((!timespec64_equal(&dst_inode->i_mtime, &src_inode->i_mtime) ||
	     !timespec64_equal(&dst_inode->i_ctime, &src_inode->i_ctime))) {
		dst_inode->i_mtime = src_inode->i_mtime;
		dst_inode->i_ctime = src_inode->i_ctime;
	}

	touch_atime(&dst_file->f_path);
}

static void fuse_copyattr(struct file *dst_file, struct file *src_file)
{
	struct inode *dst = file_inode(dst_file);
	struct inode *src = file_inode(src_file);

	dst->i_atime = src->i_atime;
	dst->i_mtime = src->i_mtime;
	dst->i_ctime = src->i_ctime;
	i_size_write(dst, i_size_read(src));
}

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

int fuse_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_open_io *foio,
			    struct inode *inode, struct file *file, bool isdir)
{
	foio->foi = (struct fuse_open_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(foio->foi),
			.value = &foio->foi,
		},
	};

	return 0;
}

int fuse_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_open_io *foio,
			     struct inode *inode, struct file *file, bool isdir)
{
	foio->foo = (struct fuse_open_out) { 0 };

	fa->out_numargs = 1;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(foio->foo),
		.value = &foio->foo,
	};

	return 0;
}

int fuse_open_backing(struct bpf_fuse_args *fa, int *out,
		      struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	const struct fuse_open_in *foi = fa->in_args[0].value;
	struct fuse_file *ff;
	int mask;
	struct fuse_dentry *fd = get_fuse_dentry(file->f_path.dentry);
	struct file *backing_file;

	ff = fuse_file_alloc(fm);
	if (!ff)
		return -ENOMEM;
	file->private_data = ff;

	switch (foi->flags & O_ACCMODE) {
	case O_RDONLY:
		mask = MAY_READ;
		break;

	case O_WRONLY:
		mask = MAY_WRITE;
		break;

	case O_RDWR:
		mask = MAY_READ | MAY_WRITE;
		break;

	default:
		return -EINVAL;
	}

	*out = inode_permission(&init_user_ns,
				  get_fuse_inode(inode)->backing_inode, mask);
	if (*out)
		return *out;

	backing_file =
		dentry_open(&fd->backing_path, foi->flags, current_cred());

	if (IS_ERR(backing_file)) {
		fuse_file_free(ff);
		file->private_data = NULL;
		return PTR_ERR(backing_file);
	}
	ff->backing_file = backing_file;

	*out = 0;
	return 0;
}

int fuse_open_finalize(struct bpf_fuse_args *fa, int *out,
		       struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_open_out *foo = fa->out_args[0].value;

	if (ff)
		ff->fh = foo->fh;
	return 0;
}

int fuse_create_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_create_open_io *fcoio,
				   struct inode *dir, struct dentry *entry,
				   struct file *file, unsigned int flags, umode_t mode)
{
	fcoio->fci = (struct fuse_create_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
		.mode = mode,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_CREATE,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(fcoio->fci),
			.value = &fcoio->fci,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_create_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_create_open_io *fcoio,
				    struct inode *dir, struct dentry *entry,
				    struct file *file, unsigned int flags, umode_t mode)
{
	fcoio->feo = (struct fuse_entry_out) { 0 };
	fcoio->foo = (struct fuse_open_out) { 0 };

	fa->out_numargs = 2;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(fcoio->feo),
		.value = &fcoio->feo,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = sizeof(fcoio->foo),
		.value = &fcoio->foo,
	};

	return 0;
}

static int fuse_open_file_backing(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct dentry *entry = file->f_path.dentry;
	struct fuse_dentry *fuse_dentry = get_fuse_dentry(entry);
	struct fuse_file *fuse_file;
	struct file *backing_file;

	fuse_file = fuse_file_alloc(fm);
	if (!fuse_file)
		return -ENOMEM;
	file->private_data = fuse_file;

	backing_file = dentry_open(&fuse_dentry->backing_path, file->f_flags,
				   current_cred());
	if (IS_ERR(backing_file)) {
		fuse_file_free(fuse_file);
		file->private_data = NULL;
		return PTR_ERR(backing_file);
	}
	fuse_file->backing_file = backing_file;

	return 0;
}

int fuse_create_open_backing(struct bpf_fuse_args *fa, int *out,
			     struct inode *dir, struct dentry *entry,
			     struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_inode *dir_fuse_inode = get_fuse_inode(dir);
	struct path backing_path;
	struct inode *inode = NULL;
	struct dentry *backing_parent;
	struct dentry *newent;
	const struct fuse_create_in *fci = fa->in_args[0].value;

	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	if (!dir_fuse_inode)
		return -EIO;

	if (IS_ERR(backing_path.dentry))
		return PTR_ERR(backing_path.dentry);

	if (d_really_is_positive(backing_path.dentry)) {
		*out = -EIO;
		goto out;
	}

	backing_parent = dget_parent(backing_path.dentry);
	inode_lock_nested(dir_fuse_inode->backing_inode, I_MUTEX_PARENT);
	*out = vfs_create(&init_user_ns, d_inode(backing_parent),
			backing_path.dentry, fci->mode, true);
	inode_unlock(d_inode(backing_parent));
	dput(backing_parent);
	if (*out)
		goto out;

	inode = fuse_iget_backing(dir->i_sb, 0, backing_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		*out = PTR_ERR(inode);
		goto out;
	}

	if (get_fuse_inode(inode)->bpf)
		bpf_prog_put(get_fuse_inode(inode)->bpf);
	get_fuse_inode(inode)->bpf = dir_fuse_inode->bpf;
	if (get_fuse_inode(inode)->bpf)
		bpf_prog_inc(dir_fuse_inode->bpf);

	newent = d_splice_alias(inode, entry);
	if (IS_ERR(newent)) {
		*out = PTR_ERR(newent);
		goto out;
	}

	entry = newent ? newent : entry;
	*out = finish_open(file, entry, fuse_open_file_backing);

out:
	path_put(&backing_path);
	return *out;
}

int fuse_create_open_finalize(struct bpf_fuse_args *fa, int *out,
				struct inode *dir, struct dentry *entry,
				struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(file->f_inode);
	struct fuse_entry_out *feo = fa->out_args[0].value;
	struct fuse_open_out *foo = fa->out_args[1].value;

	if (fi)
		fi->nodeid = feo->nodeid;
	if (ff)
		ff->fh = foo->fh;
	return 0;
}

int fuse_release_initialize_in(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
			       struct inode *inode, struct file *file)
{
	struct fuse_file *fuse_file = file->private_data;

	/* Always put backing file whatever bpf/userspace says */
	fput(fuse_file->backing_file);

	*fri = (struct fuse_release_in) {
		.fh = ((struct fuse_file *)(file->private_data))->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = FUSE_RELEASE,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

int fuse_release_initialize_out(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
				struct inode *inode, struct file *file)
{
	return 0;
}

int fuse_releasedir_initialize_in(struct bpf_fuse_args *fa,
				  struct fuse_release_in *fri,
				  struct inode *inode, struct file *file)
{
	struct fuse_file *fuse_file = file->private_data;

	/* Always put backing file whatever bpf/userspace says */
	fput(fuse_file->backing_file);

	*fri = (struct fuse_release_in) {
		.fh = ((struct fuse_file *)(file->private_data))->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(inode)->nodeid,
		.opcode = FUSE_RELEASEDIR,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

int fuse_releasedir_initialize_out(struct bpf_fuse_args *fa,
				   struct fuse_release_in *fri,
				   struct inode *inode, struct file *file)
{
	return 0;
}

int fuse_release_backing(struct bpf_fuse_args *fa, int *out,
			 struct inode *inode, struct file *file)
{
	return 0;
}

int fuse_release_finalize(struct bpf_fuse_args *fa, int *out,
			  struct inode *inode, struct file *file)
{
	fuse_file_free(file->private_data);
	*out = 0;
	return 0;
}

int fuse_flush_initialize_in(struct bpf_fuse_args *fa, struct fuse_flush_in *ffi,
			     struct file *file, fl_owner_t id)
{
	struct fuse_file *fuse_file = file->private_data;

	*ffi = (struct fuse_flush_in) {
		.fh = fuse_file->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(file->f_inode),
		.opcode = FUSE_FLUSH,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*ffi),
		.in_args[0].value = ffi,
		.flags = FUSE_BPF_FORCE,
	};

	return 0;
}

int fuse_flush_initialize_out(struct bpf_fuse_args *fa, struct fuse_flush_in *ffi,
			      struct file *file, fl_owner_t id)
{
	return 0;
}

int fuse_flush_backing(struct bpf_fuse_args *fa, int *out, struct file *file, fl_owner_t id)
{
	struct fuse_file *fuse_file = file->private_data;
	struct file *backing_file = fuse_file->backing_file;

	*out = 0;
	if (backing_file->f_op->flush)
		*out = backing_file->f_op->flush(backing_file, id);
	return *out;
}

int fuse_flush_finalize(struct bpf_fuse_args *fa, int *out, struct file *file, fl_owner_t id)
{
	return 0;
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

int fuse_copy_file_range_initialize_in(struct bpf_fuse_args *fa,
					struct fuse_copy_file_range_io *fcf,
					struct file *file_in, loff_t pos_in, struct file *file_out,
					loff_t pos_out, size_t len, unsigned int flags)
{
	struct fuse_file *fuse_file_in = file_in->private_data;
	struct fuse_file *fuse_file_out = file_out->private_data;

	fcf->fci = (struct fuse_copy_file_range_in) {
		.fh_in = fuse_file_in->fh,
		.off_in = pos_in,
		.nodeid_out = fuse_file_out->nodeid,
		.fh_out = fuse_file_out->fh,
		.off_out = pos_out,
		.len = len,
		.flags = flags,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(file_in->f_inode),
		.opcode = FUSE_COPY_FILE_RANGE,
		.in_numargs = 1,
		.in_args[0].size = sizeof(fcf->fci),
		.in_args[0].value = &fcf->fci,
	};

	return 0;
}

int fuse_copy_file_range_initialize_out(struct bpf_fuse_args *fa,
					struct fuse_copy_file_range_io *fcf,
					struct file *file_in, loff_t pos_in, struct file *file_out,
					loff_t pos_out, size_t len, unsigned int flags)
{
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fcf->fwo);
	fa->out_args[0].value = &fcf->fwo;

	return 0;
}

int fuse_copy_file_range_backing(struct bpf_fuse_args *fa, ssize_t *out, struct file *file_in,
				 loff_t pos_in, struct file *file_out, loff_t pos_out, size_t len,
				 unsigned int flags)
{
	const struct fuse_copy_file_range_in *fci = fa->in_args[0].value;
	struct fuse_file *fuse_file_in = file_in->private_data;
	struct file *backing_file_in = fuse_file_in->backing_file;
	struct fuse_file *fuse_file_out = file_out->private_data;
	struct file *backing_file_out = fuse_file_out->backing_file;

	/* TODO: Handle changing of in/out files */
	if (backing_file_out)
		*out = vfs_copy_file_range(backing_file_in, fci->off_in, backing_file_out,
					   fci->off_out, fci->len, fci->flags);
	else
		*out = generic_copy_file_range(file_in, pos_in, file_out, pos_out, len,
					       flags);
	return 0;
}

int fuse_copy_file_range_finalize(struct bpf_fuse_args *fa, ssize_t *out, struct file *file_in,
				  loff_t pos_in, struct file *file_out, loff_t pos_out, size_t len,
				  unsigned int flags)
{
	return 0;
}

int fuse_fsync_initialize_in(struct bpf_fuse_args *fa, struct fuse_fsync_in *ffi,
			     struct file *file, loff_t start, loff_t end, int datasync)
{
	struct fuse_file *fuse_file = file->private_data;

	*ffi = (struct fuse_fsync_in) {
		.fh = fuse_file->fh,
		.fsync_flags = datasync ? FUSE_FSYNC_FDATASYNC : 0,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(file->f_inode)->nodeid,
		.opcode = FUSE_FSYNC,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*ffi),
		.in_args[0].value = ffi,
		.flags = FUSE_BPF_FORCE,
	};

	return 0;
}

int fuse_fsync_initialize_out(struct bpf_fuse_args *fa, struct fuse_fsync_in *ffi,
			      struct file *file, loff_t start, loff_t end, int datasync)
{
	return 0;
}

int fuse_fsync_backing(struct bpf_fuse_args *fa, int *out,
		       struct file *file, loff_t start, loff_t end, int datasync)
{
	struct fuse_file *fuse_file = file->private_data;
	struct file *backing_file = fuse_file->backing_file;
	const struct fuse_fsync_in *ffi = fa->in_args[0].value;
	int new_datasync = (ffi->fsync_flags & FUSE_FSYNC_FDATASYNC) ? 1 : 0;

	*out = vfs_fsync(backing_file, new_datasync);
	return 0;
}

int fuse_fsync_finalize(struct bpf_fuse_args *fa, int *out,
			struct file *file, loff_t start, loff_t end, int datasync)
{
	return 0;
}

int fuse_dir_fsync_initialize_in(struct bpf_fuse_args *fa, struct fuse_fsync_in *ffi,
				 struct file *file, loff_t start, loff_t end, int datasync)
{
	struct fuse_file *fuse_file = file->private_data;

	*ffi = (struct fuse_fsync_in) {
		.fh = fuse_file->fh,
		.fsync_flags = datasync ? FUSE_FSYNC_FDATASYNC : 0,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(file->f_inode)->nodeid,
		.opcode = FUSE_FSYNCDIR,
		.in_numargs = 1,
		.in_args[0].size = sizeof(*ffi),
		.in_args[0].value = ffi,
		.flags = FUSE_BPF_FORCE,
	};

	return 0;
}

int fuse_dir_fsync_initialize_out(struct bpf_fuse_args *fa, struct fuse_fsync_in *ffi,
				  struct file *file, loff_t start, loff_t end, int datasync)
{
	return 0;
}

int fuse_getxattr_initialize_in(struct bpf_fuse_args *fa,
				struct fuse_getxattr_io *fgio,
				struct dentry *dentry, const char *name, void *value,
				size_t size)
{
	*fgio = (struct fuse_getxattr_io) {
		.fgi.size = size,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dentry->d_inode)->nodeid,
		.opcode = FUSE_GETXATTR,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(fgio->fgi),
			.value = &fgio->fgi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = strlen(name) + 1,
			.max_size = XATTR_NAME_MAX + 1,
			.flags = BPF_FUSE_MUST_ALLOCATE | BPF_FUSE_VARIABLE_SIZE,
			.value =  (void *) name,
		},
	};

	return 0;
}

int fuse_getxattr_initialize_out(struct bpf_fuse_args *fa,
				 struct fuse_getxattr_io *fgio,
				 struct dentry *dentry, const char *name, void *value,
				 size_t size)
{
	fa->flags = size ? FUSE_BPF_OUT_ARGVAR : 0;
	fa->out_numargs = 1;
	if (size) {
		fa->out_args[0].size = size;
		fa->out_args[0].max_size = size;
		fa->out_args[0].flags = BPF_FUSE_VARIABLE_SIZE;
		fa->out_args[0].value = value;
	} else {
		fa->out_args[0].size = sizeof(fgio->fgo);
		fa->out_args[0].value = &fgio->fgo;
	}
	return 0;
}

int fuse_getxattr_backing(struct bpf_fuse_args *fa, int *out,
			  struct dentry *dentry, const char *name, void *value,
			  size_t size)
{
	ssize_t ret = vfs_getxattr(&init_user_ns,
				   get_fuse_dentry(dentry)->backing_path.dentry,
				   fa->in_args[1].value, value, size);

	if (fa->flags & FUSE_BPF_OUT_ARGVAR)
		fa->out_args[0].size = ret;
	else
		((struct fuse_getxattr_out *)fa->out_args[0].value)->size = ret;

	return 0;
}

int fuse_getxattr_finalize(struct bpf_fuse_args *fa, int *out,
			   struct dentry *dentry, const char *name, void *value,
			   size_t size)
{
	struct fuse_getxattr_out *fgo;

	if (fa->flags & FUSE_BPF_OUT_ARGVAR) {
		*out = fa->out_args[0].size;
		return 0;
	}

	fgo = fa->out_args[0].value;

	*out = fgo->size;
	return 0;
}

int fuse_listxattr_initialize_in(struct bpf_fuse_args *fa,
				 struct fuse_getxattr_io *fgio,
				 struct dentry *dentry, char *list, size_t size)
{
	*fgio = (struct fuse_getxattr_io) {
		.fgi.size = size,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dentry->d_inode)->nodeid,
		.opcode = FUSE_LISTXATTR,
		.in_numargs = 1,
		.in_args[0] =
			(struct bpf_fuse_arg) {
				.size = sizeof(fgio->fgi),
				.value = &fgio->fgi,
			},
	};

	return 0;
}

int fuse_listxattr_initialize_out(struct bpf_fuse_args *fa,
				  struct fuse_getxattr_io *fgio,
				  struct dentry *dentry, char *list, size_t size)
{
	fa->out_numargs = 1;

	if (size) {
		fa->flags = FUSE_BPF_OUT_ARGVAR;
		fa->out_args[0].size = size;
		fa->out_args[0].max_size = size;
		fa->out_args[0].flags = BPF_FUSE_VARIABLE_SIZE;
		fa->out_args[0].value = (void *)list;
	} else {
		fa->out_args[0].size = sizeof(fgio->fgo);
		fa->out_args[0].value = &fgio->fgo;
	}
	return 0;
}

int fuse_listxattr_backing(struct bpf_fuse_args *fa, ssize_t *out, struct dentry *dentry,
			   char *list, size_t size)
{
	*out = vfs_listxattr(get_fuse_dentry(dentry)->backing_path.dentry, list, size);

	if (*out < 0)
		return *out;

	if (fa->flags & FUSE_BPF_OUT_ARGVAR)
		fa->out_args[0].size = *out;
	else
		((struct fuse_getxattr_out *)fa->out_args[0].value)->size = *out;

	return 0;
}

int fuse_listxattr_finalize(struct bpf_fuse_args *fa, ssize_t *out, struct dentry *dentry,
			    char *list, size_t size)
{
	struct fuse_getxattr_out *fgo;

	if (fa->error_in)
		return 0;

	if (fa->flags & FUSE_BPF_OUT_ARGVAR) {
		*out = fa->out_args[0].size;
		return 0;
	}

	fgo = fa->out_args[0].value;
	*out = fgo->size;
	return 0;
}

int fuse_setxattr_initialize_in(struct bpf_fuse_args *fa,
				struct fuse_setxattr_in *fsxi,
				struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	*fsxi = (struct fuse_setxattr_in) {
		.size = size,
		.flags = flags,
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dentry->d_inode)->nodeid,
		.opcode = FUSE_SETXATTR,
		.in_numargs = 3,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fsxi),
			.value = fsxi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = strlen(name) + 1,
			.max_size = XATTR_NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) name,
		},
		.in_args[2] = (struct bpf_fuse_arg) {
			.size = size,
			.max_size = XATTR_SIZE_MAX,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value = (void *) value,
		},
	};

	return 0;
}

int fuse_setxattr_initialize_out(struct bpf_fuse_args *fa,
				 struct fuse_setxattr_in *fsxi,
				 struct dentry *dentry, const char *name,
				 const void *value, size_t size, int flags)
{
	return 0;
}

int fuse_setxattr_backing(struct bpf_fuse_args *fa, int *out, struct dentry *dentry,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	*out = vfs_setxattr(&init_user_ns,
			    get_fuse_dentry(dentry)->backing_path.dentry, name,
			    (void *) value, size, flags);
	return 0;
}

int fuse_setxattr_finalize(struct bpf_fuse_args *fa, int *out, struct dentry *dentry,
			   const char *name, const void *value, size_t size,
			   int flags)
{
	return 0;
}

int fuse_removexattr_initialize_in(struct bpf_fuse_args *fa,
				   struct fuse_dummy_io *unused,
				   struct dentry *dentry, const char *name)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_fuse_inode(dentry->d_inode)->nodeid,
		.opcode = FUSE_REMOVEXATTR,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = strlen(name) + 1,
			.max_size = XATTR_NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) name,
		},
	};

	return 0;
}

int fuse_removexattr_initialize_out(struct bpf_fuse_args *fa,
				    struct fuse_dummy_io *unused,
				    struct dentry *dentry, const char *name)
{
	return 0;
}

int fuse_removexattr_backing(struct bpf_fuse_args *fa, int *out,
			     struct dentry *dentry, const char *name)
{
	struct path *backing_path = &get_fuse_dentry(dentry)->backing_path;

	/* TODO account for changes of the name by prefilter */
	*out = vfs_removexattr(&init_user_ns, backing_path->dentry, name);
	return 0;
}

int fuse_removexattr_finalize(struct bpf_fuse_args *fa, int *out,
			      struct dentry *dentry, const char *name)
{
	return 0;
}

static inline void fuse_bpf_aio_put(struct fuse_bpf_aio_req *aio_req)
{
	if (refcount_dec_and_test(&aio_req->ref))
		kmem_cache_free(fuse_bpf_aio_request_cachep, aio_req);
}

static void fuse_bpf_aio_cleanup_handler(struct fuse_bpf_aio_req *aio_req)
{
	struct kiocb *iocb = &aio_req->iocb;
	struct kiocb *iocb_orig = aio_req->iocb_orig;

	if (iocb->ki_flags & IOCB_WRITE) {
		__sb_writers_acquired(file_inode(iocb->ki_filp)->i_sb,
				      SB_FREEZE_WRITE);
		file_end_write(iocb->ki_filp);
		fuse_copyattr(iocb_orig->ki_filp, iocb->ki_filp);
	}
	iocb_orig->ki_pos = iocb->ki_pos;
	fuse_bpf_aio_put(aio_req);
}

static void fuse_bpf_aio_rw_complete(struct kiocb *iocb, long res)
{
	struct fuse_bpf_aio_req *aio_req =
		container_of(iocb, struct fuse_bpf_aio_req, iocb);
	struct kiocb *iocb_orig = aio_req->iocb_orig;

	fuse_bpf_aio_cleanup_handler(aio_req);
	iocb_orig->ki_complete(iocb_orig, res);
}

int fuse_file_read_iter_initialize_in(struct bpf_fuse_args *fa, struct fuse_file_read_iter_io *fri,
				      struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	fri->fri = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = iocb->ki_pos,
		.size = to->count,
	};

	/* TODO we can't assume 'to' is a kvec */
	/* TODO we also can't assume the vector has only one component */
	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_READ,
		.nodeid = ff->nodeid,
		.in_numargs = 1,
		.in_args[0].size = sizeof(fri->fri),
		.in_args[0].value = &fri->fri,
		/*
		 * TODO Design this properly.
		 * Possible approach: do not pass buf to bpf
		 * If going to userland, do a deep copy
		 * For extra credit, do that to/from the vector, rather than
		 * making an extra copy in the kernel
		 */
	};

	return 0;
}

int fuse_file_read_iter_initialize_out(struct bpf_fuse_args *fa, struct fuse_file_read_iter_io *fri,
				       struct kiocb *iocb, struct iov_iter *to)
{
	fri->frio = (struct fuse_read_iter_out) {
		.ret = fri->fri.size,
	};

	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fri->frio);
	fa->out_args[0].value = &fri->frio;

	return 0;
}

int fuse_file_read_iter_backing(struct bpf_fuse_args *fa, ssize_t *out,
				struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio = fa->out_args[0].value;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	if (!iov_iter_count(to))
		return 0;

	if ((iocb->ki_flags & IOCB_DIRECT) &&
	    (!ff->backing_file->f_mapping->a_ops ||
	     !ff->backing_file->f_mapping->a_ops->direct_IO))
		return -EINVAL;

	/* TODO This just plain ignores any change to fuse_read_in */
	if (is_sync_kiocb(iocb)) {
		*out = vfs_iter_read(ff->backing_file, to, &iocb->ki_pos,
				iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
	} else {
		struct fuse_bpf_aio_req *aio_req;

		*out = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		aio_req->iocb_orig = iocb;
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		*out = vfs_iocb_iter_read(ff->backing_file, &aio_req->iocb, to);
		fuse_bpf_aio_put(aio_req);
		if (*out != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req);
	}

	frio->ret = *out;

	/* TODO Need to point value at the buffer for post-modification */

out:
	fuse_file_accessed(file, ff->backing_file);

	return *out;
}

int fuse_file_read_iter_finalize(struct bpf_fuse_args *fa, ssize_t *out,
				 struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio = fa->out_args[0].value;

	*out = frio->ret;

	return 0;
}

int fuse_file_write_iter_initialize_in(struct bpf_fuse_args *fa,
				       struct fuse_file_write_iter_io *fwio,
				       struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	*fwio = (struct fuse_file_write_iter_io) {
		.fwi.fh = ff->fh,
		.fwi.offset = iocb->ki_pos,
		.fwi.size = from->count,
	};

	/* TODO we can't assume 'from' is a kvec */
	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_WRITE,
		.nodeid = ff->nodeid,
		.in_numargs = 2,
		.in_args[0].size = sizeof(fwio->fwi),
		.in_args[0].value = &fwio->fwi,
		.in_args[1].size = fwio->fwi.size,
		.in_args[1].value = from->kvec->iov_base,
	};

	return 0;
}

int fuse_file_write_iter_initialize_out(struct bpf_fuse_args *fa,
					struct fuse_file_write_iter_io *fwio,
					struct kiocb *iocb, struct iov_iter *from)
{
	/* TODO we can't assume 'from' is a kvec */
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fwio->fwio);
	fa->out_args[0].value = &fwio->fwio;

	return 0;
}

int fuse_file_write_iter_backing(struct bpf_fuse_args *fa, ssize_t *out,
				 struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;

	if (!iov_iter_count(from))
		return 0;

	/* TODO This just plain ignores any change to fuse_write_in */
	/* TODO uint32_t seems smaller than ssize_t.... right? */
	inode_lock(file_inode(file));

	fuse_copyattr(file, ff->backing_file);

	if (is_sync_kiocb(iocb)) {
		file_start_write(ff->backing_file);
		*out = vfs_iter_write(ff->backing_file, from, &iocb->ki_pos,
					   iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
		file_end_write(ff->backing_file);

		/* Must reflect change in size of backing file to upper file */
		if (*out > 0)
			fuse_copyattr(file, ff->backing_file);
	} else {
		struct fuse_bpf_aio_req *aio_req;

		*out = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		file_start_write(ff->backing_file);
		__sb_writers_release(file_inode(ff->backing_file)->i_sb, SB_FREEZE_WRITE);
		aio_req->iocb_orig = iocb;
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		*out = vfs_iocb_iter_write(ff->backing_file, &aio_req->iocb, from);
		fuse_bpf_aio_put(aio_req);
		if (*out != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req);
	}

out:
	inode_unlock(file_inode(file));
	fwio->ret = *out;
	if (*out < 0)
		return *out;
	return 0;
}

int fuse_file_write_iter_finalize(struct bpf_fuse_args *fa, ssize_t *out,
				  struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;

	*out = fwio->ret;
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

int fuse_mknod_initialize_in(struct bpf_fuse_args *fa, struct fuse_mknod_in *fmi,
			     struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	*fmi = (struct fuse_mknod_in) {
		.mode = mode,
		.rdev = new_encode_dev(rdev),
		.umask = current_umask(),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_MKNOD,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fmi),
			.value = fmi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_mknod_initialize_out(struct bpf_fuse_args *fa, struct fuse_mknod_in *fmi,
			      struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return 0;
}

int fuse_mknod_backing(struct bpf_fuse_args *fa, int *out,
		       struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	const struct fuse_mknod_in *fmi = fa->in_args[0].value;
	struct fuse_inode *fuse_inode = get_fuse_inode(dir);
	struct inode *backing_inode = fuse_inode->backing_inode;
	struct path backing_path;
	struct inode *inode = NULL;

	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	mode = fmi->mode;
	if (!IS_POSIXACL(backing_inode))
		mode &= ~fmi->umask;
	*out = vfs_mknod(&init_user_ns, backing_inode, backing_path.dentry, mode,
			new_decode_dev(fmi->rdev));
	inode_unlock(backing_inode);
	if (*out)
		goto out;
	if (d_really_is_negative(backing_path.dentry) ||
	    unlikely(d_unhashed(backing_path.dentry))) {
		*out = -EINVAL;
		/**
		 * TODO: overlayfs responds to this situation with a
		 * lookupOneLen. Should we do that too?
		 */
		goto out;
	}
	inode = fuse_iget_backing(dir->i_sb, fuse_inode->nodeid, backing_inode);
	if (IS_ERR(inode)) {
		*out = PTR_ERR(inode);
		goto out;
	}
	d_instantiate(entry, inode);
out:
	path_put(&backing_path);
	return *out;
}

int fuse_mknod_finalize(struct bpf_fuse_args *fa, int *out,
			  struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return 0;
}

int fuse_mkdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_mkdir_in *fmi,
			     struct inode *dir, struct dentry *entry, umode_t mode)
{
	*fmi = (struct fuse_mkdir_in) {
		.mode = mode,
		.umask = current_umask(),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_MKDIR,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fmi),
			.value = fmi,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_mkdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_mkdir_in *fmi,
			      struct inode *dir, struct dentry *entry, umode_t mode)
{
	return 0;
}

int fuse_mkdir_backing(struct bpf_fuse_args *fa, int *out,
		       struct inode *dir, struct dentry *entry, umode_t mode)
{
	const struct fuse_mkdir_in *fmi = fa->in_args[0].value;
	struct fuse_inode *fuse_inode = get_fuse_inode(dir);
	struct inode *backing_inode = fuse_inode->backing_inode;
	struct path backing_path;
	struct inode *inode = NULL;
	struct dentry *d;

	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	mode = fmi->mode;
	if (!IS_POSIXACL(backing_inode))
		mode &= ~fmi->umask;
	*out = vfs_mkdir(&init_user_ns, backing_inode, backing_path.dentry,
			mode);
	if (*out)
		goto out;
	if (d_really_is_negative(backing_path.dentry) ||
	    unlikely(d_unhashed(backing_path.dentry))) {
		d = lookup_one_len(entry->d_name.name,
				   backing_path.dentry->d_parent,
				   entry->d_name.len);
		if (IS_ERR(d)) {
			*out = PTR_ERR(d);
			goto out;
		}
		dput(backing_path.dentry);
		backing_path.dentry = d;
	}
	inode = fuse_iget_backing(dir->i_sb, fuse_inode->nodeid, backing_inode);
	if (IS_ERR(inode)) {
		*out = PTR_ERR(inode);
		goto out;
	}
	d_instantiate(entry, inode);
out:
	inode_unlock(backing_inode);
	path_put(&backing_path);
	return *out;
}

int fuse_mkdir_finalize(struct bpf_fuse_args *fa, int *out,
			  struct inode *dir, struct dentry *entry, umode_t mode)
{
	return 0;
}

int fuse_rmdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			     struct inode *dir, struct dentry *entry)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_RMDIR,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_rmdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			      struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_rmdir_backing(struct bpf_fuse_args *fa, int *out,
		       struct inode *dir, struct dentry *entry)
{
	struct path backing_path;
	struct dentry *backing_parent_dentry;
	struct inode *backing_inode;

	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	backing_parent_dentry = dget_parent(backing_path.dentry);
	backing_inode = d_inode(backing_parent_dentry);

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	*out = vfs_rmdir(&init_user_ns, backing_inode, backing_path.dentry);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!*out)
		d_drop(entry);
	path_put(&backing_path);
	return *out;
}

int fuse_rmdir_finalize(struct bpf_fuse_args *fa, int *out, struct inode *dir, struct dentry *entry)
{
	return 0;
}

static int fuse_rename_backing_common(struct inode *olddir,
				      struct dentry *oldent,
				      struct inode *newdir,
				      struct dentry *newent, unsigned int flags)
{
	int err = 0;
	struct path old_backing_path;
	struct path new_backing_path;
	struct dentry *old_backing_dir_dentry;
	struct dentry *old_backing_dentry;
	struct dentry *new_backing_dir_dentry;
	struct dentry *new_backing_dentry;
	struct dentry *trap = NULL;
	struct inode *target_inode;
	struct renamedata rd;

	//TODO Actually deal with changing anything that isn't a flag
	get_fuse_backing_path(oldent, &old_backing_path);
	if (!old_backing_path.dentry)
		return -EBADF;
	get_fuse_backing_path(newent, &new_backing_path);
	if (!new_backing_path.dentry) {
		/*
		 * TODO A file being moved from a backing path to another
		 * backing path which is not yet instrumented with FUSE-BPF.
		 * This may be slow and should be substituted with something
		 * more clever.
		 */
		err = -EXDEV;
		goto put_old_path;
	}
	if (new_backing_path.mnt != old_backing_path.mnt) {
		err = -EXDEV;
		goto put_new_path;
	}
	old_backing_dentry = old_backing_path.dentry;
	new_backing_dentry = new_backing_path.dentry;
	old_backing_dir_dentry = dget_parent(old_backing_dentry);
	new_backing_dir_dentry = dget_parent(new_backing_dentry);
	target_inode = d_inode(newent);

	trap = lock_rename(old_backing_dir_dentry, new_backing_dir_dentry);
	if (trap == old_backing_dentry) {
		err = -EINVAL;
		goto put_parents;
	}
	if (trap == new_backing_dentry) {
		err = -ENOTEMPTY;
		goto put_parents;
	}

	rd = (struct renamedata) {
		.old_mnt_userns = &init_user_ns,
		.old_dir = d_inode(old_backing_dir_dentry),
		.old_dentry = old_backing_dentry,
		.new_mnt_userns = &init_user_ns,
		.new_dir = d_inode(new_backing_dir_dentry),
		.new_dentry = new_backing_dentry,
		.flags = flags,
	};
	err = vfs_rename(&rd);
	if (err)
		goto unlock;
	if (target_inode)
		fsstack_copy_attr_all(target_inode,
				get_fuse_inode(target_inode)->backing_inode);
	fsstack_copy_attr_all(d_inode(oldent), d_inode(old_backing_dentry));
unlock:
	unlock_rename(old_backing_dir_dentry, new_backing_dir_dentry);
put_parents:
	dput(new_backing_dir_dentry);
	dput(old_backing_dir_dentry);
put_new_path:
	path_put(&new_backing_path);
put_old_path:
	path_put(&old_backing_path);
	return err;
}

int fuse_rename2_initialize_in(struct bpf_fuse_args *fa, struct fuse_rename2_in *fri,
			       struct inode *olddir, struct dentry *oldent,
			       struct inode *newdir, struct dentry *newent,
			       unsigned int flags)
{
	*fri = (struct fuse_rename2_in) {
		.newdir = get_node_id(newdir),
		.flags = flags,
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(olddir),
		.opcode = FUSE_RENAME2,
		.in_numargs = 3,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fri),
			.value = fri,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = oldent->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) oldent->d_name.name,
		},
		.in_args[2] = (struct bpf_fuse_arg) {
			.size = newent->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) newent->d_name.name,
		},
	};

	return 0;
}

int fuse_rename2_initialize_out(struct bpf_fuse_args *fa, struct fuse_rename2_in *fri,
				struct inode *olddir, struct dentry *oldent,
				struct inode *newdir, struct dentry *newent,
				unsigned int flags)
{
	return 0;
}

int fuse_rename2_backing(struct bpf_fuse_args *fa, int *out,
			 struct inode *olddir, struct dentry *oldent,
			 struct inode *newdir, struct dentry *newent,
			 unsigned int flags)
{
	const struct fuse_rename2_in *fri = fa->in_args[0].value;

	/* TODO: deal with changing dirs/ents */
	*out = fuse_rename_backing_common(olddir, oldent, newdir, newent,
					  fri->flags);
	return *out;
}

int fuse_rename2_finalize(struct bpf_fuse_args *fa, int *out,
			  struct inode *olddir, struct dentry *oldent,
			  struct inode *newdir, struct dentry *newent,
			  unsigned int flags)
{
	return 0;
}

int fuse_rename_initialize_in(struct bpf_fuse_args *fa, struct fuse_rename_in *fri,
			      struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent)
{
	*fri = (struct fuse_rename_in) {
		.newdir = get_node_id(newdir),
	};
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(olddir),
		.opcode = FUSE_RENAME,
		.in_numargs = 3,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(*fri),
			.value = fri,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = oldent->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) oldent->d_name.name,
		},
		.in_args[2] = (struct bpf_fuse_arg) {
			.size = newent->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) newent->d_name.name,
		},
	};

	return 0;
}

int fuse_rename_initialize_out(struct bpf_fuse_args *fa, struct fuse_rename_in *fri,
			       struct inode *olddir, struct dentry *oldent,
			       struct inode *newdir, struct dentry *newent)
{
	return 0;
}

int fuse_rename_backing(struct bpf_fuse_args *fa, int *out,
			struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent)
{
	/* TODO: deal with changing dirs/ents */
	*out = fuse_rename_backing_common(olddir, oldent, newdir, newent, 0);
	return *out;
}

int fuse_rename_finalize(struct bpf_fuse_args *fa, int *out,
			 struct inode *olddir, struct dentry *oldent,
			 struct inode *newdir, struct dentry *newent)
{
	return 0;
}

int fuse_unlink_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			      struct inode *dir, struct dentry *entry)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_UNLINK,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
	};

	return 0;
}

int fuse_unlink_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *dummy,
			       struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_unlink_backing(struct bpf_fuse_args *fa, int *out, struct inode *dir, struct dentry *entry)
{
	struct path backing_path;
	struct dentry *backing_parent_dentry;
	struct inode *backing_inode;

	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	/* TODO Not sure if we should reverify like overlayfs, or get inode from d_parent */
	backing_parent_dentry = dget_parent(backing_path.dentry);
	backing_inode = d_inode(backing_parent_dentry);

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	*out = vfs_unlink(&init_user_ns, backing_inode, backing_path.dentry,
			 NULL);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!*out)
		d_drop(entry);
	path_put(&backing_path);
	return *out;
}

int fuse_unlink_finalize(struct bpf_fuse_args *fa, int *out,
			 struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_link_initialize_in(struct bpf_fuse_args *fa, struct fuse_link_in *fli,
			    struct dentry *entry, struct inode *dir,
			    struct dentry *newent)
{
	struct inode *src_inode = entry->d_inode;

	*fli = (struct fuse_link_in) {
		.oldnodeid = get_node_id(src_inode),
	};

	fa->opcode = FUSE_LINK;
	fa->in_numargs = 2;
	fa->in_args[0].size = sizeof(*fli);
	fa->in_args[0].value = fli;
	fa->in_args[1].size = newent->d_name.len + 1;
	fa->in_args[1].max_size = NAME_MAX + 1;
	fa->in_args[1].value = (void *) newent->d_name.name;
	fa->in_args[1].flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE;

	return 0;
}

int fuse_link_initialize_out(struct bpf_fuse_args *fa, struct fuse_link_in *fli,
			     struct dentry *entry, struct inode *dir,
			     struct dentry *newent)
{
	return 0;
}

int fuse_link_backing(struct bpf_fuse_args *fa, int *out, struct dentry *entry,
		      struct inode *dir, struct dentry *newent)
{
	struct path backing_old_path;
	struct path backing_new_path;
	struct dentry *backing_dir_dentry;
	struct inode *fuse_new_inode = NULL;
	struct fuse_inode *fuse_dir_inode = get_fuse_inode(dir);
	struct inode *backing_dir_inode = fuse_dir_inode->backing_inode;

	*out = 0;
	get_fuse_backing_path(entry, &backing_old_path);
	if (!backing_old_path.dentry)
		return -EBADF;

	get_fuse_backing_path(newent, &backing_new_path);
	if (!backing_new_path.dentry) {
		*out = -EBADF;
		goto err_dst_path;
	}

	backing_dir_dentry = dget_parent(backing_new_path.dentry);
	backing_dir_inode = d_inode(backing_dir_dentry);

	inode_lock_nested(backing_dir_inode, I_MUTEX_PARENT);
	*out = vfs_link(backing_old_path.dentry, &init_user_ns,
		       backing_dir_inode, backing_new_path.dentry, NULL);
	inode_unlock(backing_dir_inode);
	if (*out)
		goto out;

	if (d_really_is_negative(backing_new_path.dentry) ||
	    unlikely(d_unhashed(backing_new_path.dentry))) {
		*out = -EINVAL;
		/**
		 * TODO: overlayfs responds to this situation with a
		 * lookupOneLen. Should we do that too?
		 */
		goto out;
	}

	fuse_new_inode = fuse_iget_backing(dir->i_sb, fuse_dir_inode->nodeid, backing_dir_inode);
	if (IS_ERR(fuse_new_inode)) {
		*out = PTR_ERR(fuse_new_inode);
		goto out;
	}
	d_instantiate(newent, fuse_new_inode);

out:
	dput(backing_dir_dentry);
	path_put(&backing_new_path);
err_dst_path:
	path_put(&backing_old_path);
	return *out;
}

int fuse_link_finalize(struct bpf_fuse_args *fa, int *out, struct dentry *entry,
		       struct inode *dir, struct dentry *newent)
{
	return 0;
}

int fuse_getattr_initialize_in(struct bpf_fuse_args *fa, struct fuse_getattr_io *fgio,
			       const struct dentry *entry, struct kstat *stat,
			       u32 request_mask, unsigned int flags)
{
	fgio->fgi = (struct fuse_getattr_in) {
		.getattr_flags = flags,
		.fh = -1, /* TODO is this OK? */
	};

	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(entry->d_inode),
		.opcode = FUSE_GETATTR,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(fgio->fgi),
			.value = &fgio->fgi,
		},
	};

	return 0;
}

int fuse_getattr_initialize_out(struct bpf_fuse_args *fa, struct fuse_getattr_io *fgio,
				const struct dentry *entry, struct kstat *stat,
				u32 request_mask, unsigned int flags)
{
	fgio->fao = (struct fuse_attr_out) { 0 };

	fa->out_numargs = 1;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(fgio->fao),
		.value = &fgio->fao,
	};

	return 0;
}

static void fuse_stat_to_attr(struct fuse_conn *fc, struct inode *inode,
			      struct kstat *stat, struct fuse_attr *attr)
{
	unsigned int blkbits;

	/* see the comment in fuse_change_attributes() */
	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		stat->size = i_size_read(inode);
		stat->mtime.tv_sec = inode->i_mtime.tv_sec;
		stat->mtime.tv_nsec = inode->i_mtime.tv_nsec;
		stat->ctime.tv_sec = inode->i_ctime.tv_sec;
		stat->ctime.tv_nsec = inode->i_ctime.tv_nsec;
	}

	attr->ino = stat->ino;
	attr->mode = (inode->i_mode & S_IFMT) | (stat->mode & 07777);
	attr->nlink = stat->nlink;
	attr->uid = from_kuid(fc->user_ns, stat->uid);
	attr->gid = from_kgid(fc->user_ns, stat->gid);
	attr->atime = stat->atime.tv_sec;
	attr->atimensec = stat->atime.tv_nsec;
	attr->mtime = stat->mtime.tv_sec;
	attr->mtimensec = stat->mtime.tv_nsec;
	attr->ctime = stat->ctime.tv_sec;
	attr->ctimensec = stat->ctime.tv_nsec;
	attr->size = stat->size;
	attr->blocks = stat->blocks;

	if (stat->blksize != 0)
		blkbits = ilog2(stat->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	attr->blksize = 1 << blkbits;
}

int fuse_getattr_backing(struct bpf_fuse_args *fa, int *out,
			 const struct dentry *entry, struct kstat *stat,
			 u32 request_mask, unsigned int flags)
{
	struct path *backing_path = &get_fuse_dentry(entry)->backing_path;
	struct inode *backing_inode = backing_path->dentry->d_inode;
	struct fuse_attr_out *fao = fa->out_args[0].value;
	struct kstat tmp;

	if (!stat)
		stat = &tmp;

	*out = vfs_getattr(backing_path, stat, request_mask, flags);

	if (!*out)
		fuse_stat_to_attr(get_fuse_conn(entry->d_inode), backing_inode,
				  stat, &fao->attr);

	return 0;
}

int fuse_getattr_finalize(struct bpf_fuse_args *fa, int *out,
			  const struct dentry *entry, struct kstat *stat,
			  u32 request_mask, unsigned int flags)
{
	struct fuse_attr_out *outarg = fa->out_args[0].value;
	struct inode *inode = entry->d_inode;
	u64 attr_version = fuse_get_attr_version(get_fuse_mount(inode)->fc);

	/* TODO: Ensure this doesn't happen if we had an error getting attrs in
	 * backing.
	 */
	*out = finalize_attr(inode, outarg, attr_version, stat);
	return 0;
}

static void fattr_to_iattr(struct fuse_conn *fc,
			   const struct fuse_setattr_in *arg,
			   struct iattr *iattr)
{
	unsigned int fvalid = arg->valid;

	if (fvalid & FATTR_MODE)
		iattr->ia_valid |= ATTR_MODE, iattr->ia_mode = arg->mode;
	if (fvalid & FATTR_UID) {
		iattr->ia_valid |= ATTR_UID;
		iattr->ia_uid = make_kuid(fc->user_ns, arg->uid);
	}
	if (fvalid & FATTR_GID) {
		iattr->ia_valid |= ATTR_GID;
		iattr->ia_gid = make_kgid(fc->user_ns, arg->gid);
	}
	if (fvalid & FATTR_SIZE)
		iattr->ia_valid |= ATTR_SIZE, iattr->ia_size = arg->size;
	if (fvalid & FATTR_ATIME) {
		iattr->ia_valid |= ATTR_ATIME;
		iattr->ia_atime.tv_sec = arg->atime;
		iattr->ia_atime.tv_nsec = arg->atimensec;
		if (!(fvalid & FATTR_ATIME_NOW))
			iattr->ia_valid |= ATTR_ATIME_SET;
	}
	if (fvalid & FATTR_MTIME) {
		iattr->ia_valid |= ATTR_MTIME;
		iattr->ia_mtime.tv_sec = arg->mtime;
		iattr->ia_mtime.tv_nsec = arg->mtimensec;
		if (!(fvalid & FATTR_MTIME_NOW))
			iattr->ia_valid |= ATTR_MTIME_SET;
	}
	if (fvalid & FATTR_CTIME) {
		iattr->ia_valid |= ATTR_CTIME;
		iattr->ia_ctime.tv_sec = arg->ctime;
		iattr->ia_ctime.tv_nsec = arg->ctimensec;
	}
}

int fuse_setattr_initialize_in(struct bpf_fuse_args *fa, struct fuse_setattr_io *fsio,
			       struct dentry *dentry, struct iattr *attr, struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(dentry->d_inode);

	*fsio = (struct fuse_setattr_io) { 0 };
	iattr_to_fattr(fc, attr, &fsio->fsi, true);

	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_SETATTR,
		.nodeid = get_node_id(dentry->d_inode),
		.in_numargs = 1,
		.in_args[0].size = sizeof(fsio->fsi),
		.in_args[0].value = &fsio->fsi,
	};

	return 0;
}

int fuse_setattr_initialize_out(struct bpf_fuse_args *fa, struct fuse_setattr_io *fsio,
				struct dentry *dentry, struct iattr *attr, struct file *file)
{
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fsio->fao);
	fa->out_args[0].value = &fsio->fao;

	return 0;
}

int fuse_setattr_backing(struct bpf_fuse_args *fa, int *out,
			 struct dentry *dentry, struct iattr *attr, struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(dentry->d_inode);
	const struct fuse_setattr_in *fsi = fa->in_args[0].value;
	struct iattr new_attr = { 0 };
	struct path *backing_path = &get_fuse_dentry(dentry)->backing_path;

	fattr_to_iattr(fc, fsi, &new_attr);
	/* TODO: Some info doesn't get saved by the attr->fattr->attr transition
	 * When we actually allow the bpf to change these, we may have to consider
	 * the extra flags more, or pass more info into the bpf. Until then we can
	 * keep everything except for ATTR_FILE, since we'd need a file on the
	 * lower fs. For what it's worth, neither f2fs nor ext4 make use of that
	 * even if it is present.
	 */
	new_attr.ia_valid = attr->ia_valid & ~ATTR_FILE;
	inode_lock(d_inode(backing_path->dentry));
	*out = notify_change(&init_user_ns, backing_path->dentry, &new_attr,
			    NULL);
	inode_unlock(d_inode(backing_path->dentry));

	if (*out == 0 && (new_attr.ia_valid & ATTR_SIZE))
		i_size_write(dentry->d_inode, new_attr.ia_size);
	return 0;
}

int fuse_setattr_finalize(struct bpf_fuse_args *fa, int *out,
			  struct dentry *dentry, struct iattr *attr, struct file *file)
{
	return 0;
}

int fuse_statfs_initialize_in(struct bpf_fuse_args *fa, struct fuse_statfs_out *fso,
			      struct dentry *dentry, struct kstatfs *buf)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(d_inode(dentry)),
		.opcode = FUSE_STATFS,
	};

	return 0;
}

int fuse_statfs_initialize_out(struct bpf_fuse_args *fa, struct fuse_statfs_out *fso,
			       struct dentry *dentry, struct kstatfs *buf)
{
	*fso = (struct fuse_statfs_out) { 0 };

	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(fso);
	fa->out_args[0].value = fso;

	return 0;
}

int fuse_statfs_backing(struct bpf_fuse_args *fa, int *out,
			struct dentry *dentry, struct kstatfs *buf)
{
	struct path backing_path;
	struct fuse_statfs_out *fso = fa->out_args[0].value;

	*out = 0;
	get_fuse_backing_path(dentry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;
	*out = vfs_statfs(&backing_path, buf);
	path_put(&backing_path);
	buf->f_type = FUSE_SUPER_MAGIC;

	//TODO Provide postfilter opportunity to modify
	if (!*out)
		convert_statfs_to_fuse(&fso->st, buf);

	return 0;
}

int fuse_statfs_finalize(struct bpf_fuse_args *fa, int *out,
			 struct dentry *dentry, struct kstatfs *buf)
{
	struct fuse_statfs_out *fso = fa->out_args[0].value;

	if (!fa->error_in)
		convert_fuse_statfs(buf, &fso->st);
	return 0;
}

int fuse_get_link_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *unused,
				struct inode *inode, struct dentry *dentry,
				struct delayed_call *callback)
{
	/*
	 * TODO
	 * If we want to handle changing these things, we'll need to copy
	 * the lower fs's data into our own buffer, and provide our own callback
	 * to free that buffer.
	 *
	 * Pre could change the name we're looking at
	 * postfilter can change the name we return
	 *
	 * We ought to only make that buffer if it's been requested, so leaving
	 * this unimplemented for the moment
	 */
	*fa = (struct bpf_fuse_args) {
		.opcode = FUSE_READLINK,
		.nodeid = get_node_id(inode),
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = dentry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value =  (void *) dentry->d_name.name,
		},
		/*
		 * .out_argvar = 1,
		 * .out_numargs = 1,
		 * .out_args[0].size = ,
		 * .out_args[0].value = ,
		 */
	};

	return 0;
}

int fuse_get_link_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *unused,
				 struct inode *inode, struct dentry *dentry,
				 struct delayed_call *callback)
{
	/*
	 * .out_argvar = 1,
	 * .out_numargs = 1,
	 * .out_args[0].size = ,
	 * .out_args[0].value = ,
	 */

	return 0;
}

int fuse_get_link_backing(struct bpf_fuse_args *fa, const char **out,
			  struct inode *inode, struct dentry *dentry,
			  struct delayed_call *callback)
{
	struct path backing_path;

	if (!dentry) {
		*out = ERR_PTR(-ECHILD);
		return PTR_ERR(*out);
	}

	get_fuse_backing_path(dentry, &backing_path);
	if (!backing_path.dentry) {
		*out = ERR_PTR(-ECHILD);
		return PTR_ERR(*out);
	}

	/*
	 * TODO: If we want to do our own thing, copy the data and then call the
	 * callback
	 */
	*out = vfs_get_link(backing_path.dentry, callback);

	path_put(&backing_path);
	return 0;
}

int fuse_get_link_finalize(struct bpf_fuse_args *fa, const char **out,
			     struct inode *inode, struct dentry *dentry,
			     struct delayed_call *callback)
{
	return 0;
}

int fuse_symlink_initialize_in(struct bpf_fuse_args *fa, struct fuse_dummy_io *unused,
			       struct inode *dir, struct dentry *entry, const char *link, int len)
{
	*fa = (struct bpf_fuse_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_SYMLINK,
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
			.value =  (void *) entry->d_name.name,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.size = len,
			.max_size = PATH_MAX,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
			.value = (void *) link,
		},
	};

	return 0;
}

int fuse_symlink_initialize_out(struct bpf_fuse_args *fa, struct fuse_dummy_io *unused,
				struct inode *dir, struct dentry *entry, const char *link, int len)
{
	return 0;
}

int fuse_symlink_backing(struct bpf_fuse_args *fa, int *out,
			 struct inode *dir, struct dentry *entry, const char *link, int len)
{
	struct fuse_inode *fuse_inode = get_fuse_inode(dir);
	struct inode *backing_inode = fuse_inode->backing_inode;
	struct path backing_path;
	struct inode *inode = NULL;

	*out = 0;
	//TODO Actually deal with changing the backing entry in symlink
	get_fuse_backing_path(entry, &backing_path);
	if (!backing_path.dentry)
		return -EBADF;

	inode_lock_nested(backing_inode, I_MUTEX_PARENT);
	*out = vfs_symlink(&init_user_ns, backing_inode, backing_path.dentry,
			  link);
	inode_unlock(backing_inode);
	if (*out)
		goto out;
	if (d_really_is_negative(backing_path.dentry) ||
	    unlikely(d_unhashed(backing_path.dentry))) {
		*out = -EINVAL;
		/**
		 * TODO: overlayfs responds to this situation with a
		 * lookupOneLen. Should we do that too?
		 */
		goto out;
	}
	inode = fuse_iget_backing(dir->i_sb, fuse_inode->nodeid, backing_inode);
	if (IS_ERR(inode)) {
		*out = PTR_ERR(inode);
		goto out;
	}
	d_instantiate(entry, inode);
out:
	path_put(&backing_path);
	return *out;
}

int  fuse_symlink_finalize(struct bpf_fuse_args *fa, int *out,
			   struct inode *dir, struct dentry *entry, const char *link, int len)
{
	return 0;
}

int fuse_readdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_read_io *frio,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force, bool is_continued)
{
	struct fuse_file *ff = file->private_data;

	*fa = (struct bpf_fuse_args) {
		.nodeid = ff->nodeid,
		.opcode = FUSE_READDIR,
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(frio->fri),
			.value = &frio->fri,
		},
	};

	frio->fri = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = ctx->pos,
		.size = PAGE_SIZE,
	};

	*force_again = false;
	*allow_force = true;
	return 0;
}

int fuse_readdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_read_io *frio,
				struct file *file, struct dir_context *ctx,
				bool *force_again, bool *allow_force, bool is_continued)
{
	u8 *page = (u8 *)__get_free_page(GFP_KERNEL);

	if (!page)
		return -ENOMEM;

	fa->flags = FUSE_BPF_OUT_ARGVAR;
	fa->out_numargs = 2;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(frio->fro),
		.value = &frio->fro,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = PAGE_SIZE,
		.max_size = PAGE_SIZE,
		.flags = BPF_FUSE_VARIABLE_SIZE,
		.value = page,
	};
	frio->fro = (struct fuse_read_out) {
		.again = 0,
		.offset = 0,
	};

	return 0;
}

struct extfuse_ctx {
	struct dir_context ctx;
	u8 *addr;
	size_t offset;
};

static int filldir(struct dir_context *ctx, const char *name, int namelen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	struct extfuse_ctx *ec = container_of(ctx, struct extfuse_ctx, ctx);
	struct fuse_dirent *fd = (struct fuse_dirent *)(ec->addr + ec->offset);

	if (ec->offset + sizeof(struct fuse_dirent) + namelen > PAGE_SIZE)
		return -ENOMEM;

	*fd = (struct fuse_dirent) {
		.ino = ino,
		.off = offset,
		.namelen = namelen,
		.type = d_type,
	};

	memcpy(fd->name, name, namelen);
	ec->offset += FUSE_DIRENT_SIZE(fd);

	return 0;
}

static int parse_dirfile(char *buf, size_t nbytes, struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		ctx->pos = dirent->off;
		if (!dir_emit(ctx, dirent->name, dirent->namelen, dirent->ino,
				dirent->type))
			break;

		buf += reclen;
		nbytes -= reclen;
	}

	return 0;
}


int fuse_readdir_backing(struct bpf_fuse_args *fa, int *out,
			 struct file *file, struct dir_context *ctx,
			 bool *force_again, bool *allow_force, bool is_continued)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_dir = ff->backing_file;
	struct fuse_read_out *fro = fa->out_args[0].value;
	struct extfuse_ctx ec;

	ec = (struct extfuse_ctx) {
		.ctx.actor = filldir,
		.ctx.pos = ctx->pos,
		.addr = fa->out_args[1].value,
	};

	if (!ec.addr)
		return -ENOMEM;

	if (!is_continued)
		backing_dir->f_pos = file->f_pos;

	*out = iterate_dir(backing_dir, &ec.ctx);
	if (ec.offset == 0)
		*allow_force = false;
	fa->out_args[1].size = ec.offset;

	fro->offset = ec.ctx.pos;
	fro->again = false;

	return *out;
}

int fuse_readdir_finalize(struct bpf_fuse_args *fa, int *out,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force, bool is_continued)
{
	struct fuse_read_out *fro = fa->out_args[0].value;
	struct fuse_file *ff = file->private_data;
	struct file *backing_dir = ff->backing_file;

	*out = parse_dirfile(fa->out_args[1].value, fa->out_args[1].size, ctx);
	*force_again = !!fro->again;
	if (*force_again && !*allow_force)
		*out = -EINVAL;

	ctx->pos = fro->offset;
	backing_dir->f_pos = fro->offset;

	free_page((unsigned long)fa->out_args[1].value);
	return *out;
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

int __init fuse_bpf_init(void)
{
	fuse_bpf_aio_request_cachep = kmem_cache_create("fuse_bpf_aio_req",
						   sizeof(struct fuse_bpf_aio_req),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!fuse_bpf_aio_request_cachep)
		return -ENOMEM;

	return 0;
}

void __exit fuse_bpf_cleanup(void)
{
	kmem_cache_destroy(fuse_bpf_aio_request_cachep);
}

static ssize_t fuse_bpf_simple_request(struct fuse_mount *fm, struct bpf_fuse_args *fa,
				       unsigned short in_numargs, unsigned short out_numargs,
				       struct bpf_fuse_arg *out_arg_array, bool add_out_to_in)
{
	int i;
	uint32_t max_size;
	ssize_t res;

	struct fuse_args args = {
		.nodeid = fa->nodeid,
		.opcode = fa->opcode,
		.error_in = fa->error_in,
		.in_numargs = in_numargs,
		.out_numargs = out_numargs,
		.force = !!(fa->flags & FUSE_BPF_FORCE),
		.out_argvar = !!(fa->flags & FUSE_BPF_OUT_ARGVAR),
		.is_lookup = !!(fa->flags & FUSE_BPF_IS_LOOKUP),
	};

	/* Set in args */
	for (i = 0; i < fa->in_numargs; ++i)
		args.in_args[i] = (struct fuse_in_arg) {
			.size = fa->in_args[i].size,
			.value = fa->in_args[i].value,
		};
	if (add_out_to_in) {
		for (i = 0; i < fa->out_numargs; ++i)
			args.in_args[fa->in_numargs + i] = (struct fuse_in_arg) {
				.size = fa->out_args[i].size,
				.value = fa->out_args[i].value,
			};
	}

	/* All out args must be writeable */
	for (i = 0; i < out_numargs; ++i) {
		max_size = out_arg_array[i].max_size ?: out_arg_array[i].size;
		if (!bpf_fuse_get_writeable(&out_arg_array[i], max_size, true))
			return -ENOMEM;
	}

	/* Set out args */
	for (i = 0; i < out_numargs; ++i)
		args.out_args[i] = (struct fuse_arg) {
			.size = out_arg_array[i].size,
			.value = out_arg_array[i].value,
		};

	res = fuse_simple_request(fm, &args);

	/* update used areas of buffers */
	for (i = 0; i < out_numargs; ++i)
		if (out_arg_array[i].flags & BPF_FUSE_VARIABLE_SIZE)
			out_arg_array[i].size = args.out_args[i].size;
	fa->ret = args.ret;

	return res;
}

ssize_t fuse_prefilter_simple_request(struct fuse_mount *fm, struct bpf_fuse_args *fa)
{
	return fuse_bpf_simple_request(fm, fa, fa->in_numargs, fa->in_numargs,
				       fa->in_args, false);
}

ssize_t fuse_postfilter_simple_request(struct fuse_mount *fm, struct bpf_fuse_args *fa)
{
	return fuse_bpf_simple_request(fm, fa, fa->in_numargs + fa->out_numargs, fa->out_numargs,
				       fa->out_args, true);
}
