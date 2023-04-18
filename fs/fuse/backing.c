// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF: Filesystem in Userspace with BPF
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/bpf_fuse.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/uio.h>

/*
 * expression statement to wrap the backing filter logic
 * struct inode *inode: inode with bpf and backing inode
 * typedef io: (typically complex) type whose components fuse_args can point to.
 *     An instance of this type is created locally and passed to initialize
 * void initialize_in(struct bpf_fuse_args *fa, io *in_out, args...): function that sets
 *     up fa and io based on args
 * void initialize_out(struct bpf_fuse_args *fa, io *in_out, args...): function that sets
 *     up fa and io based on args
 * int backing(struct fuse_bpf_args_internal *fa, args...): function that actually performs
 *     the backing io operation
 * void *finalize(struct fuse_bpf_args *, args...): function that performs any final
 *     work needed to commit the backing io
 */
#define bpf_fuse_backing(inode, io, out,				\
			 initialize_in, initialize_out,			\
			 backing, finalize, args...)			\
({									\
	struct fuse_inode *fuse_inode = get_fuse_inode(inode);		\
	struct bpf_fuse_args fa = { 0 };				\
	bool initialized = false;					\
	bool handled = false;						\
	ssize_t res;							\
	io feo = { 0 };							\
	int error = 0;							\
									\
	do {								\
		if (!inode || !fuse_inode->backing_inode)		\
			break;						\
									\
		handled = true;						\
		error = initialize_in(&fa, &feo, args);			\
		if (error)						\
			break;						\
									\
		error = initialize_out(&fa, &feo, args);		\
		if (error)						\
			break;						\
									\
		initialized = true;					\
									\
		error = backing(&fa, out, args);			\
		if (error < 0)						\
			fa.info.error_in = error;			\
									\
	} while (false);						\
									\
	if (initialized && handled) {					\
		res = finalize(&fa, out, args);				\
		if (res)						\
			error = res;					\
	}								\
									\
	*out = error ? _Generic((*out),					\
			default :					\
				error,					\
			struct dentry * :				\
				ERR_PTR(error),				\
			const char * :					\
				ERR_PTR(error)				\
			) : (*out);					\
	handled;							\
})

#define FUSE_BPF_IOCB_MASK (IOCB_APPEND | IOCB_DSYNC | IOCB_HIPRI | IOCB_NOWAIT | IOCB_SYNC)

struct fuse_bpf_aio_req {
	struct kiocb iocb;
	refcount_t ref;
	struct kiocb *iocb_orig;
	struct timespec64 pre_atime;
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
	fuse_invalidate_attr(dst);
}

static void fuse_file_start_write(struct file *fuse_file, struct file *backing_file,
				  loff_t pos, size_t count)
{
	struct inode *inode = file_inode(fuse_file);
	struct fuse_inode *fi = get_fuse_inode(inode);

	if (inode->i_size < pos + count)
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	file_start_write(backing_file);
}

static void fuse_file_end_write(struct file *fuse_file, struct file *backing_file,
				loff_t pos, size_t res)
{
	struct inode *inode = file_inode(fuse_file);
	struct fuse_inode *fi = get_fuse_inode(inode);

	file_end_write(backing_file);

	if (res > 0)
		fuse_write_update_attr(inode, pos, res);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	fuse_invalidate_attr(inode);
}

static void fuse_file_start_read(struct file *backing_file, struct timespec64 *pre_atime)
{
	*pre_atime = file_inode(backing_file)->i_atime;
}

static void fuse_file_end_read(struct file *fuse_file, struct file *backing_file,
			  struct timespec64 *pre_atime)
{
	/* Mimic atime update policy of passthrough inode, not the value */
	if (!timespec64_equal(&file_inode(backing_file)->i_atime, pre_atime))
		fuse_invalidate_atime(file_inode(fuse_file));
}

static void fuse_get_backing_path(struct file *file, struct path *path)
{
	path_get(&file->f_path);
	*path = file->f_path;
}

static bool has_file(int type)
{
	return type == FUSE_ENTRY_BACKING;
}

/*
 * The optional fuse bpf entry lists the backing file for a particular
 * lookup. These are inherited by default.
 *
 * In the future, we may support multiple bpfs, and multiple backing files for
 * the bpf to choose between.
 *
 * Currently, the expected format is possibly a bpf program, then the backing
 * file. Changing only the bpf is valid, though meaningless if there isn't an
 * inherited backing file.
 *
 * Support for the bpf program will be added in a later patch
 *
 */
int parse_fuse_bpf_entry(struct fuse_bpf_entry *fbe, int num)
{
	struct fuse_bpf_entry_out *fbeo;
	struct file *file;
	bool has_backing = false;
	int num_entries;
	int err = -EINVAL;
	int i;

	if (num > 0)
		num_entries = num;
	else
		num_entries = FUSE_BPF_MAX_ENTRIES;

	for (i = 0; i < num_entries; i++) {
		file = NULL;
		fbeo = &fbe->out[i];

		/* reserved for future use */
		if (fbeo->unused != 0)
			goto out_err;

		if (has_file(fbeo->entry_type)) {
			file = fget(fbeo->fd);
			if (!file) {
				err = -EBADF;
				goto out_err;
			}
		}

		switch (fbeo->entry_type) {
		case 0:
			if (num == -1)
				num_entries = i;
			else
				goto out_err;
			break;
		case FUSE_ENTRY_REMOVE_BACKING:
			if (fbe->backing_action)
				goto out_err;
			fbe->backing_action = FUSE_BPF_REMOVE;
			break;
		case FUSE_ENTRY_BACKING:
			if (fbe->backing_action)
				goto out_err;
			fuse_get_backing_path(file, &fbe->backing_path);
			fbe->backing_action = FUSE_BPF_SET;
			has_backing = true;
			break;
		default:
			err = -EINVAL;
			goto out_err;
		}
		if (has_file(fbeo->entry_type)) {
			fput(file);
			file = NULL;
		}
	}

	fbe->is_used = num_entries > 0;

	return 0;
out_err:
	if (file)
		fput(file);
	if (has_backing)
		path_put_init(&fbe->backing_path);
	return err;
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

struct fuse_open_args {
	struct fuse_open_in in;
	struct fuse_open_out out;
};

static int fuse_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_open_args *args,
				   struct inode *inode, struct file *file, bool isdir)
{
	args->in = (struct fuse_open_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
	};
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_fuse_inode(inode)->nodeid,
			.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN,
		},
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(args->in),
			.value = &args->in,
		},
	};

	return 0;
}

static int fuse_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_open_args *args,
				    struct inode *inode, struct file *file, bool isdir)
{
	args->out = (struct fuse_open_out) { 0 };

	fa->out_numargs = 1;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(args->out),
		.value = &args->out,
	};

	return 0;
}

static int fuse_open_backing(struct bpf_fuse_args *fa, int *out,
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

	*out = inode_permission(&nop_mnt_idmap,
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

static int fuse_open_finalize(struct bpf_fuse_args *fa, int *out,
			      struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_open_out *foo = fa->out_args[0].value;

	if (ff) {
		ff->fh = foo->fh;
		ff->nodeid = get_fuse_inode(inode)->nodeid;
	}
	return 0;
}

int fuse_bpf_open(int *out, struct inode *inode, struct file *file, bool isdir)
{
	return bpf_fuse_backing(inode, struct fuse_open_args, out,
				fuse_open_initialize_in, fuse_open_initialize_out,
				fuse_open_backing, fuse_open_finalize,
				inode, file, isdir);
}

struct fuse_create_open_args {
	struct fuse_create_in in;
	struct fuse_buffer name;
	struct fuse_entry_out entry_out;
	struct fuse_open_out open_out;
};

static int fuse_create_open_initialize_in(struct bpf_fuse_args *fa, struct fuse_create_open_args *args,
					  struct inode *dir, struct dentry *entry,
					  struct file *file, unsigned int flags, umode_t mode)
{
	args->in = (struct fuse_create_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY),
		.mode = mode,
	};

	args->name = (struct fuse_buffer) {
		.data = (void *) entry->d_name.name,
		.size = entry->d_name.len + 1,
		.flags = BPF_FUSE_IMMUTABLE,
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(dir),
			.opcode = FUSE_CREATE,
		},
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(args->in),
			.value = &args->in,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.is_buffer = true,
			.buffer = &args->name,
		},
	};

	return 0;
}

static int fuse_create_open_initialize_out(struct bpf_fuse_args *fa, struct fuse_create_open_args *args,
					   struct inode *dir, struct dentry *entry,
					   struct file *file, unsigned int flags, umode_t mode)
{
	args->entry_out = (struct fuse_entry_out) { 0 };
	args->open_out = (struct fuse_open_out) { 0 };

	fa->out_numargs = 2;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(args->entry_out),
		.value = &args->entry_out,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.size = sizeof(args->open_out),
		.value = &args->open_out,
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

static int fuse_create_open_backing(struct bpf_fuse_args *fa, int *out,
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

	if (IS_ERR(backing_path.dentry))
		return PTR_ERR(backing_path.dentry);

	if (d_really_is_positive(backing_path.dentry)) {
		*out = -EIO;
		goto out;
	}

	backing_parent = dget_parent(backing_path.dentry);
	inode_lock_nested(dir_fuse_inode->backing_inode, I_MUTEX_PARENT);
	*out = vfs_create(&nop_mnt_idmap, d_inode(backing_parent),
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

static int fuse_create_open_finalize(struct bpf_fuse_args *fa, int *out,
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

int fuse_bpf_create_open(int *out, struct inode *dir, struct dentry *entry,
			 struct file *file, unsigned int flags, umode_t mode)
{
	return bpf_fuse_backing(dir, struct fuse_create_open_args, out,
				fuse_create_open_initialize_in,
				fuse_create_open_initialize_out,
				fuse_create_open_backing,
				fuse_create_open_finalize,
				dir, entry, file, flags, mode);
}

static int fuse_release_initialize_in(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
				      struct inode *inode, struct file *file)
{
	struct fuse_file *fuse_file = file->private_data;

	/* Always put backing file whatever bpf/userspace says */
	fput(fuse_file->backing_file);

	*fri = (struct fuse_release_in) {
		.fh = ((struct fuse_file *)(file->private_data))->fh,
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_fuse_inode(inode)->nodeid,
			.opcode = FUSE_RELEASE,
		},		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

static int fuse_release_initialize_out(struct bpf_fuse_args *fa, struct fuse_release_in *fri,
				       struct inode *inode, struct file *file)
{
	return 0;
}

static int fuse_releasedir_initialize_in(struct bpf_fuse_args *fa,
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
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_fuse_inode(inode)->nodeid,
			.opcode = FUSE_RELEASEDIR,
		},		.in_numargs = 1,
		.in_args[0].size = sizeof(*fri),
		.in_args[0].value = fri,
	};

	return 0;
}

static int fuse_releasedir_initialize_out(struct bpf_fuse_args *fa,
					  struct fuse_release_in *fri,
					  struct inode *inode, struct file *file)
{
	return 0;
}

static int fuse_release_backing(struct bpf_fuse_args *fa, int *out,
				struct inode *inode, struct file *file)
{
	return 0;
}

static int fuse_release_finalize(struct bpf_fuse_args *fa, int *out,
				 struct inode *inode, struct file *file)
{
	fuse_file_free(file->private_data);
	*out = 0;
	return 0;
}

int fuse_bpf_release(int *out, struct inode *inode, struct file *file)
{
	return bpf_fuse_backing(inode, struct fuse_release_in, out,
				fuse_release_initialize_in, fuse_release_initialize_out,
				fuse_release_backing, fuse_release_finalize,
				inode, file);
}

int fuse_bpf_releasedir(int *out, struct inode *inode, struct file *file)
{
	return bpf_fuse_backing(inode, struct fuse_release_in, out,
				fuse_releasedir_initialize_in, fuse_releasedir_initialize_out,
				fuse_release_backing, fuse_release_finalize, inode, file);
}

struct fuse_lseek_args {
	struct fuse_lseek_in in;
	struct fuse_lseek_out out;
};

static int fuse_lseek_initialize_in(struct bpf_fuse_args *fa, struct fuse_lseek_args *args,
				    struct file *file, loff_t offset, int whence)
{
	struct fuse_file *fuse_file = file->private_data;

	args->in = (struct fuse_lseek_in) {
		.fh = fuse_file->fh,
		.offset = offset,
		.whence = whence,
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(file->f_inode),
			.opcode = FUSE_LSEEK,
		},
		.in_numargs = 1,
		.in_args[0].size = sizeof(args->in),
		.in_args[0].value = &args->in,
	};

	return 0;
}

static int fuse_lseek_initialize_out(struct bpf_fuse_args *fa, struct fuse_lseek_args *args,
				     struct file *file, loff_t offset, int whence)
{
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(args->out);
	fa->out_args[0].value = &args->out;

	return 0;
}

static int fuse_lseek_backing(struct bpf_fuse_args *fa, loff_t *out,
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

static int fuse_lseek_finalize(struct bpf_fuse_args *fa, loff_t *out,
			       struct file *file, loff_t offset, int whence)
{
	struct fuse_lseek_out *flo = fa->out_args[0].value;

	if (!fa->info.error_in)
		file->f_pos = flo->offset;
	*out = flo->offset;
	return 0;
}

int fuse_bpf_lseek(loff_t *out, struct inode *inode, struct file *file, loff_t offset, int whence)
{
	return bpf_fuse_backing(inode, struct fuse_lseek_args, out,
				fuse_lseek_initialize_in, fuse_lseek_initialize_out,
				fuse_lseek_backing, fuse_lseek_finalize,
				file, offset, whence);
}

static inline void fuse_bpf_aio_put(struct fuse_bpf_aio_req *aio_req)
{
	if (refcount_dec_and_test(&aio_req->ref))
		kmem_cache_free(fuse_bpf_aio_request_cachep, aio_req);
}

static void fuse_bpf_aio_cleanup_handler(struct fuse_bpf_aio_req *aio_req, long res)
{
	struct kiocb *iocb = &aio_req->iocb;
	struct kiocb *iocb_orig = aio_req->iocb_orig;
	struct file *filp = iocb->ki_filp;
	struct file *fuse_filp = iocb_orig->ki_filp;

	if (iocb->ki_flags & IOCB_WRITE) {
		__sb_writers_acquired(file_inode(iocb->ki_filp)->i_sb,
				      SB_FREEZE_WRITE);
		fuse_file_end_write(iocb_orig->ki_filp, iocb->ki_filp, iocb->ki_pos, res);
	} else {
		fuse_file_end_read(fuse_filp, filp, &aio_req->pre_atime);
	}
	iocb_orig->ki_pos = iocb->ki_pos;
	fuse_bpf_aio_put(aio_req);
}

static void fuse_bpf_aio_rw_complete(struct kiocb *iocb, long res)
{
	struct fuse_bpf_aio_req *aio_req =
		container_of(iocb, struct fuse_bpf_aio_req, iocb);
	struct kiocb *iocb_orig = aio_req->iocb_orig;

	fuse_bpf_aio_cleanup_handler(aio_req, res);
	iocb_orig->ki_complete(iocb_orig, res);
}

struct fuse_file_read_iter_args {
	struct fuse_read_in in;
	struct fuse_read_iter_out out;
};

static int fuse_file_read_iter_initialize_in(struct bpf_fuse_args *fa, struct fuse_file_read_iter_args *args,
					     struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	args->in = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = iocb->ki_pos,
		.size = to->count,
	};

	/* TODO we can't assume 'to' is a kvec */
	/* TODO we also can't assume the vector has only one component */
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.opcode = FUSE_READ,
			.nodeid = ff->nodeid,
		},		.in_numargs = 1,
		.in_args[0].size = sizeof(args->in),
		.in_args[0].value = &args->in,
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

static int fuse_file_read_iter_initialize_out(struct bpf_fuse_args *fa, struct fuse_file_read_iter_args *args,
					      struct kiocb *iocb, struct iov_iter *to)
{
	args->out = (struct fuse_read_iter_out) {
		.ret = args->in.size,
	};

	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(args->out);
	fa->out_args[0].value = &args->out;

	return 0;
}

static int fuse_file_read_iter_backing(struct bpf_fuse_args *fa, ssize_t *out,
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
		struct timespec64 pre_atime;

		fuse_file_start_read(ff->backing_file, &pre_atime);
		*out = vfs_iter_read(ff->backing_file, to, &iocb->ki_pos,
				iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
		fuse_file_end_read(file, ff->backing_file, &pre_atime);
	} else {
		struct fuse_bpf_aio_req *aio_req;

		*out = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		aio_req->iocb_orig = iocb;
		fuse_file_start_read(ff->backing_file, &aio_req->pre_atime);
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		*out = vfs_iocb_iter_read(ff->backing_file, &aio_req->iocb, to);
		fuse_bpf_aio_put(aio_req);
		if (*out != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req, *out);
	}

	frio->ret = *out;

	/* TODO Need to point value at the buffer for post-modification */

out:
	fuse_file_accessed(file, ff->backing_file);

	return *out;
}

static int fuse_file_read_iter_finalize(struct bpf_fuse_args *fa, ssize_t *out,
					struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio = fa->out_args[0].value;

	*out = frio->ret;

	return 0;
}

int fuse_bpf_file_read_iter(ssize_t *out, struct inode *inode, struct kiocb *iocb, struct iov_iter *to)
{
	return bpf_fuse_backing(inode, struct fuse_file_read_iter_args, out,
				fuse_file_read_iter_initialize_in,
				fuse_file_read_iter_initialize_out,
				fuse_file_read_iter_backing,
				fuse_file_read_iter_finalize,
				iocb, to);
}

struct fuse_file_write_iter_args {
	struct fuse_write_in in;
	struct fuse_write_iter_out out;
};

static int fuse_file_write_iter_initialize_in(struct bpf_fuse_args *fa,
					      struct fuse_file_write_iter_args *args,
					      struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	*args = (struct fuse_file_write_iter_args) {
		.in.fh = ff->fh,
		.in.offset = iocb->ki_pos,
		.in.size = from->count,
	};

	/* TODO we can't assume 'from' is a kvec */
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.opcode = FUSE_WRITE,
			.nodeid = ff->nodeid,
		},
		.in_numargs = 1,
		.in_args[0].size = sizeof(args->in),
		.in_args[0].value = &args->in,
	};

	return 0;
}

static int fuse_file_write_iter_initialize_out(struct bpf_fuse_args *fa,
					       struct fuse_file_write_iter_args *args,
					       struct kiocb *iocb, struct iov_iter *from)
{
	/* TODO we can't assume 'from' is a kvec */
	fa->out_numargs = 1;
	fa->out_args[0].size = sizeof(args->out);
	fa->out_args[0].value = &args->out;

	return 0;
}

static int fuse_file_write_iter_backing(struct bpf_fuse_args *fa, ssize_t *out,
					struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;
	ssize_t count = iov_iter_count(from);

	if (!count)
		return 0;

	/* TODO This just plain ignores any change to fuse_write_in */
	/* TODO uint32_t seems smaller than ssize_t.... right? */
	inode_lock(file_inode(file));

	fuse_copyattr(file, ff->backing_file);

	if (is_sync_kiocb(iocb)) {
		fuse_file_start_write(file, ff->backing_file, iocb->ki_pos, count);
		*out = vfs_iter_write(ff->backing_file, from, &iocb->ki_pos,
					   iocb_to_rw_flags(iocb->ki_flags, FUSE_BPF_IOCB_MASK));
		fuse_file_end_write(file, ff->backing_file, iocb->ki_pos, *out);
	} else {
		struct fuse_bpf_aio_req *aio_req;

		*out = -ENOMEM;
		aio_req = kmem_cache_zalloc(fuse_bpf_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			goto out;

		fuse_file_start_write(file, ff->backing_file, iocb->ki_pos, count);
		__sb_writers_release(file_inode(ff->backing_file)->i_sb, SB_FREEZE_WRITE);
		aio_req->iocb_orig = iocb;
		kiocb_clone(&aio_req->iocb, iocb, ff->backing_file);
		aio_req->iocb.ki_complete = fuse_bpf_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		*out = vfs_iocb_iter_write(ff->backing_file, &aio_req->iocb, from);
		fuse_bpf_aio_put(aio_req);
		if (*out != -EIOCBQUEUED)
			fuse_bpf_aio_cleanup_handler(aio_req, *out);
	}

out:
	inode_unlock(file_inode(file));
	fwio->ret = *out;
	if (*out < 0)
		return *out;
	return 0;
}

static int fuse_file_write_iter_finalize(struct bpf_fuse_args *fa, ssize_t *out,
					 struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_write_iter_out *fwio = fa->out_args[0].value;

	*out = fwio->ret;
	return 0;
}

int fuse_bpf_file_write_iter(ssize_t *out, struct inode *inode, struct kiocb *iocb, struct iov_iter *from)
{
	return bpf_fuse_backing(inode, struct fuse_file_write_iter_args, out,
				fuse_file_write_iter_initialize_in,
				fuse_file_write_iter_initialize_out,
				fuse_file_write_iter_backing,
				fuse_file_write_iter_finalize,
				iocb, from);
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

static int fuse_file_fallocate_initialize_in(struct bpf_fuse_args *fa,
					     struct fuse_fallocate_in *in,
					     struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;

	*in = (struct fuse_fallocate_in) {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode,
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.opcode = FUSE_FALLOCATE,
			.nodeid = ff->nodeid,
		},
		.in_numargs = 1,
		.in_args[0].size = sizeof(*in),
		.in_args[0].value = in,
	};

	return 0;
}

static int fuse_file_fallocate_initialize_out(struct bpf_fuse_args *fa,
					      struct fuse_fallocate_in *in,
					      struct file *file, int mode, loff_t offset, loff_t length)
{
	return 0;
}

static int fuse_file_fallocate_backing(struct bpf_fuse_args *fa, int *out,
				       struct file *file, int mode, loff_t offset, loff_t length)
{
	const struct fuse_fallocate_in *ffi = fa->in_args[0].value;
	struct fuse_file *ff = file->private_data;

	*out = vfs_fallocate(ff->backing_file, ffi->mode, ffi->offset,
			     ffi->length);
	return 0;
}

static int fuse_file_fallocate_finalize(struct bpf_fuse_args *fa, int *out,
					struct file *file, int mode, loff_t offset, loff_t length)
{
	return 0;
}

int fuse_bpf_file_fallocate(int *out, struct inode *inode, struct file *file, int mode, loff_t offset, loff_t length)
{
	return bpf_fuse_backing(inode, struct fuse_fallocate_in, out,
				fuse_file_fallocate_initialize_in,
				fuse_file_fallocate_initialize_out,
				fuse_file_fallocate_backing,
				fuse_file_fallocate_finalize,
				file, mode, offset, length);
}

/*******************************************************************************
 * Directory operations after here                                             *
 ******************************************************************************/

struct fuse_lookup_args {
	struct fuse_buffer name;
	struct fuse_entry_out out;
	struct fuse_bpf_entry entries_storage;
	struct fuse_buffer bpf_entries;
};

static int fuse_lookup_initialize_in(struct bpf_fuse_args *fa, struct fuse_lookup_args *args,
				     struct inode *dir, struct dentry *entry, unsigned int flags)
{
	*args = (struct fuse_lookup_args) {
		.name = (struct fuse_buffer) {
			.data = (void *) entry->d_name.name,
			.size = entry->d_name.len + 1,
			.max_size = NAME_MAX + 1,
			.flags = BPF_FUSE_VARIABLE_SIZE | BPF_FUSE_MUST_ALLOCATE,
		},
	};
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_fuse_inode(dir)->nodeid,
			.opcode = FUSE_LOOKUP,
		},
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.is_buffer = true,
			.buffer = &args->name,
		},
	};

	return 0;
}

static int fuse_lookup_initialize_out(struct bpf_fuse_args *fa, struct fuse_lookup_args *args,
				      struct inode *dir, struct dentry *entry, unsigned int flags)
{
	args->bpf_entries = (struct fuse_buffer) {
		.data = args->entries_storage.out,
		.size = 0,
		.alloc_size = sizeof(args->entries_storage.out),
		.max_size = sizeof(args->entries_storage.out),
		.flags = BPF_FUSE_VARIABLE_SIZE,
	},

	fa->out_numargs = 2;
	fa->flags = FUSE_BPF_OUT_ARGVAR | FUSE_BPF_IS_LOOKUP;
	fa->out_args[0] = (struct bpf_fuse_arg) {
		.size = sizeof(args->out),
		.value = &args->out,
	};
	fa->out_args[1] = (struct bpf_fuse_arg) {
		.is_buffer = true,
		.buffer = &args->bpf_entries,
	};

	return 0;
}

static int fuse_lookup_backing(struct bpf_fuse_args *fa, struct dentry **out, struct inode *dir,
			       struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fuse_entry = get_fuse_dentry(entry);
	struct fuse_dentry *dir_fuse_entry = get_fuse_dentry(entry->d_parent);
	struct dentry *dir_backing_entry = dir_fuse_entry->backing_path.dentry;
	struct inode *dir_backing_inode = dir_backing_entry->d_inode;
	struct fuse_entry_out *feo = (void *)fa->out_args[0].value;
	struct dentry *backing_entry;
	const char *name;
	struct kstat stat;
	int len;
	int err;

	/* TODO this will not handle lookups over mount points */
	inode_lock_nested(dir_backing_inode, I_MUTEX_PARENT);
	if (fa->in_args[0].buffer->flags & BPF_FUSE_MODIFIED) {
		name = (char *)fa->in_args[0].buffer->data;
		len = strnlen(name, fa->in_args[0].buffer->size);
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
		.mnt = mntget(dir_fuse_entry->backing_path.mnt),
	};

	if (d_is_negative(backing_entry)) {
		fa->info.error_in = -ENOENT;
		return 0;
	}

	err = vfs_getattr(&fuse_entry->backing_path, &stat,
				  STATX_BASIC_STATS, 0);
	if (err) {
		path_put_init(&fuse_entry->backing_path);
		return err;
	}

	fuse_stat_to_attr(get_fuse_conn(dir),
			  backing_entry->d_inode, &stat, &feo->attr);
	return 0;
}

int fuse_handle_backing(struct fuse_bpf_entry *fbe, struct path *backing_path)
{
	switch (fbe->backing_action) {
	case FUSE_BPF_UNCHANGED:
		/* backing inode/path are added in fuse_lookup_backing */
		break;

	case FUSE_BPF_REMOVE:
		path_put_init(backing_path);
		break;

	case FUSE_BPF_SET: {
		if (!fbe->backing_path.dentry)
			return -EINVAL;

		path_put(backing_path);
		*backing_path = fbe->backing_path;
		fbe->backing_path.dentry = NULL;
		fbe->backing_path.mnt = NULL;

		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

static int fuse_lookup_finalize(struct bpf_fuse_args *fa, struct dentry **out,
				struct inode *dir, struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *fd;
	struct dentry *backing_dentry;
	struct inode *inode, *backing_inode;
	struct inode *d_inode = entry->d_inode;
	struct fuse_entry_out *feo = fa->out_args[0].value;
	struct fuse_bpf_entry_out *febo = fa->out_args[1].buffer->data;
	struct fuse_bpf_entry *fbe = container_of(febo, struct fuse_bpf_entry, out[0]);
	int error = -1;
	u64 target_nodeid = 0;

	parse_fuse_bpf_entry(fbe, -1);
	fd = get_fuse_dentry(entry);
	if (!fd)
		return -EIO;
	error = fuse_handle_backing(fbe, &fd->backing_path);
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

	get_fuse_inode(inode)->nodeid = feo->nodeid;

	*out = d_splice_alias(inode, entry);
	return 0;
}

int fuse_bpf_lookup(struct dentry **out, struct inode *dir, struct dentry *entry, unsigned int flags)
{
	return bpf_fuse_backing(dir, struct fuse_lookup_args, out,
				fuse_lookup_initialize_in, fuse_lookup_initialize_out,
				fuse_lookup_backing, fuse_lookup_finalize,
				dir, entry, flags);
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

struct fuse_mknod_args {
	struct fuse_mknod_in in;
	struct fuse_buffer name;
};

static int fuse_mknod_initialize_in(struct bpf_fuse_args *fa, struct fuse_mknod_args *args,
				    struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	*args = (struct fuse_mknod_args) {
		.in = (struct fuse_mknod_in) {
			.mode = mode,
			.rdev = new_encode_dev(rdev),
			.umask = current_umask(),
		},
		.name = (struct fuse_buffer) {
			.data = (void *) entry->d_name.name,
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
		},
	};
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(dir),
			.opcode = FUSE_MKNOD,
		},
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(args->in),
			.value = &args->in,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.is_buffer = true,
			.buffer = &args->name,
		},
	};

	return 0;
}

static int fuse_mknod_initialize_out(struct bpf_fuse_args *fa, struct fuse_mknod_args *args,
				     struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return 0;
}

static int fuse_mknod_backing(struct bpf_fuse_args *fa, int *out,
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
	*out = vfs_mknod(&nop_mnt_idmap, backing_inode, backing_path.dentry, mode,
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

static int fuse_mknod_finalize(struct bpf_fuse_args *fa, int *out,
			       struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return 0;
}

int fuse_bpf_mknod(int *out, struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return bpf_fuse_backing(dir, struct fuse_mknod_args, out,
				fuse_mknod_initialize_in, fuse_mknod_initialize_out,
				fuse_mknod_backing, fuse_mknod_finalize,
				dir, entry, mode, rdev);
}

struct fuse_mkdir_args {
	struct fuse_mkdir_in in;
	struct fuse_buffer name;
};

static int fuse_mkdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_mkdir_args *args,
				    struct inode *dir, struct dentry *entry, umode_t mode)
{
	*args = (struct fuse_mkdir_args) {
		.in = (struct fuse_mkdir_in) {
			.mode = mode,
			.umask = current_umask(),
		},
		.name = (struct fuse_buffer) {
			.data = (void *) entry->d_name.name,
			.size = entry->d_name.len + 1,
			.flags = BPF_FUSE_IMMUTABLE,
		},
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(dir),
			.opcode = FUSE_MKDIR,
		},
		.in_numargs = 2,
		.in_args[0] = (struct bpf_fuse_arg) {
			.size = sizeof(args->in),
			.value = &args->in,
		},
		.in_args[1] = (struct bpf_fuse_arg) {
			.value = &args->name,
			.is_buffer = true,
		},
	};

	return 0;
}

static int fuse_mkdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_mkdir_args *args,
				     struct inode *dir, struct dentry *entry, umode_t mode)
{
	return 0;
}

static int fuse_mkdir_backing(struct bpf_fuse_args *fa, int *out,
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
	*out = vfs_mkdir(&nop_mnt_idmap, backing_inode, backing_path.dentry,
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

static int fuse_mkdir_finalize(struct bpf_fuse_args *fa, int *out,
			       struct inode *dir, struct dentry *entry, umode_t mode)
{
	return 0;
}

int fuse_bpf_mkdir(int *out, struct inode *dir, struct dentry *entry, umode_t mode)
{
	return bpf_fuse_backing(dir, struct fuse_mkdir_args, out,
				fuse_mkdir_initialize_in, fuse_mkdir_initialize_out,
				fuse_mkdir_backing, fuse_mkdir_finalize,
				dir, entry, mode);
}

static int fuse_rmdir_initialize_in(struct bpf_fuse_args *fa, struct fuse_buffer *name,
				    struct inode *dir, struct dentry *entry)
{
	*name = (struct fuse_buffer) {
		.data = (void *) entry->d_name.name,
		.size = entry->d_name.len + 1,
		.flags = BPF_FUSE_IMMUTABLE,
	};
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(dir),
			.opcode = FUSE_RMDIR,
		},
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.is_buffer = true,
			.buffer = name,
		},
	};

	return 0;
}

static int fuse_rmdir_initialize_out(struct bpf_fuse_args *fa, struct fuse_buffer *name,
				     struct inode *dir, struct dentry *entry)
{
	return 0;
}

static int fuse_rmdir_backing(struct bpf_fuse_args *fa, int *out,
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
	*out = vfs_rmdir(&nop_mnt_idmap, backing_inode, backing_path.dentry);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!*out)
		d_drop(entry);
	path_put(&backing_path);
	return *out;
}

static int fuse_rmdir_finalize(struct bpf_fuse_args *fa, int *out, struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_bpf_rmdir(int *out, struct inode *dir, struct dentry *entry)
{
	return bpf_fuse_backing(dir, struct fuse_buffer, out,
				fuse_rmdir_initialize_in, fuse_rmdir_initialize_out,
				fuse_rmdir_backing, fuse_rmdir_finalize,
				dir, entry);
}

static int fuse_unlink_initialize_in(struct bpf_fuse_args *fa, struct fuse_buffer *name,
				     struct inode *dir, struct dentry *entry)
{
	*name = (struct fuse_buffer) {
		.data = (void *) entry->d_name.name,
		.size = entry->d_name.len + 1,
		.flags = BPF_FUSE_IMMUTABLE,
	};
	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.nodeid = get_node_id(dir),
			.opcode = FUSE_UNLINK,
		},
		.in_numargs = 1,
		.in_args[0] = (struct bpf_fuse_arg) {
			.is_buffer = true,
			.buffer = name,
		},
	};

	return 0;
}

static int fuse_unlink_initialize_out(struct bpf_fuse_args *fa, struct fuse_buffer *name,
				      struct inode *dir, struct dentry *entry)
{
	return 0;
}

static int fuse_unlink_backing(struct bpf_fuse_args *fa, int *out, struct inode *dir, struct dentry *entry)
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
	*out = vfs_unlink(&nop_mnt_idmap, backing_inode, backing_path.dentry,
			 NULL);
	inode_unlock(backing_inode);

	dput(backing_parent_dentry);
	if (!*out)
		d_drop(entry);
	path_put(&backing_path);
	return *out;
}

static int fuse_unlink_finalize(struct bpf_fuse_args *fa, int *out,
				struct inode *dir, struct dentry *entry)
{
	return 0;
}

int fuse_bpf_unlink(int *out, struct inode *dir, struct dentry *entry)
{
	return bpf_fuse_backing(dir, struct fuse_buffer, out,
				fuse_unlink_initialize_in, fuse_unlink_initialize_out,
				fuse_unlink_backing, fuse_unlink_finalize,
				dir, entry);
}

static int fuse_access_initialize_in(struct bpf_fuse_args *fa, struct fuse_access_in *in,
				     struct inode *inode, int mask)
{
	*in = (struct fuse_access_in) {
		.mask = mask,
	};

	*fa = (struct bpf_fuse_args) {
		.info = (struct bpf_fuse_meta_info) {
			.opcode = FUSE_ACCESS,
			.nodeid = get_node_id(inode),
		},
		.in_numargs = 1,
		.in_args[0].size = sizeof(*in),
		.in_args[0].value = in,
	};

	return 0;
}

static int fuse_access_initialize_out(struct bpf_fuse_args *fa, struct fuse_access_in *in,
				      struct inode *inode, int mask)
{
	return 0;
}

static int fuse_access_backing(struct bpf_fuse_args *fa, int *out, struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	const struct fuse_access_in *fai = fa->in_args[0].value;

	*out = inode_permission(&nop_mnt_idmap, fi->backing_inode, fai->mask);
	return 0;
}

static int fuse_access_finalize(struct bpf_fuse_args *fa, int *out, struct inode *inode, int mask)
{
	return 0;
}

int fuse_bpf_access(int *out, struct inode *inode, int mask)
{
	return bpf_fuse_backing(inode, struct fuse_access_in, out,
				fuse_access_initialize_in, fuse_access_initialize_out,
				fuse_access_backing, fuse_access_finalize, inode, mask);
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
