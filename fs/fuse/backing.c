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
