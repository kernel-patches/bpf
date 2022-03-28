// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal file system backend for holding eBPF maps and programs,
 * used by bpf(2) object pinning.
 *
 * Authors:
 *
 *	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <linux/init.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/kdev_t.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/bpf_preload.h>

static char *bpf_preload_list_str = CONFIG_BPF_PRELOAD_LIST;

static int __init bpf_preload_list_setup(char *str)
{
	bpf_preload_list_str = str;
	return 1;
}
__setup("bpf_preload_list=", bpf_preload_list_setup);

static void *bpf_any_get(void *raw, enum bpf_type type)
{
	switch (type) {
	case BPF_TYPE_PROG:
		bpf_prog_inc(raw);
		break;
	case BPF_TYPE_MAP:
		bpf_map_inc_with_uref(raw);
		break;
	case BPF_TYPE_LINK:
		bpf_link_inc(raw);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	return raw;
}

static void bpf_any_put(void *raw, enum bpf_type type)
{
	switch (type) {
	case BPF_TYPE_PROG:
		bpf_prog_put(raw);
		break;
	case BPF_TYPE_MAP:
		bpf_map_put_with_uref(raw);
		break;
	case BPF_TYPE_LINK:
		bpf_link_put(raw);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

static void *bpf_fd_probe_obj(u32 ufd, enum bpf_type *type)
{
	void *raw;

	raw = bpf_map_get_with_uref(ufd);
	if (!IS_ERR(raw)) {
		*type = BPF_TYPE_MAP;
		return raw;
	}

	raw = bpf_prog_get(ufd);
	if (!IS_ERR(raw)) {
		*type = BPF_TYPE_PROG;
		return raw;
	}

	raw = bpf_link_get_from_fd(ufd);
	if (!IS_ERR(raw)) {
		*type = BPF_TYPE_LINK;
		return raw;
	}

	return ERR_PTR(-EINVAL);
}

static const struct inode_operations bpf_dir_iops;

static const struct inode_operations bpf_prog_iops = { };
static const struct inode_operations bpf_map_iops  = { };
static const struct inode_operations bpf_link_iops  = { };

static struct inode *bpf_get_inode(struct super_block *sb,
				   const struct inode *dir,
				   umode_t mode)
{
	struct inode *inode;

	switch (mode & S_IFMT) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOSPC);

	inode->i_ino = get_next_ino();
	inode->i_atime = current_time(inode);
	inode->i_mtime = inode->i_atime;
	inode->i_ctime = inode->i_atime;

	inode_init_owner(&init_user_ns, inode, dir, mode);

	return inode;
}

static int bpf_inode_type(const struct inode *inode, enum bpf_type *type)
{
	*type = BPF_TYPE_UNSPEC;
	if (inode->i_op == &bpf_prog_iops)
		*type = BPF_TYPE_PROG;
	else if (inode->i_op == &bpf_map_iops)
		*type = BPF_TYPE_MAP;
	else if (inode->i_op == &bpf_link_iops)
		*type = BPF_TYPE_LINK;
	else
		return -EACCES;

	return 0;
}

static void bpf_dentry_finalize(struct dentry *dentry, struct inode *inode,
				struct inode *dir)
{
	d_instantiate(dentry, inode);
	dget(dentry);

	dir->i_mtime = current_time(dir);
	dir->i_ctime = dir->i_mtime;
}

static int bpf_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	inode = bpf_get_inode(dir->i_sb, dir, mode | S_IFDIR);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &bpf_dir_iops;
	inode->i_fop = &simple_dir_operations;

	inc_nlink(inode);
	inc_nlink(dir);

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

struct map_iter {
	void *key;
	bool done;
};

static struct map_iter *map_iter(struct seq_file *m)
{
	return m->private;
}

static struct bpf_map *seq_file_to_map(struct seq_file *m)
{
	return file_inode(m->file)->i_private;
}

static void map_iter_free(struct map_iter *iter)
{
	if (iter) {
		kfree(iter->key);
		kfree(iter);
	}
}

static struct map_iter *map_iter_alloc(struct bpf_map *map)
{
	struct map_iter *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL | __GFP_NOWARN);
	if (!iter)
		goto error;

	iter->key = kzalloc(map->key_size, GFP_KERNEL | __GFP_NOWARN);
	if (!iter->key)
		goto error;

	return iter;

error:
	map_iter_free(iter);
	return NULL;
}

static void *map_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct bpf_map *map = seq_file_to_map(m);
	void *key = map_iter(m)->key;
	void *prev_key;

	(*pos)++;
	if (map_iter(m)->done)
		return NULL;

	if (unlikely(v == SEQ_START_TOKEN))
		prev_key = NULL;
	else
		prev_key = key;

	rcu_read_lock();
	if (map->ops->map_get_next_key(map, prev_key, key)) {
		map_iter(m)->done = true;
		key = NULL;
	}
	rcu_read_unlock();
	return key;
}

static void *map_seq_start(struct seq_file *m, loff_t *pos)
{
	if (map_iter(m)->done)
		return NULL;

	return *pos ? map_iter(m)->key : SEQ_START_TOKEN;
}

static void map_seq_stop(struct seq_file *m, void *v)
{
}

static int map_seq_show(struct seq_file *m, void *v)
{
	struct bpf_map *map = seq_file_to_map(m);
	void *key = map_iter(m)->key;

	if (unlikely(v == SEQ_START_TOKEN)) {
		seq_puts(m, "# WARNING!! The output is for debug purpose only\n");
		seq_puts(m, "# WARNING!! The output format will change\n");
	} else {
		map->ops->map_seq_show_elem(map, key, m);
	}

	return 0;
}

static const struct seq_operations bpffs_map_seq_ops = {
	.start	= map_seq_start,
	.next	= map_seq_next,
	.show	= map_seq_show,
	.stop	= map_seq_stop,
};

static int bpffs_map_open(struct inode *inode, struct file *file)
{
	struct bpf_map *map = inode->i_private;
	struct map_iter *iter;
	struct seq_file *m;
	int err;

	iter = map_iter_alloc(map);
	if (!iter)
		return -ENOMEM;

	err = seq_open(file, &bpffs_map_seq_ops);
	if (err) {
		map_iter_free(iter);
		return err;
	}

	m = file->private_data;
	m->private = iter;

	return 0;
}

static int bpffs_map_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	map_iter_free(map_iter(m));

	return seq_release(inode, file);
}

/* bpffs_map_fops should only implement the basic
 * read operation for a BPF map.  The purpose is to
 * provide a simple user intuitive way to do
 * "cat bpffs/pathto/a-pinned-map".
 *
 * Other operations (e.g. write, lookup...) should be realized by
 * the userspace tools (e.g. bpftool) through the
 * BPF_OBJ_GET_INFO_BY_FD and the map's lookup/update
 * interface.
 */
static const struct file_operations bpffs_map_fops = {
	.open		= bpffs_map_open,
	.read		= seq_read,
	.release	= bpffs_map_release,
};

static int bpffs_obj_open(struct inode *inode, struct file *file)
{
	return -EIO;
}

static const struct file_operations bpffs_obj_fops = {
	.open		= bpffs_obj_open,
};

static int bpf_mkobj_ops(struct dentry *dentry, umode_t mode, void *raw,
			 const struct inode_operations *iops,
			 const struct file_operations *fops)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct inode *inode = bpf_get_inode(dir->i_sb, dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = iops;
	inode->i_fop = fops;
	inode->i_private = raw;

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

static int bpf_mkprog(struct dentry *dentry, umode_t mode, void *arg)
{
	return bpf_mkobj_ops(dentry, mode, arg, &bpf_prog_iops,
			     &bpffs_obj_fops);
}

static int bpf_mkmap(struct dentry *dentry, umode_t mode, void *arg)
{
	struct bpf_map *map = arg;

	return bpf_mkobj_ops(dentry, mode, arg, &bpf_map_iops,
			     bpf_map_support_seq_show(map) ?
			     &bpffs_map_fops : &bpffs_obj_fops);
}

static int bpf_mklink(struct dentry *dentry, umode_t mode, void *arg)
{
	struct bpf_link *link = arg;

	return bpf_mkobj_ops(dentry, mode, arg, &bpf_link_iops,
			     bpf_link_is_iter(link) ?
			     &bpf_iter_fops : &bpffs_obj_fops);
}

static struct dentry *
bpf_lookup(struct inode *dir, struct dentry *dentry, unsigned flags)
{
	/* Dots in names (e.g. "/sys/fs/bpf/foo.bar") are reserved for future
	 * extensions. That allows popoulate_bpffs() create special files.
	 */
	if ((dir->i_mode & S_IALLUGO) &&
	    strchr(dentry->d_name.name, '.'))
		return ERR_PTR(-EPERM);

	return simple_lookup(dir, dentry, flags);
}

static int bpf_symlink(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, const char *target)
{
	char *link = kstrdup(target, GFP_USER | __GFP_NOWARN);
	struct inode *inode;

	if (!link)
		return -ENOMEM;

	inode = bpf_get_inode(dir->i_sb, dir, S_IRWXUGO | S_IFLNK);
	if (IS_ERR(inode)) {
		kfree(link);
		return PTR_ERR(inode);
	}

	inode->i_op = &simple_symlink_inode_operations;
	inode->i_link = link;

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

static const struct inode_operations bpf_dir_iops = {
	.lookup		= bpf_lookup,
	.mkdir		= bpf_mkdir,
	.symlink	= bpf_symlink,
	.rmdir		= simple_rmdir,
	.rename		= simple_rename,
	.link		= simple_link,
	.unlink		= simple_unlink,
};

/* pin object into bpffs */
int bpf_obj_do_pin_kernel(struct dentry *parent, const char *name, void *raw,
			  enum bpf_type type)
{
	umode_t mode = S_IFREG | S_IRUSR;
	struct dentry *dentry;
	int ret;

	inode_lock(parent->d_inode);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry)) {
		inode_unlock(parent->d_inode);
		return PTR_ERR(dentry);
	}

	switch (type) {
	case BPF_TYPE_PROG:
		ret = bpf_mkprog(dentry, mode, raw);
		break;
	case BPF_TYPE_MAP:
		ret = bpf_mkmap(dentry, mode, raw);
		break;
	case BPF_TYPE_LINK:
		ret = bpf_mklink(dentry, mode, raw);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	dput(dentry);
	inode_unlock(parent->d_inode);
	return ret;
}
EXPORT_SYMBOL(bpf_obj_do_pin_kernel);

static int bpf_obj_do_pin(const char __user *pathname, void *raw,
			  enum bpf_type type)
{
	struct dentry *dentry;
	struct inode *dir;
	struct path path;
	umode_t mode;
	int ret;

	dentry = user_path_create(AT_FDCWD, pathname, &path, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	mode = S_IFREG | ((S_IRUSR | S_IWUSR) & ~current_umask());

	ret = security_path_mknod(&path, dentry, mode, 0);
	if (ret)
		goto out;

	dir = d_inode(path.dentry);
	if (dir->i_op != &bpf_dir_iops) {
		ret = -EPERM;
		goto out;
	}

	switch (type) {
	case BPF_TYPE_PROG:
		ret = vfs_mkobj(dentry, mode, bpf_mkprog, raw);
		break;
	case BPF_TYPE_MAP:
		ret = vfs_mkobj(dentry, mode, bpf_mkmap, raw);
		break;
	case BPF_TYPE_LINK:
		ret = vfs_mkobj(dentry, mode, bpf_mklink, raw);
		break;
	default:
		ret = -EPERM;
	}
out:
	done_path_create(&path, dentry);
	return ret;
}

int bpf_obj_pin_user(u32 ufd, const char __user *pathname)
{
	enum bpf_type type;
	void *raw;
	int ret;

	raw = bpf_fd_probe_obj(ufd, &type);
	if (IS_ERR(raw))
		return PTR_ERR(raw);

	ret = bpf_obj_do_pin(pathname, raw, type);
	if (ret != 0)
		bpf_any_put(raw, type);

	return ret;
}

static void *bpf_obj_do_get(const char __user *pathname,
			    enum bpf_type *type, int flags)
{
	struct inode *inode;
	struct path path;
	void *raw;
	int ret;

	ret = user_path_at(AT_FDCWD, pathname, LOOKUP_FOLLOW, &path);
	if (ret)
		return ERR_PTR(ret);

	inode = d_backing_inode(path.dentry);
	ret = path_permission(&path, ACC_MODE(flags));
	if (ret)
		goto out;

	ret = bpf_inode_type(inode, type);
	if (ret)
		goto out;

	raw = bpf_any_get(inode->i_private, *type);
	if (!IS_ERR(raw))
		touch_atime(&path);

	path_put(&path);
	return raw;
out:
	path_put(&path);
	return ERR_PTR(ret);
}

int bpf_obj_get_user(const char __user *pathname, int flags)
{
	enum bpf_type type = BPF_TYPE_UNSPEC;
	int f_flags;
	void *raw;
	int ret;

	f_flags = bpf_get_file_flag(flags);
	if (f_flags < 0)
		return f_flags;

	raw = bpf_obj_do_get(pathname, &type, f_flags);
	if (IS_ERR(raw))
		return PTR_ERR(raw);

	if (type == BPF_TYPE_PROG)
		ret = bpf_prog_new_fd(raw);
	else if (type == BPF_TYPE_MAP)
		ret = bpf_map_new_fd(raw, f_flags);
	else if (type == BPF_TYPE_LINK)
		ret = (f_flags != O_RDWR) ? -EINVAL : bpf_link_new_fd(raw);
	else
		return -ENOENT;

	if (ret < 0)
		bpf_any_put(raw, type);
	return ret;
}

static struct bpf_prog *__get_prog_inode(struct inode *inode, enum bpf_prog_type type)
{
	struct bpf_prog *prog;
	int ret = inode_permission(&init_user_ns, inode, MAY_READ);
	if (ret)
		return ERR_PTR(ret);

	if (inode->i_op == &bpf_map_iops)
		return ERR_PTR(-EINVAL);
	if (inode->i_op == &bpf_link_iops)
		return ERR_PTR(-EINVAL);
	if (inode->i_op != &bpf_prog_iops)
		return ERR_PTR(-EACCES);

	prog = inode->i_private;

	ret = security_bpf_prog(prog);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!bpf_prog_get_ok(prog, &type, false))
		return ERR_PTR(-EINVAL);

	bpf_prog_inc(prog);
	return prog;
}

struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type)
{
	struct bpf_prog *prog;
	struct path path;
	int ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ERR_PTR(ret);
	prog = __get_prog_inode(d_backing_inode(path.dentry), type);
	if (!IS_ERR(prog))
		touch_atime(&path);
	path_put(&path);
	return prog;
}
EXPORT_SYMBOL(bpf_prog_get_type_path);

/*
 * Display the mount options in /proc/mounts.
 */
static int bpf_show_options(struct seq_file *m, struct dentry *root)
{
	umode_t mode = d_inode(root)->i_mode & S_IALLUGO & ~S_ISVTX;

	if (mode != S_IRWXUGO)
		seq_printf(m, ",mode=%o", mode);
	return 0;
}

static void bpf_free_inode(struct inode *inode)
{
	enum bpf_type type;

	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	if (!bpf_inode_type(inode, &type))
		bpf_any_put(inode->i_private, type);
	free_inode_nonrcu(inode);
}

static const struct super_operations bpf_super_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= bpf_show_options,
	.free_inode	= bpf_free_inode,
};

enum {
	OPT_MODE,
};

static const struct fs_parameter_spec bpf_fs_parameters[] = {
	fsparam_u32oct	("mode",			OPT_MODE),
	{}
};

struct bpf_mount_opts {
	umode_t mode;
};

static int bpf_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct bpf_mount_opts *opts = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, bpf_fs_parameters, param, &result);
	if (opt < 0) {
		/* We might like to report bad mount options here, but
		 * traditionally we've ignored all mount options, so we'd
		 * better continue to ignore non-existing options for bpf.
		 */
		if (opt == -ENOPARAM) {
			opt = vfs_parse_fs_param_source(fc, param);
			if (opt != -ENOPARAM)
				return opt;

			return 0;
		}

		if (opt < 0)
			return opt;
	}

	switch (opt) {
	case OPT_MODE:
		opts->mode = result.uint_32 & S_IALLUGO;
		break;
	}

	return 0;
}

struct bpf_preload_ops *bpf_preload_ops;
EXPORT_SYMBOL_GPL(bpf_preload_ops);

struct bpf_preload_ops_item {
	struct list_head list;
	struct bpf_preload_ops *ops;
	char *obj_name;
};

static LIST_HEAD(preload_list);
static DEFINE_MUTEX(bpf_preload_lock);

static bool bpf_preload_mod_get(const char *obj_name,
				struct bpf_preload_ops **ops)
{
	/* If the kernel preload module wasn't loaded earlier then load it now.
	 * When the preload code is built into vmlinux the module's __init
	 * function will populate it.
	 */
	if (!*ops) {
		mutex_unlock(&bpf_preload_lock);
		request_module(obj_name);
		mutex_lock(&bpf_preload_lock);
		if (!*ops)
			return false;
	}
	/* And grab the reference, so the module doesn't disappear while the
	 * kernel is interacting with the kernel module and its UMD.
	 */
	if (!try_module_get((*ops)->owner)) {
		pr_err("bpf_preload module get failed.\n");
		return false;
	}
	return true;
}

static void bpf_preload_mod_put(struct bpf_preload_ops *ops)
{
	if (ops)
		/* now user can "rmmod <kernel module>" if necessary */
		module_put(ops->owner);
}

static bool bpf_preload_list_mod_get(void)
{
	struct bpf_preload_ops_item *cur;
	bool ret = false;

	/*
	 * Keep the legacy registration method, but do not attempt to load
	 * bpf_preload.ko, as it switched to the new registration method.
	 */
	if (bpf_preload_ops)
		ret |= bpf_preload_mod_get("bpf_preload", &bpf_preload_ops);

	list_for_each_entry(cur, &preload_list, list)
		ret |= bpf_preload_mod_get(cur->obj_name, &cur->ops);

	return ret;
}

static struct dentry *create_subdir(struct dentry *parent, const char *name)
{
	struct dentry *dentry;
	int err;

	inode_lock(parent->d_inode);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	err = vfs_mkdir(&init_user_ns, parent->d_inode, dentry, 0755);
	if (err) {
		dput(dentry);
		dentry = ERR_PTR(err);
	}
out:
	inode_unlock(parent->d_inode);
	return dentry;
}

static int bpf_preload_list(struct dentry *parent)
{
	struct bpf_preload_ops_item *cur;
	struct dentry *cur_parent;
	int err;

	if (bpf_preload_ops) {
		err = bpf_preload_ops->preload(parent);
		if (err)
			return err;
	}

	list_for_each_entry(cur, &preload_list, list) {
		if (!cur->ops)
			continue;

		cur_parent = parent;

		if (strcmp(cur->obj_name, "bpf_preload")) {
			cur_parent = create_subdir(parent, cur->obj_name);
			if (IS_ERR(cur_parent))
				cur_parent = parent;
		}

		err = cur->ops->preload(cur_parent);

		if (cur_parent != parent)
			dput(cur_parent);

		if (err)
			return err;
	}

	return 0;
}

static void bpf_preload_list_mod_put(void)
{
	struct bpf_preload_ops_item *cur;

	list_for_each_entry(cur, &preload_list, list)
		bpf_preload_mod_put(cur->ops);

	bpf_preload_mod_put(bpf_preload_ops);
}

static int populate_bpffs(struct dentry *parent)
{
	int err = 0;

	/* grab the mutex to make sure the kernel interactions with bpf_preload
	 * are serialized
	 */
	mutex_lock(&bpf_preload_lock);

	/* if kernel preload mods weren't built into vmlinux then load them */
	if (!bpf_preload_list_mod_get())
		goto out;

	err = bpf_preload_list(parent);
	bpf_preload_list_mod_put();

out:
	mutex_unlock(&bpf_preload_lock);
	return err;
}

static int bpf_fill_super(struct super_block *sb, struct fs_context *fc)
{
	static const struct tree_descr bpf_rfiles[] = { { "" } };
	struct bpf_mount_opts *opts = fc->fs_private;
	struct inode *inode;
	int ret;

	ret = simple_fill_super(sb, BPF_FS_MAGIC, bpf_rfiles);
	if (ret)
		return ret;

	sb->s_op = &bpf_super_ops;

	inode = sb->s_root->d_inode;
	inode->i_op = &bpf_dir_iops;
	inode->i_mode &= ~S_IALLUGO;
	populate_bpffs(sb->s_root);
	inode->i_mode |= S_ISVTX | opts->mode;
	return 0;
}

static int bpf_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, bpf_fill_super);
}

static void bpf_free_fc(struct fs_context *fc)
{
	kfree(fc->fs_private);
}

static const struct fs_context_operations bpf_context_ops = {
	.free		= bpf_free_fc,
	.parse_param	= bpf_parse_param,
	.get_tree	= bpf_get_tree,
};

/*
 * Set up the filesystem mount context.
 */
static int bpf_init_fs_context(struct fs_context *fc)
{
	struct bpf_mount_opts *opts;

	opts = kzalloc(sizeof(struct bpf_mount_opts), GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	opts->mode = S_IRWXUGO;

	fc->fs_private = opts;
	fc->ops = &bpf_context_ops;
	return 0;
}

static struct file_system_type bpf_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bpf",
	.init_fs_context = bpf_init_fs_context,
	.parameters	= bpf_fs_parameters,
	.kill_sb	= kill_litter_super,
};

static struct bpf_preload_ops_item *
bpf_preload_list_lookup_entry(const char *obj_name)
{
	struct bpf_preload_ops_item *cur;

	list_for_each_entry(cur, &preload_list, list)
		if (!strcmp(obj_name, cur->obj_name))
			return cur;

	return NULL;
}

static int bpf_preload_list_add_entry(const char *obj_name,
				      struct bpf_preload_ops *ops)
{
	struct bpf_preload_ops_item *new;

	if (!*obj_name)
		return 0;

	new = kzalloc(sizeof(*new), GFP_NOFS);
	if (!new)
		return -ENOMEM;

	new->obj_name = kstrdup(obj_name, GFP_NOFS);
	if (!new->obj_name) {
		kfree(new);
		return -ENOMEM;
	}

	new->ops = ops;

	list_add(&new->list, &preload_list);
	return 0;
}

bool bpf_preload_set_ops(const char *obj_name, struct module *owner,
			 struct bpf_preload_ops *ops)
{
	struct bpf_preload_ops_item *found_item;
	bool set = false;

	mutex_lock(&bpf_preload_lock);

	found_item = bpf_preload_list_lookup_entry(obj_name);
	if (found_item) {
		if (!found_item->ops ||
		    (found_item->ops && found_item->ops->owner == owner)) {
			found_item->ops = ops;
			set = true;
		}
	}

	mutex_unlock(&bpf_preload_lock);
	return set;
}
EXPORT_SYMBOL_GPL(bpf_preload_set_ops);

static int __init bpf_init_preload_list(void)
{
	char *str_ptr = bpf_preload_list_str, *str_end;
	struct bpf_preload_ops_item *cur, *tmp;
	char obj_name[NAME_MAX + 1];
	int ret;

	while (str_ptr && *str_ptr) {
		str_end = strchrnul(str_ptr, ',');

		snprintf(obj_name, sizeof(obj_name), "%.*s",
			 (int)(str_end - str_ptr), str_ptr);

		if (!bpf_preload_list_lookup_entry(obj_name)) {
			ret = bpf_preload_list_add_entry(obj_name, NULL);
			if (ret)
				goto out;
		}

		if (!*str_end)
			break;

		str_ptr = str_end + 1;
	}

	return 0;
out:
	list_for_each_entry_safe(cur, tmp, &preload_list, list) {
		list_del(&cur->list);
		kfree(cur->obj_name);
		kfree(cur);
	}

	return ret;
}

static int __init bpf_init(void)
{
	int ret;

	ret = sysfs_create_mount_point(fs_kobj, "bpf");
	if (ret)
		return ret;

	ret = register_filesystem(&bpf_fs_type);
	if (ret) {
		sysfs_remove_mount_point(fs_kobj, "bpf");
		return ret;
	}

	ret = bpf_init_preload_list();
	if (ret) {
		unregister_filesystem(&bpf_fs_type);
		sysfs_remove_mount_point(fs_kobj, "bpf");
		return ret;
	}

	return ret;
}
fs_initcall(bpf_init);
