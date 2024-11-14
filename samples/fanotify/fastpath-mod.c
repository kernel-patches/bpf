// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fsnotify.h>
#include <linux/fanotify.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/file.h>

static int sample_fp_handler(struct fsnotify_group *group,
			     struct fanotify_fastpath_hook *fp_hook,
			     struct fanotify_fastpath_event *fp_event)
{
	struct dentry *dentry;
	struct path *subtree;

	dentry = fsnotify_data_dentry(fp_event->data, fp_event->data_type);
	if (!dentry)
		return FAN_FP_RET_SEND_TO_USERSPACE;

	subtree = fp_hook->data;

	if (is_subdir(dentry, subtree->dentry))
		return FAN_FP_RET_SEND_TO_USERSPACE;
	return FAN_FP_RET_SKIP_EVENT;
}

static int sample_fp_init(struct fanotify_fastpath_hook *fp_hook, void *args)
{
	struct path *subtree;
	struct file *file;
	int fd;

	fd = *(int *)args;

	file = fget(fd);
	if (!file)
		return -EBADF;
	subtree = kzalloc(sizeof(struct path), GFP_KERNEL);
	if (!subtree) {
		fput(file);
		return -ENOMEM;
	}
	path_get(&file->f_path);
	*subtree = file->f_path;
	fput(file);
	fp_hook->data = subtree;
	return 0;
}

static void sample_fp_free(struct fanotify_fastpath_hook *fp_hook)
{
	struct path *subtree = fp_hook->data;

	path_put(subtree);
	kfree(subtree);
}

static struct fanotify_fastpath_ops fan_fp_ignore_a_ops = {
	.fp_handler = sample_fp_handler,
	.fp_init = sample_fp_init,
	.fp_free = sample_fp_free,
	.name = "monitor-subtree",
	.owner = THIS_MODULE,
	.flags = FAN_FP_F_SYS_ADMIN_ONLY,
	.desc = "only emit events under a subtree",
	.init_args = "struct {\n\tint subtree_fd;\n};",
};

static int __init fanotify_fastpath_sample_init(void)
{
	return fanotify_fastpath_register(&fan_fp_ignore_a_ops);
}
static void __exit fanotify_fastpath_sample_exit(void)
{
	fanotify_fastpath_unregister(&fan_fp_ignore_a_ops);
}

module_init(fanotify_fastpath_sample_init);
module_exit(fanotify_fastpath_sample_exit);

MODULE_AUTHOR("Song Liu");
MODULE_DESCRIPTION("Example fanotify fastpath handler");
MODULE_LICENSE("GPL");
