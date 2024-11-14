// SPDX-License-Identifier: GPL-2.0
#include <linux/fanotify.h>
#include <linux/kobject.h>
#include <linux/module.h>

#include "fanotify.h"

extern struct srcu_struct fsnotify_mark_srcu;

static DEFINE_SPINLOCK(fp_list_lock);
static LIST_HEAD(fp_list);

static struct kobject *fan_fp_root_kobj;

static struct {
	enum fanotify_fastpath_flags flag;
	const char *name;
} fanotify_fastpath_flags_names[] = {
	{
		.flag = FAN_FP_F_SYS_ADMIN_ONLY,
		.name = "SYS_ADMIN_ONLY",
	}
};

static ssize_t flags_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	struct fanotify_fastpath_ops *ops;
	ssize_t len = 0;
	int i;

	ops = container_of(kobj, struct fanotify_fastpath_ops, kobj);
	for (i = 0; i < ARRAY_SIZE(fanotify_fastpath_flags_names); i++) {
		if (ops->flags & fanotify_fastpath_flags_names[i].flag) {
			len += sysfs_emit_at(buf, len, "%s%s", len ? " " : "",
					     fanotify_fastpath_flags_names[i].name);
		}
	}
	len += sysfs_emit_at(buf, len, "\n");
	return len;
}

static ssize_t desc_show(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf)
{
	struct fanotify_fastpath_ops *ops;

	ops = container_of(kobj, struct fanotify_fastpath_ops, kobj);

	return sysfs_emit(buf, "%s\n", ops->desc ?: "N/A");
}

static ssize_t init_args_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct fanotify_fastpath_ops *ops;

	ops = container_of(kobj, struct fanotify_fastpath_ops, kobj);

	return sysfs_emit(buf, "%s\n", ops->init_args ?: "N/A");
}

static struct kobj_attribute flags_kobj_attr = __ATTR_RO(flags);
static struct kobj_attribute desc_kobj_attr = __ATTR_RO(desc);
static struct kobj_attribute init_args_kobj_attr = __ATTR_RO(init_args);

static struct attribute *fan_fp_attrs[] = {
	&flags_kobj_attr.attr,
	&desc_kobj_attr.attr,
	&init_args_kobj_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(fan_fp);

static void fan_fp_kobj_release(struct kobject *kobj)
{

}

static const struct kobj_type fan_fp_ktype = {
	.release = fan_fp_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = fan_fp_groups,
};

static struct fanotify_fastpath_ops *fanotify_fastpath_find(const char *name)
{
	struct fanotify_fastpath_ops *ops;

	list_for_each_entry(ops, &fp_list, list) {
		if (!strcmp(ops->name, name))
			return ops;
	}
	return NULL;
}

static void __fanotify_fastpath_unregister(struct fanotify_fastpath_ops *ops)
{
	spin_lock(&fp_list_lock);
	list_del_init(&ops->list);
	spin_unlock(&fp_list_lock);
}

/*
 * fanotify_fastpath_register - Register a new fastpath handler.
 *
 * Add a fastpath handler to the fp_list. These fastpath handlers are
 * available for all users in the system.
 *
 * @ops:	pointer to fanotify_fastpath_ops to add.
 *
 * Returns:
 *	0	- on success;
 *	-EEXIST	- fastpath handler of the same name already exists.
 */
int fanotify_fastpath_register(struct fanotify_fastpath_ops *ops)
{
	int ret;

	spin_lock(&fp_list_lock);
	if (fanotify_fastpath_find(ops->name)) {
		/* cannot register two handlers with the same name */
		spin_unlock(&fp_list_lock);
		return -EEXIST;
	}
	list_add_tail(&ops->list, &fp_list);
	spin_unlock(&fp_list_lock);


	kobject_init(&ops->kobj, &fan_fp_ktype);
	ret = kobject_add(&ops->kobj, fan_fp_root_kobj, "%s", ops->name);
	if (ret) {
		__fanotify_fastpath_unregister(ops);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(fanotify_fastpath_register);

/*
 * fanotify_fastpath_unregister - Unregister a new fastpath handler.
 *
 * Remove a fastpath handler from fp_list.
 *
 * @ops:	pointer to fanotify_fastpath_ops to remove.
 */
void fanotify_fastpath_unregister(struct fanotify_fastpath_ops *ops)
{
	kobject_put(&ops->kobj);
	__fanotify_fastpath_unregister(ops);
}
EXPORT_SYMBOL_GPL(fanotify_fastpath_unregister);

/*
 * fanotify_fastpath_add - Add a fastpath handler to fsnotify_group.
 *
 * Add a fastpath handler from fp_list to a fsnotify_group.
 *
 * @group:	fsnotify_group that will have add
 * @argp:	fanotify_fastpath_args that specifies the fastpath handler
 *		and the init arguments of the fastpath handler.
 *
 * Returns:
 *	0	- on success;
 *	-EEXIST	- fastpath handler of the same name already exists.
 */
int fanotify_fastpath_add(struct fsnotify_group *group,
			  struct fanotify_fastpath_args __user *argp)
{
	struct fanotify_fastpath_hook *fp_hook;
	struct fanotify_fastpath_ops *fp_ops;
	struct fanotify_fastpath_args args;
	void *init_args = NULL;
	int ret = 0;

	ret = copy_from_user(&args, argp, sizeof(args));
	if (ret)
		return -EFAULT;

	if (args.version != 1 || args.flags || args.init_args_size > FAN_FP_ARGS_MAX)
		return -EINVAL;

	args.name[FAN_FP_NAME_MAX - 1] = '\0';

	fsnotify_group_lock(group);

	if (rcu_access_pointer(group->fanotify_data.fp_hook)) {
		fsnotify_group_unlock(group);
		return -EBUSY;
	}

	fp_hook = kzalloc(sizeof(*fp_hook), GFP_KERNEL);
	if (!fp_hook) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&fp_list_lock);
	fp_ops = fanotify_fastpath_find(args.name);
	if (!fp_ops || !try_module_get(fp_ops->owner)) {
		spin_unlock(&fp_list_lock);
		ret = -ENOENT;
		goto err_free_hook;
	}
	spin_unlock(&fp_list_lock);

	if (!capable(CAP_SYS_ADMIN) && (fp_ops->flags & FAN_FP_F_SYS_ADMIN_ONLY)) {
		ret = -EPERM;
		goto err_module_put;
	}

	if (fp_ops->fp_init) {
		if (args.init_args_size) {
			init_args = kzalloc(args.init_args_size, GFP_KERNEL);
			if (!init_args) {
				ret = -ENOMEM;
				goto err_module_put;
			}
			if (copy_from_user(init_args, (void __user *)args.init_args,
					   args.init_args_size)) {
				ret = -EFAULT;
				goto err_free_args;
			}

		}
		ret = fp_ops->fp_init(fp_hook, init_args);
		if (ret)
			goto err_free_args;
		kfree(init_args);
	}
	fp_hook->ops = fp_ops;
	rcu_assign_pointer(group->fanotify_data.fp_hook, fp_hook);

out:
	fsnotify_group_unlock(group);
	return ret;

err_free_args:
	kfree(init_args);
err_module_put:
	module_put(fp_ops->owner);
err_free_hook:
	kfree(fp_hook);
	goto out;
}

void fanotify_fastpath_hook_free(struct fanotify_fastpath_hook *fp_hook)
{
	if (fp_hook->ops->fp_free)
		fp_hook->ops->fp_free(fp_hook);

	module_put(fp_hook->ops->owner);
	kfree(fp_hook);
}

/*
 * fanotify_fastpath_add - Delete a fastpath handler from fsnotify_group.
 */
void fanotify_fastpath_del(struct fsnotify_group *group)
{
	struct fanotify_fastpath_hook *fp_hook;

	fsnotify_group_lock(group);
	fp_hook = group->fanotify_data.fp_hook;
	if (!fp_hook)
		goto out;

	rcu_assign_pointer(group->fanotify_data.fp_hook, NULL);
	fanotify_fastpath_hook_free(fp_hook);

out:
	fsnotify_group_unlock(group);
}

static int __init fanotify_fastpath_init(void)
{
	fan_fp_root_kobj = kobject_create_and_add("fanotify_fastpath", kernel_kobj);
	if (!fan_fp_root_kobj)
		return -ENOMEM;
	return 0;
}
device_initcall(fanotify_fastpath_init);
