// SPDX-License-Identifier: GPL-2.0
#include <linux/fanotify.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/bpf.h>

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
	if (!fp_ops || !bpf_try_module_get(fp_ops, fp_ops->owner)) {
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
	bpf_module_put(fp_ops, fp_ops->owner);
err_free_hook:
	kfree(fp_hook);
	goto out;
}

void fanotify_fastpath_hook_free(struct fanotify_fastpath_hook *fp_hook)
{
	if (fp_hook->ops->fp_free)
		fp_hook->ops->fp_free(fp_hook);

	bpf_module_put(fp_hook->ops, fp_hook->ops->owner);
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

__bpf_kfunc_start_defs();

/**
 * bpf_fanotify_data_inode - get inode from fanotify_fastpath_event
 *
 * @event: fanotify_fastpath_event to get inode from
 *
 * Get referenced inode from fanotify_fastpath_event.
 *
 * Return: A refcounted inode or NULL.
 *
 */
__bpf_kfunc struct inode *bpf_fanotify_data_inode(struct fanotify_fastpath_event *event)
{
	struct inode *inode = fsnotify_data_inode(event->data, event->data_type);

	return inode ? igrab(inode) : NULL;
}

/**
 * bpf_fanotify_data_dentry - get dentry from fanotify_fastpath_event
 *
 * @event: fanotify_fastpath_event to get dentry from
 *
 * Get referenced dentry from fanotify_fastpath_event.
 *
 * Return: A refcounted inode or NULL.
 *
 */
__bpf_kfunc struct dentry *bpf_fanotify_data_dentry(struct fanotify_fastpath_event *event)
{
	struct dentry *dentry = fsnotify_data_dentry(event->data, event->data_type);

	return dget(dentry);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_fanotify_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_fanotify_data_inode,
	     KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_fanotify_data_dentry,
	     KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_KFUNCS_END(bpf_fanotify_kfunc_set_ids)

static const struct btf_kfunc_id_set bpf_fanotify_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_fanotify_kfunc_set_ids,
};

static const struct bpf_func_proto *
bpf_fanotify_fastpath_get_func_proto(enum bpf_func_id func_id,
				     const struct bpf_prog *prog)
{
	return tracing_prog_func_proto(func_id, prog);
}

static bool bpf_fanotify_fastpath_is_valid_access(int off, int size,
						  enum bpf_access_type type,
						  const struct bpf_prog *prog,
						  struct bpf_insn_access_aux *info)
{
	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	return true;
}

static int bpf_fanotify_fastpath_btf_struct_access(struct bpf_verifier_log *log,
						   const struct bpf_reg_state *reg,
						   int off, int size)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_fanotify_fastpath_verifier_ops = {
	.get_func_proto		= bpf_fanotify_fastpath_get_func_proto,
	.is_valid_access	= bpf_fanotify_fastpath_is_valid_access,
	.btf_struct_access	= bpf_fanotify_fastpath_btf_struct_access,
};

static int bpf_fanotify_fastpath_reg(void *kdata, struct bpf_link *link)
{
	return fanotify_fastpath_register(kdata);
}

static void bpf_fanotify_fastpath_unreg(void *kdata, struct bpf_link *link)
{
	fanotify_fastpath_unregister(kdata);
}

static int bpf_fanotify_fastpath_init(struct btf *btf)
{
	return 0;
}

static int bpf_fanotify_fastpath_init_member(const struct btf_type *t,
					     const struct btf_member *member,
					     void *kdata, const void *udata)
{
	const struct fanotify_fastpath_ops *uops;
	struct fanotify_fastpath_ops *ops;
	u32 moff;
	int ret;

	uops = (const struct fanotify_fastpath_ops *)udata;
	ops = (struct fanotify_fastpath_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct fanotify_fastpath_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				       sizeof(ops->name));
		if (ret <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int __bpf_fan_fp_handler(struct fsnotify_group *group,
				struct fanotify_fastpath_hook *fp_hook,
				struct fanotify_fastpath_event *fp_event)
{
	return 0;
}

static int __bpf_fan_fp_init(struct fanotify_fastpath_hook *hook, void *args)
{
	return 0;
}

static void __bpf_fan_fp_free(struct fanotify_fastpath_hook *hook)
{
}

/* For bpf_struct_ops->cfi_stubs */
static struct fanotify_fastpath_ops __bpf_fanotify_fastpath_ops = {
	.fp_handler = __bpf_fan_fp_handler,
	.fp_init = __bpf_fan_fp_init,
	.fp_free = __bpf_fan_fp_free,
};

static struct bpf_struct_ops bpf_fanotify_fastpath_ops = {
	.verifier_ops = &bpf_fanotify_fastpath_verifier_ops,
	.reg = bpf_fanotify_fastpath_reg,
	.unreg = bpf_fanotify_fastpath_unreg,
	.init = bpf_fanotify_fastpath_init,
	.init_member = bpf_fanotify_fastpath_init_member,
	.name = "fanotify_fastpath_ops",
	.cfi_stubs = &__bpf_fanotify_fastpath_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_fanotify_fastpath_struct_ops_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_fanotify_kfunc_set);
	ret = ret ?: register_bpf_struct_ops(&bpf_fanotify_fastpath_ops, fanotify_fastpath_ops);
	return ret;
}
late_initcall(bpf_fanotify_fastpath_struct_ops_init);
