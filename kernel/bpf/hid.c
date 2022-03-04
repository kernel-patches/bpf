// SPDX-License-Identifier: GPL-2.0
/*
 * based on kernel/bpf/net-namespace.c
 */

#include <linux/bpf.h>
#include <linux/bpf-hid.h>
#include <linux/filter.h>
#include <linux/hid.h>
#include <linux/hidraw.h>

/*
 * Functions to manage BPF programs attached to hid
 */

struct bpf_hid_link {
	struct bpf_link link;
	enum bpf_attach_type type;
	enum bpf_hid_attach_type hid_type;

	/* Must be accessed with bpf_hid_mutex held. */
	struct hid_device *hdev;
	struct list_head node; /* node in list of links attached to hid */
};

/* Protects updates to bpf_hid */
DEFINE_MUTEX(bpf_hid_mutex);

static struct bpf_hid_hooks hid_hooks = {0};

void bpf_hid_set_hooks(struct bpf_hid_hooks *hooks)
{
	if (hooks)
		hid_hooks = *hooks;
	else
		memset(&hid_hooks, 0, sizeof(hid_hooks));
}
EXPORT_SYMBOL_GPL(bpf_hid_set_hooks);

BPF_CALL_5(bpf_hid_get_data, void*, ctx, u64, offset, u32, n, void*, data, u64, size)
{
	struct hid_bpf_ctx *bpf_ctx = ctx;

	if (!hid_hooks.hid_get_data)
		return -EOPNOTSUPP;

	return hid_hooks.hid_get_data(bpf_ctx->hdev,
				      bpf_ctx->data, bpf_ctx->allocated_size,
				      offset, n,
				      data, size);
}

static const struct bpf_func_proto bpf_hid_get_data_proto = {
	.func      = bpf_hid_get_data,
	.gpl_only  = true,
	.ret_type  = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_ANYTHING,
	.arg4_type = ARG_PTR_TO_MEM,
	.arg5_type = ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_5(bpf_hid_set_data, void*, ctx, u64, offset, u32, n, void*, data, u64, size)
{
	struct hid_bpf_ctx *bpf_ctx = ctx;

	if (!hid_hooks.hid_set_data)
		return -EOPNOTSUPP;

	hid_hooks.hid_set_data(bpf_ctx->hdev,
			       bpf_ctx->data, bpf_ctx->allocated_size,
			       offset, n,
			       data, size);
	return 0;
}

static const struct bpf_func_proto bpf_hid_set_data_proto = {
	.func      = bpf_hid_set_data,
	.gpl_only  = true,
	.ret_type  = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_ANYTHING,
	.arg4_type = ARG_PTR_TO_MEM,
	.arg5_type = ARG_CONST_SIZE_OR_ZERO,
};

static const struct bpf_func_proto *
hid_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_hid_get_data:
		return &bpf_hid_get_data_proto;
	case BPF_FUNC_hid_set_data:
		return &bpf_hid_set_data_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool hid_is_valid_access(int off, int size,
				enum bpf_access_type access_type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info)
{
	/* everything not in ctx is prohibited */
	if (off < 0 || off + size > sizeof(struct hid_bpf_ctx) + HID_BPF_MIN_BUFFER_SIZE)
		return false;

	switch (off) {
	/* type, allocated_size, hdev are read-only */
	case bpf_ctx_range_till(struct hid_bpf_ctx, type, hdev):
		return access_type == BPF_READ;
	}

	/* everything else is read/write */
	return true;
}

const struct bpf_verifier_ops hid_verifier_ops = {
	.get_func_proto  = hid_func_proto,
	.is_valid_access = hid_is_valid_access
};

/* Must be called with bpf_hid_mutex held. */
static void bpf_hid_run_array_detach(struct hid_device *hdev,
				     enum bpf_hid_attach_type type)
{
	struct bpf_prog_array *run_array;

	run_array = rcu_replace_pointer(hdev->bpf.run_array[type], NULL,
					lockdep_is_held(&bpf_hid_mutex));
	bpf_prog_array_free(run_array);

	if (hid_hooks.array_detached)
		hid_hooks.array_detached(hdev, type);
}

static int link_index(struct hid_device *hdev, enum bpf_hid_attach_type type,
		      struct bpf_hid_link *link)
{
	struct bpf_hid_link *pos;
	int i = 0;

	list_for_each_entry(pos, &hdev->bpf.links[type], node) {
		if (pos == link)
			return i;
		i++;
	}
	return -ENOENT;
}

static int link_count(struct hid_device *hdev, enum bpf_hid_attach_type type)
{
	struct list_head *pos;
	int i = 0;

	list_for_each(pos, &hdev->bpf.links[type])
		i++;
	return i;
}

static void fill_prog_array(struct hid_device *hdev, enum bpf_hid_attach_type type,
			    struct bpf_prog_array *prog_array)
{
	struct bpf_hid_link *pos;
	unsigned int i = 0;

	list_for_each_entry(pos, &hdev->bpf.links[type], node) {
		prog_array->items[i].prog = pos->link.prog;
		i++;
	}
}

static void bpf_hid_link_release(struct bpf_link *link)
{
	struct bpf_hid_link *hid_link =
		container_of(link, struct bpf_hid_link, link);
	enum bpf_hid_attach_type type = hid_link->hid_type;
	struct bpf_prog_array *old_array, *new_array;
	struct hid_device *hdev;
	int cnt, idx;

	mutex_lock(&bpf_hid_mutex);

	hdev = hid_link->hdev;
	if (!hdev)
		goto out_unlock;

	/* Remember link position in case of safe delete */
	idx = link_index(hdev, type, hid_link);
	list_del(&hid_link->node);

	cnt = link_count(hdev, type);
	if (!cnt) {
		bpf_hid_run_array_detach(hdev, type);
		goto out_unlock;
	}

	old_array = rcu_dereference_protected(hdev->bpf.run_array[type],
					      lockdep_is_held(&bpf_hid_mutex));
	new_array = bpf_prog_array_alloc(cnt, GFP_KERNEL);
	if (!new_array) {
		WARN_ON(bpf_prog_array_delete_safe_at(old_array, idx));
		goto out_unlock;
	}
	fill_prog_array(hdev, type, new_array);
	rcu_assign_pointer(hdev->bpf.run_array[type], new_array);
	bpf_prog_array_free(old_array);

out_unlock:
	hid_link->hdev = NULL;
	mutex_unlock(&bpf_hid_mutex);
}

static int bpf_hid_link_detach(struct bpf_link *link)
{
	bpf_hid_link_release(link);
	return 0;
}

static void bpf_hid_link_dealloc(struct bpf_link *link)
{
	struct bpf_hid_link *hid_link =
		container_of(link, struct bpf_hid_link, link);

	kfree(hid_link);
}

static int bpf_hid_link_update_prog(struct bpf_link *link,
				    struct bpf_prog *new_prog,
				    struct bpf_prog *old_prog)
{
	struct bpf_hid_link *hid_link =
		container_of(link, struct bpf_hid_link, link);
	enum bpf_hid_attach_type type = hid_link->hid_type;
	struct bpf_prog_array *run_array;
	struct hid_device *hdev;
	int idx, ret;

	if (old_prog && old_prog != link->prog)
		return -EPERM;
	if (new_prog->type != link->prog->type)
		return -EINVAL;

	mutex_lock(&bpf_hid_mutex);

	hdev = hid_link->hdev;
	if (!hdev) {
		/* hid dying */
		ret = -ENOLINK;
		goto out_unlock;
	}

	run_array = rcu_dereference_protected(hdev->bpf.run_array[type],
					      lockdep_is_held(&bpf_hid_mutex));
	idx = link_index(hdev, type, hid_link);
	ret = bpf_prog_array_update_at(run_array, idx, new_prog);
	if (ret)
		goto out_unlock;

	old_prog = xchg(&link->prog, new_prog);
	bpf_prog_put(old_prog);

out_unlock:
	mutex_unlock(&bpf_hid_mutex);
	return ret;
}

static int bpf_hid_link_fill_info(const struct bpf_link *link,
				  struct bpf_link_info *info)
{
	const struct bpf_hid_link *hid_link =
		container_of(link, struct bpf_hid_link, link);
	int hidraw_ino = -1;
	struct hid_device *hdev;
	struct hidraw *hidraw;

	mutex_lock(&bpf_hid_mutex);
	hdev = hid_link->hdev;
	if (hdev && hdev->hidraw) {
		hidraw = hdev->hidraw;
		hidraw_ino = hidraw->minor;
	}
	mutex_unlock(&bpf_hid_mutex);

	info->hid.hidraw_ino = hidraw_ino;
	info->hid.attach_type = hid_link->type;
	return 0;
}

static void bpf_hid_link_show_fdinfo(const struct bpf_link *link,
				     struct seq_file *seq)
{
	struct bpf_link_info info = {};

	bpf_hid_link_fill_info(link, &info);
	seq_printf(seq,
		   "hidraw_ino:\t%u\n"
		   "attach_type:\t%u\n",
		   info.hid.hidraw_ino,
		   info.hid.attach_type);
}

static const struct bpf_link_ops bpf_hid_link_ops = {
	.release = bpf_hid_link_release,
	.dealloc = bpf_hid_link_dealloc,
	.detach = bpf_hid_link_detach,
	.update_prog = bpf_hid_link_update_prog,
	.fill_link_info = bpf_hid_link_fill_info,
	.show_fdinfo = bpf_hid_link_show_fdinfo,
};

/* Must be called with bpf_hid_mutex held. */
static int __bpf_hid_prog_query(const union bpf_attr *attr,
				union bpf_attr __user *uattr,
				  struct hid_device *hdev,
				  enum bpf_hid_attach_type type)
{
	__u32 __user *prog_ids = u64_to_user_ptr(attr->query.prog_ids);
	struct bpf_prog_array *run_array;
	u32 prog_cnt = 0, flags = 0;

	run_array = rcu_dereference_protected(hdev->bpf.run_array[type],
					      lockdep_is_held(&bpf_hid_mutex));
	if (run_array)
		prog_cnt = bpf_prog_array_length(run_array);

	if (copy_to_user(&uattr->query.attach_flags, &flags, sizeof(flags)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.prog_cnt, &prog_cnt, sizeof(prog_cnt)))
		return -EFAULT;
	if (!attr->query.prog_cnt || !prog_ids || !prog_cnt)
		return 0;

	return bpf_prog_array_copy_to_user(run_array, prog_ids,
					   attr->query.prog_cnt);
}

int bpf_hid_prog_query(const union bpf_attr *attr,
		       union bpf_attr __user *uattr)
{
	enum bpf_hid_attach_type type;
	struct hid_device *hdev;
	int ret;

	if (attr->query.query_flags || !hid_hooks.hdev_from_fd)
		return -EINVAL;

	type = to_bpf_hid_attach_type(attr->query.attach_type);
	if (type < 0)
		return -EINVAL;

	hdev = hid_hooks.hdev_from_fd(attr->query.target_fd);
	if (IS_ERR(hdev))
		return PTR_ERR(hdev);

	mutex_lock(&bpf_hid_mutex);
	ret = __bpf_hid_prog_query(attr, uattr, hdev, type);
	mutex_unlock(&bpf_hid_mutex);

	return ret;
}

static int bpf_hid_max_progs(enum bpf_hid_attach_type type)
{
	switch (type) {
	case BPF_HID_ATTACH_DEVICE_EVENT:
		return 64;
	case BPF_HID_ATTACH_RDESC_FIXUP:
		return 1;
	default:
		return 0;
	}
}

static int bpf_hid_link_attach(struct hid_device *hdev, struct bpf_link *link,
			       enum bpf_hid_attach_type type)
{
	struct bpf_hid_link *hid_link =
		container_of(link, struct bpf_hid_link, link);
	struct bpf_prog_array *run_array;
	int cnt, err = 0;

	mutex_lock(&bpf_hid_mutex);

	cnt = link_count(hdev, type);
	if (cnt >= bpf_hid_max_progs(type)) {
		err = -E2BIG;
		goto out_unlock;
	}

	if (hid_hooks.link_attach) {
		err = hid_hooks.link_attach(hdev, type);
		if (err)
			goto out_unlock;
	}

	run_array = bpf_prog_array_alloc(cnt + 1, GFP_KERNEL);
	if (!run_array) {
		err = -ENOMEM;
		goto out_unlock;
	}

	list_add_tail(&hid_link->node, &hdev->bpf.links[type]);

	fill_prog_array(hdev, type, run_array);
	run_array = rcu_replace_pointer(hdev->bpf.run_array[type], run_array,
					lockdep_is_held(&bpf_hid_mutex));
	bpf_prog_array_free(run_array);

	if (hid_hooks.link_attached)
		hid_hooks.link_attached(hdev, type);

out_unlock:
	mutex_unlock(&bpf_hid_mutex);
	return err;
}

int bpf_hid_link_create(const union bpf_attr *attr, struct bpf_prog *prog)
{
	enum bpf_hid_attach_type hid_type;
	struct bpf_link_primer link_primer;
	struct bpf_hid_link *hid_link;
	enum bpf_attach_type type;
	struct hid_device *hdev;
	int err;

	if (attr->link_create.flags || !hid_hooks.hdev_from_fd)
		return -EINVAL;

	type = attr->link_create.attach_type;
	hid_type = to_bpf_hid_attach_type(type);
	if (hid_type < 0)
		return -EINVAL;

	hdev = hid_hooks.hdev_from_fd(attr->link_create.target_fd);
	if (IS_ERR(hdev))
		return PTR_ERR(hdev);

	hid_link = kzalloc(sizeof(*hid_link), GFP_USER);
	if (!hid_link)
		return -ENOMEM;

	bpf_link_init(&hid_link->link, BPF_LINK_TYPE_HID,
		      &bpf_hid_link_ops, prog);
	hid_link->hdev = hdev;
	hid_link->type = type;
	hid_link->hid_type = hid_type;

	err = bpf_link_prime(&hid_link->link, &link_primer);
	if (err) {
		kfree(hid_link);
		return err;
	}

	err = bpf_hid_link_attach(hdev, &hid_link->link, hid_type);
	if (err) {
		bpf_link_cleanup(&link_primer);
		return err;
	}

	return bpf_link_settle(&link_primer);
}

const struct bpf_prog_ops hid_prog_ops = {
};

int bpf_hid_init(struct hid_device *hdev)
{
	int type;

	for (type = 0; type < MAX_BPF_HID_ATTACH_TYPE; type++)
		INIT_LIST_HEAD(&hdev->bpf.links[type]);

	return 0;
}
EXPORT_SYMBOL_GPL(bpf_hid_init);

void bpf_hid_exit(struct hid_device *hdev)
{
	enum bpf_hid_attach_type type;
	struct bpf_hid_link *hid_link;

	mutex_lock(&bpf_hid_mutex);
	for (type = 0; type < MAX_BPF_HID_ATTACH_TYPE; type++) {
		bpf_hid_run_array_detach(hdev, type);
		list_for_each_entry(hid_link, &hdev->bpf.links[type], node) {
			hid_link->hdev = NULL; /* auto-detach link */
		}
	}
	mutex_unlock(&bpf_hid_mutex);
}
EXPORT_SYMBOL_GPL(bpf_hid_exit);
