// SPDX-License-Identifier: GPL-2.0-only

#include <net/devtx.h>
#include <linux/filter.h>

DEFINE_STATIC_KEY_FALSE(devtx_enabled_key);
EXPORT_SYMBOL_GPL(devtx_enabled_key);

struct devtx_hook_entry {
	struct list_head devtx_hooks;
	struct btf_id_set8 *set;
	const struct xdp_metadata_ops *xmo;
};

static LIST_HEAD(devtx_hooks);
static DEFINE_MUTEX(devtx_hooks_lock);

void devtx_hooks_enable(void)
{
	static_branch_inc(&devtx_enabled_key);
}

void devtx_hooks_disable(void)
{
	static_branch_dec(&devtx_enabled_key);
}

bool devtx_hooks_match(u32 attach_btf_id, const struct xdp_metadata_ops *xmo)
{
	struct devtx_hook_entry *entry, *tmp;
	bool match = false;

	mutex_lock(&devtx_hooks_lock);
	list_for_each_entry_safe(entry, tmp, &devtx_hooks, devtx_hooks) {
		if (btf_id_set8_contains(entry->set, attach_btf_id)) {
			match = entry->xmo == xmo;
			break;
		}
	}
	mutex_unlock(&devtx_hooks_lock);

	return match;
}

int devtx_hooks_register(struct btf_id_set8 *set, const struct xdp_metadata_ops *xmo)
{
	struct devtx_hook_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->set = set;
	entry->xmo = xmo;

	mutex_lock(&devtx_hooks_lock);
	list_add(&entry->devtx_hooks, &devtx_hooks);
	mutex_unlock(&devtx_hooks_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(devtx_hooks_register);

void devtx_hooks_unregister(struct btf_id_set8 *set)
{
	struct devtx_hook_entry *entry, *tmp;

	mutex_lock(&devtx_hooks_lock);
	list_for_each_entry_safe(entry, tmp, &devtx_hooks, devtx_hooks) {
		if (entry->set == set) {
			list_del(&entry->devtx_hooks);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&devtx_hooks_lock);
}
EXPORT_SYMBOL_GPL(devtx_hooks_unregister);

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");

/**
 * bpf_devtx_request_tx_timestamp - Request TX timestamp on the packet.
 * Callable only from the devtx-submit hook.
 * @ctx: devtx context pointer.
 *
 * Returns 0 on success or ``-errno`` on error.
 */
__bpf_kfunc int bpf_devtx_request_tx_timestamp(const struct devtx_ctx *ctx)
{
	return -EOPNOTSUPP;
}

/**
 * bpf_devtx_tx_timestamp - Read TX timestamp of the packet. Callable
 * only from the devtx-complete hook.
 * @ctx: devtx context pointer.
 * @timestamp: Return value pointer.
 *
 * Returns 0 on success or ``-errno`` on error.
 */
__bpf_kfunc int bpf_devtx_tx_timestamp(const struct devtx_ctx *ctx, __u64 *timestamp)
{
	return -EOPNOTSUPP;
}

__diag_pop();

BTF_SET8_START(devtx_sb_kfunc_ids)
#define NETDEV_METADATA_KFUNC(_, name, __) BTF_ID_FLAGS(func, name, 0)
DEVTX_SUBMIT_KFUNC_xxx
#undef NETDEV_METADATA_KFUNC
BTF_SET8_END(devtx_sb_kfunc_ids)

static const struct btf_kfunc_id_set devtx_sb_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &devtx_sb_kfunc_ids,
};

BTF_SET8_START(devtx_cp_kfunc_ids)
#define NETDEV_METADATA_KFUNC(_, name, __) BTF_ID_FLAGS(func, name, 0)
DEVTX_COMPLETE_KFUNC_xxx
#undef NETDEV_METADATA_KFUNC
BTF_SET8_END(devtx_cp_kfunc_ids)

static const struct btf_kfunc_id_set devtx_cp_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &devtx_cp_kfunc_ids,
};

static int __init devtx_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &devtx_sb_kfunc_set);
	if (ret) {
		pr_warn("failed to register devtx_sb kfuncs: %d", ret);
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &devtx_cp_kfunc_set);
	if (ret) {
		pr_warn("failed to register devtx_cp completion kfuncs: %d", ret);
		return ret;
	}

	return 0;
}
late_initcall(devtx_init);
