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
