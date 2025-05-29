// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>


struct str_listener {
	struct hlist_node node;
	char *str;
	resource_handler handler;
	bool kmalloc;
};

DEFINE_STATIC_SRCU(srcu);
static DEFINE_MUTEX(str_listeners_mutex);
static DEFINE_HASHTABLE(str_listeners, 8);

static struct str_listener *find_listener(const char *str)
{
	struct str_listener *item;
	unsigned int hash = jhash(str, strlen(str), 0);

	hash_for_each_possible(str_listeners, item, node, hash) {
		if (strcmp(item->str, str) == 0)
			return item;
	}
	return NULL;
}

static void __mem_range_result_free(struct rcu_head *rcu)
{
	struct mem_range_result *result = container_of(rcu, struct mem_range_result, rcu);
	struct mem_cgroup *memcg, *old_memcg;

	memcg = result->memcg;
	old_memcg = set_active_memcg(memcg);
	if (likely(!!result->buf)) {
		if (result->kmalloc)
			kfree(result->buf);
		else
			vfree(result->buf);
	}
	kfree(result);
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
}

static void __mem_range_result_put(struct kref *kref)
{
	struct mem_range_result *result = container_of(kref, struct mem_range_result, ref);

	call_srcu(&srcu, &result->rcu, __mem_range_result_free);
}

int mem_range_result_put(struct mem_range_result *result)
{

	if (!result) {
		pr_err("%s, receive invalid range\n", __func__);
		return -EINVAL;
	}

	kref_put(&result->ref, __mem_range_result_put);
	return 0;
}

__bpf_kfunc int bpf_mem_range_result_put(struct mem_range_result *result)
{
	return mem_range_result_put(result);
}

/*
 * Cache the content in @buf into kernel
 */
__bpf_kfunc int bpf_copy_to_kernel(const char *name, char *buf, int size)
{
	struct mem_range_result *range;
	struct mem_cgroup *memcg, *old_memcg;
	struct str_listener *item;
	resource_handler handler;
	bool kmalloc;
	char *kbuf;
	int id, ret = 0;

	id = srcu_read_lock(&srcu);
	item = find_listener(name);
	if (!item) {
		srcu_read_unlock(&srcu, id);
		return -EINVAL;
	}
	kmalloc = item->kmalloc;
	handler = item->handler;
	srcu_read_unlock(&srcu, id);
	memcg = get_mem_cgroup_from_current();
	old_memcg = set_active_memcg(memcg);
	range = kmalloc(sizeof(struct mem_range_result), GFP_KERNEL);
	if (!range) {
		pr_err("fail to allocate mem_range_result\n");
		ret = -ENOMEM;
		goto err;
	}

	kref_init(&range->ref);
	if (item->kmalloc)
		kbuf = kmalloc(size, GFP_KERNEL | __GFP_ACCOUNT);
	else
		kbuf = __vmalloc(size, GFP_KERNEL | __GFP_ACCOUNT);
	if (!kbuf) {
		kfree(range);
		ret = -ENOMEM;
		goto err;
	}
	ret = copy_from_kernel_nofault(kbuf, buf, size);
	if (unlikely(ret < 0)) {
		kfree(range);
		if (item->kmalloc)
			kfree(kbuf);
		else
			vfree(kbuf);
		ret = -EINVAL;
		goto err;
	}
	range->kmalloc = item->kmalloc;
	range->buf = kbuf;
	range->buf_sz = size;
	range->data_sz = size;
	range->memcg = memcg;
	mem_cgroup_tryget(memcg);
	range->status = 0;
	ret = handler(name, range);
	mem_range_result_put(range);
err:
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
	return ret;
}

int register_carrier_listener(struct carrier_listener *listener)
{
	struct str_listener *item;
	unsigned int hash;
	int ret;

	if (!listener->name)
		return -EINVAL;
	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;
	item->str = kstrdup(listener->name, GFP_KERNEL);
	if (!item->str) {
		kfree(item);
		return -ENOMEM;
	}
	item->handler = listener->handler;
	item->kmalloc = listener->kmalloc;
	hash = jhash(item->str, strlen(item->str), 0);
	mutex_lock(&str_listeners_mutex);
	if (!find_listener(item->str)) {
		hash_add(str_listeners, &item->node, hash);
	} else {
		kfree(item->str);
		kfree(item);
		ret = -EBUSY;
	}
	mutex_unlock(&str_listeners_mutex);

	return ret;
}
EXPORT_SYMBOL(register_carrier_listener);

int unregister_carrier_listener(char *str)
{
	struct str_listener *item;
	int ret = 0;

	mutex_lock(&str_listeners_mutex);
	item = find_listener(str);
	if (!!item)
		hash_del(&item->node);
	else
		ret = -EINVAL;
	mutex_unlock(&str_listeners_mutex);

	return ret;
}
EXPORT_SYMBOL(unregister_carrier_listener);

