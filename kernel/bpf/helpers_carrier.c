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

DEFINE_STATIC_SRCU(srcu);
static DEFINE_MUTEX(carrier_listeners_mutex);
static DEFINE_HASHTABLE(carrier_listeners, 8);

static struct carrier_listener *find_listener(const char *str)
{
	struct carrier_listener *item;
	unsigned int hash = jhash(str, strlen(str), 0);

	hash_for_each_possible_rcu(carrier_listeners, item, node, hash) {
		if (strcmp(item->name, str) == 0)
			return item;
	}
	return NULL;
}

static void __mem_range_result_free(struct kref *kref)
{
	struct mem_range_result *result = container_of(kref, struct mem_range_result, ref);
	struct mem_cgroup *memcg, *old_memcg;

	/* vunmap() is blocking */
	might_sleep();
	memcg = result->memcg;
	old_memcg = set_active_memcg(memcg);
	if (likely(!!result->buf)) {
		switch (result->alloc_type) {
		case TYPE_KALLOC:
			kfree(result->buf);
			break;
		case TYPE_VMALLOC:
			vfree(result->buf);
			break;
		case TYPE_VMAP:
			vunmap(result->buf);
			for (unsigned int i = 0; i < result->pg_cnt; i++)
				__free_pages(result->pages[i], 0);
			vfree(result->pages);
		}
	}
	kfree(result);
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
}

struct mem_range_result *mem_range_result_alloc(void)
{
	struct mem_range_result *range;

	range = kmalloc(sizeof(struct mem_range_result), GFP_KERNEL);
	if (!range)
		return NULL;
	kref_init(&range->ref);
	return range;
}

void mem_range_result_get(struct mem_range_result *r)
{
	if (!r)
		return;
	kref_get(&r->ref);
}

void mem_range_result_put(struct mem_range_result *r)
{
	might_sleep();
	if (!r)
		return;
	kref_put(&r->ref, __mem_range_result_free);
}

__bpf_kfunc int bpf_mem_range_result_put(struct mem_range_result *result)
{
	mem_range_result_put(result);
	return 0;
}

/*
 * Cache the content in @buf into kernel
 */
__bpf_kfunc int bpf_copy_to_kernel(const char *name, char *buf, int size)
{
	struct mem_range_result *range;
	struct mem_cgroup *memcg, *old_memcg;
	struct carrier_listener *item;
	resource_handler handler;
	enum alloc_type alloc_type;
	char *kbuf;
	int id, ret = 0;

	/*
	 * This lock ensures no use of item after free and there is no in-flight
	 * handler
	 */
	id = srcu_read_lock(&srcu);
	item = find_listener(name);
	if (!item) {
		srcu_read_unlock(&srcu, id);
		return -EINVAL;
	}
	alloc_type = item->alloc_type;
	handler = item->handler;
	memcg = get_mem_cgroup_from_current();
	old_memcg = set_active_memcg(memcg);
	range = mem_range_result_alloc();
	if (!range) {
		pr_err("fail to allocate mem_range_result\n");
		ret = -ENOMEM;
		goto err;
	}

	switch (alloc_type) {
	case TYPE_KALLOC:
		kbuf = kmalloc(size, GFP_KERNEL | __GFP_ACCOUNT);
		break;
	case TYPE_VMALLOC:
		kbuf = __vmalloc(size, GFP_KERNEL | __GFP_ACCOUNT);
		break;
	default:
		kfree(range);
		ret = -EINVAL;
		goto err;
	}
	if (!kbuf) {
		kfree(range);
		ret = -ENOMEM;
		goto err;
	}
	ret = copy_from_kernel_nofault(kbuf, buf, size);
	if (unlikely(ret < 0)) {
		if (range->alloc_type == TYPE_KALLOC)
			kfree(kbuf);
		else
			vfree(kbuf);
		kfree(range);
		ret = -EINVAL;
		goto err;
	}
	range->buf = kbuf;
	range->buf_sz = size;
	range->data_sz = size;
	range->memcg = memcg;
	mem_cgroup_tryget(memcg);
	range->status = 0;
	range->alloc_type = alloc_type;
	/* We exit the lock after the handler finishes */
	ret = handler(name, range);
	srcu_read_unlock(&srcu, id);
	mem_range_result_put(range);
err:
	if (ret != 0)
		srcu_read_unlock(&srcu, id);
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
	return ret;
}

int register_carrier_listener(struct carrier_listener *listener)
{
	unsigned int hash;
	int ret = 0;
	char *str = listener->name;

	/* Not support vmap-ed */
	if (listener->alloc_type > TYPE_VMALLOC)
		return -EINVAL;
	if (!str)
		return -EINVAL;
	hash = jhash(str, strlen(str), 0);
	mutex_lock(&carrier_listeners_mutex);
	if (!find_listener(str))
		hash_add_rcu(carrier_listeners, &listener->node, hash);
	else
		ret = -EBUSY;
	mutex_unlock(&carrier_listeners_mutex);

	return ret;
}
EXPORT_SYMBOL(register_carrier_listener);

int unregister_carrier_listener(char *str)
{
	struct carrier_listener *item;
	int ret = 0;

	mutex_lock(&carrier_listeners_mutex);
	item = find_listener(str);
	if (!!item) {
		hash_del_rcu(&item->node);
		/*
		 * It also waits on in-flight handler. Refer to note on the read
		 * side
		 */
		synchronize_srcu(&srcu);
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&carrier_listeners_mutex);

	return ret;
}
EXPORT_SYMBOL(unregister_carrier_listener);

