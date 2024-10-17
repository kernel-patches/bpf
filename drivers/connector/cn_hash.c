// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Anjali Kulkarni <anjali.k.kulkarni@oracle.com>
 *
 * Copyright (c) 2024 Oracle and/or its affiliates.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/connector.h>
#include <linux/mutex.h>
#include <linux/pid_namespace.h>

#include <linux/cn_proc.h>

struct cn_hash_dev *cn_hash_alloc_dev(const char *name)
{
	struct cn_hash_dev *hdev;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return NULL;

	snprintf(hdev->name, sizeof(hdev->name), "%s", name);
	atomic_set(&hdev->hrefcnt, 0);
	mutex_init(&hdev->uexit_hash_lock);
	hash_init(hdev->uexit_pid_htable);
	return hdev;
}

void cn_hash_free_dev(struct cn_hash_dev *hdev)
{
	struct uexit_pid_hnode *hnode;
	struct hlist_node *tmp;
	int bucket;

	pr_debug("%s: Freeing entire hdev %p\n", __func__, hdev);

	mutex_lock(&hdev->uexit_hash_lock);
	hash_for_each_safe(hdev->uexit_pid_htable, bucket, tmp,
			hnode, uexit_pid_hlist) {
		hash_del(&hnode->uexit_pid_hlist);
		pr_debug("%s: Freeing node for pid %d\n",
				__func__, hnode->pid);
		kfree(hnode);
	}

	mutex_unlock(&hdev->uexit_hash_lock);
	mutex_destroy(&hdev->uexit_hash_lock);

	/*
	 * This refcnt check is added in case CONFIG_CONNECTOR is
	 * compiled with =m as a module. In that case, when unloading
	 * the module, we need to make sure no hash entries are still
	 * present in the hdev table.
	 */
	while (atomic_read(&hdev->hrefcnt)) {
		pr_info("Waiting for %s to become free: refcnt=%d\n",
				hdev->name, atomic_read(&hdev->hrefcnt));
		msleep(1000);
	}

	kfree(hdev);
	hdev = NULL;
}

static struct uexit_pid_hnode *cn_hash_alloc_elem(__u32 uexit_code, pid_t pid)
{
	struct uexit_pid_hnode *elem;

	elem = kzalloc(sizeof(*elem), GFP_KERNEL);
	if (!elem)
		return NULL;

	INIT_HLIST_NODE(&elem->uexit_pid_hlist);
	elem->uexit_code = uexit_code;
	elem->pid = pid;
	return elem;
}

static inline void cn_hash_free_elem(struct uexit_pid_hnode *elem)
{
	kfree(elem);
}

int cn_hash_add_elem(struct cn_hash_dev *hdev, __u32 uexit_code, pid_t pid)
{
	struct uexit_pid_hnode *elem, *hnode;

	elem = cn_hash_alloc_elem(uexit_code, pid);
	if (!elem) {
		pr_err("%s: cn_hash_alloc_elem() returned NULL pid %d\n",
				__func__, pid);
		return -ENOMEM;
	}

	mutex_lock(&hdev->uexit_hash_lock);
	/*
	 * Check if an entry for the same pid already exists
	 */
	hash_for_each_possible(hdev->uexit_pid_htable,
				hnode, uexit_pid_hlist, pid) {
		if (hnode->pid == pid) {
			mutex_unlock(&hdev->uexit_hash_lock);
			cn_hash_free_elem(elem);
			pr_debug("%s: pid %d already exists in hash table\n",
				__func__, pid);
			return -EEXIST;
		}
	}

	hash_add(hdev->uexit_pid_htable, &elem->uexit_pid_hlist, pid);
	mutex_unlock(&hdev->uexit_hash_lock);

	atomic_inc(&hdev->hrefcnt);

	pr_debug("%s: After hash_add of pid %d elem %p hrefcnt %d\n",
			__func__, pid, elem, atomic_read(&hdev->hrefcnt));
	return 0;
}

int cn_hash_del_get_exval(struct cn_hash_dev *hdev, pid_t pid)
{
	struct uexit_pid_hnode *hnode;
	struct hlist_node *tmp;
	int excde;

	mutex_lock(&hdev->uexit_hash_lock);
	hash_for_each_possible_safe(hdev->uexit_pid_htable,
				hnode, tmp, uexit_pid_hlist, pid) {
		if (hnode->pid == pid) {
			excde = hnode->uexit_code;
			hash_del(&hnode->uexit_pid_hlist);
			mutex_unlock(&hdev->uexit_hash_lock);
			kfree(hnode);
			atomic_dec(&hdev->hrefcnt);
			pr_debug("%s: After hash_del of pid %d, found exit code %u hrefcnt %d\n",
					__func__, pid, excde,
					atomic_read(&hdev->hrefcnt));
			return excde;
		}
	}

	mutex_unlock(&hdev->uexit_hash_lock);
	pr_err("%s: pid %d not found in hash table\n",
			__func__, pid);
	return -EINVAL;
}

int cn_hash_get_exval(struct cn_hash_dev *hdev, pid_t pid)
{
	struct uexit_pid_hnode *hnode;
	__u32 excde;

	mutex_lock(&hdev->uexit_hash_lock);
	hash_for_each_possible(hdev->uexit_pid_htable,
				hnode, uexit_pid_hlist, pid) {
		if (hnode->pid == pid) {
			excde = hnode->uexit_code;
			mutex_unlock(&hdev->uexit_hash_lock);
			pr_debug("%s: Found exit code %u for pid %d\n",
					__func__, excde, pid);
			return excde;
		}
	}

	mutex_unlock(&hdev->uexit_hash_lock);
	pr_debug("%s: pid %d not found in hash table\n",
			__func__, pid);
	return -EINVAL;
}

int cn_hash_display_hlist(struct cn_hash_dev *hdev, pid_t pid, int max_len,
				int *hkey, int *key_display)
{
	struct uexit_pid_hnode *hnode;
	int key, count = 0;

	mutex_lock(&hdev->uexit_hash_lock);
	key = hash_min(pid, HASH_BITS(hdev->uexit_pid_htable));
	pr_debug("Bucket: %d\n", key);

	hlist_for_each_entry(hnode,
			&hdev->uexit_pid_htable[key],
			uexit_pid_hlist) {
		if (key_display[key] != 1) {
			if (hnode->uexit_pid_hlist.next == NULL)
				pr_debug("pid %d ", hnode->pid);
			else
				pr_debug("pid %d --> ", hnode->pid);
		}
		count++;
	}

	mutex_unlock(&hdev->uexit_hash_lock);

	if ((key_display[key] != 1) && !count)
		pr_debug("(empty)\n");

	pr_debug("\n");

	*hkey = key;

	if (count > max_len) {
		pr_err("%d entries in hlist for key %d, expected %d\n",
				count, key, max_len);
		return -EINVAL;
	}

	return 0;
}

bool cn_hash_table_empty(struct cn_hash_dev *hdev)
{
	bool is_empty;

	is_empty = hash_empty(hdev->uexit_pid_htable);
	pr_debug("Hash table is %s\n", (is_empty ? "empty" : "not empty"));

	return is_empty;
}
