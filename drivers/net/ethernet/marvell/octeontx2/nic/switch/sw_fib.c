// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU switch driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/route.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"
#include "sw_fib.h"

static DEFINE_SPINLOCK(sw_fib_llock);
static LIST_HEAD(sw_fib_lh);

static struct workqueue_struct *sw_fib_wq;
static void sw_fib_work_handler(struct work_struct *work);
static DECLARE_DELAYED_WORK(sw_fib_work, sw_fib_work_handler);

struct sw_fib_list_entry {
	struct list_head lh;
	struct otx2_nic *pf;
	int cnt;
	struct fib_entry *entry;
};

static int sw_fib_notify(struct otx2_nic *pf,
			 int cnt,
			 struct fib_entry *entry)
{
	struct fib_notify_req *req;
	int rc;

	if (cnt > 16)
		return -EINVAL;

	mutex_lock(&pf->mbox.lock);
	req = otx2_mbox_alloc_msg_fib_notify(&pf->mbox);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}

	req->cnt = cnt;
	memcpy(req->entry, entry, sizeof(*entry) * cnt);

	rc = otx2_sync_mbox_msg(&pf->mbox);
out:
	mutex_unlock(&pf->mbox.lock);
	return rc;
}

static void sw_fib_work_handler(struct work_struct *work)
{
	struct sw_fib_list_entry *lentry;
	LIST_HEAD(tlist);

	spin_lock_bh(&sw_fib_llock);
	list_splice_init(&sw_fib_lh, &tlist);
	spin_unlock_bh(&sw_fib_llock);

	while ((lentry =
		list_first_entry_or_null(&tlist,
					 struct sw_fib_list_entry, lh)) != NULL) {
		list_del_init(&lentry->lh);
		sw_fib_notify(lentry->pf, lentry->cnt, lentry->entry);
		kfree(lentry->entry);
		kfree(lentry);
	}

	spin_lock_bh(&sw_fib_llock);
	if (!list_empty(&sw_fib_lh))
		queue_delayed_work(sw_fib_wq, &sw_fib_work,
				   msecs_to_jiffies(10));
	spin_unlock_bh(&sw_fib_llock);
}

int sw_fib_add_to_list(struct net_device *dev,
		       struct fib_entry *entry, int cnt)
{
	struct otx2_nic *pf = netdev_priv(dev);
	struct sw_fib_list_entry *lentry;

	lentry = kcalloc(1, sizeof(*lentry), GFP_ATOMIC);
	if (!lentry)
		return -ENOMEM;

	lentry->pf = pf;
	lentry->cnt = cnt;
	lentry->entry = entry;
	INIT_LIST_HEAD(&lentry->lh);

	spin_lock(&sw_fib_llock);
	list_add_tail(&lentry->lh, &sw_fib_lh);
	queue_delayed_work(sw_fib_wq, &sw_fib_work,
			   msecs_to_jiffies(10));
	spin_unlock(&sw_fib_llock);

	return 0;
}

int sw_fib_init(void)
{
	sw_fib_wq = alloc_workqueue("sw_pf_fib_wq", 0, 0);
	if (!sw_fib_wq)
		return -ENOMEM;

	return 0;
}

void sw_fib_deinit(void)
{
	struct sw_fib_list_entry *lentry;
	LIST_HEAD(tlist);

	cancel_delayed_work_sync(&sw_fib_work);
	destroy_workqueue(sw_fib_wq);

	spin_lock_bh(&sw_fib_llock);
	list_splice_init(&sw_fib_lh, &tlist);
	spin_unlock_bh(&sw_fib_llock);

	while ((lentry =
		list_first_entry_or_null(&tlist,
					 struct sw_fib_list_entry, lh)) != NULL) {
		list_del_init(&lentry->lh);
		kfree(lentry->entry);
		kfree(lentry);
	}
}
