// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"
#include "rvu_sw_l3.h"

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct rvu *rvu, int devid)		\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&rvu->afpf_wq_info.mbox_up, devid, sizeof(struct _req_type), \
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}
MBOX_UP_AF2SWDEV_MESSAGES
#undef M

static struct workqueue_struct *sw_l3_offl_wq;

struct l3_entry {
	struct list_head list;
	struct rvu *rvu;
	u32 port_id;
	int cnt;
	struct fib_entry entry[];
};

static DEFINE_MUTEX(l3_offl_llock);
static LIST_HEAD(l3_offl_lh);
static bool l3_offl_work_running;

static struct workqueue_struct *sw_l3_offl_wq;
static void sw_l3_offl_work_handler(struct work_struct *work);
static DECLARE_DELAYED_WORK(l3_offl_work, sw_l3_offl_work_handler);

static int rvu_sw_l3_offl_rule_push(struct list_head *lh)
{
	struct af2swdev_notify_req *req;
	struct fib_entry *entry, *dst;
	struct l3_entry *l3_entry;
	struct rvu *rvu;
	int tot_cnt = 0;
	int swdev_pf;
	int sz, cnt;
	bool rc;

	BUILD_BUG_ON(sizeof(*req) > 1024);

	l3_entry = list_first_entry_or_null(lh, struct l3_entry, list);
	if (!l3_entry)
		return 0;

	rvu = l3_entry->rvu;
	swdev_pf = rvu_get_pf(rvu->pdev, rvu->rswitch.pcifunc);

	mutex_lock(&rvu->mbox_lock);
	req = otx2_mbox_alloc_msg_af2swdev_notify(rvu, swdev_pf);
	if (!req) {
		mutex_unlock(&rvu->mbox_lock);

		while ((l3_entry =
			list_first_entry_or_null(lh,
						 struct l3_entry, list)) != NULL) {
			list_del_init(&l3_entry->list);
			kfree(l3_entry);
		}

		return -ENOMEM;
	}

	dst = &req->entry[0];
	while ((l3_entry =
		list_first_entry_or_null(lh,
					 struct l3_entry, list)) != NULL) {
		entry = l3_entry->entry;
		cnt = l3_entry->cnt;
		sz = sizeof(*entry) * cnt;

		memcpy(dst, entry, sz);
		tot_cnt += cnt;
		dst += cnt;

		list_del_init(&l3_entry->list);
		kfree(l3_entry);
	}
	req->flags = FIB_CMD;
	req->cnt = tot_cnt;

	rc = otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, swdev_pf);
	if (rc)
		otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, swdev_pf);

	mutex_unlock(&rvu->mbox_lock);
	return rc ? 0 : -EFAULT;
}

static atomic64_t req_cnt;
static atomic64_t ack_cnt;
static atomic64_t req_processed;
static LIST_HEAD(l3_local_lh);
static int lcnt;

static void sw_l3_offl_work_handler(struct work_struct *work)
{
	struct l3_entry *l3_entry;
	struct list_head l3lh;
	u64 req, ack, proc;

	INIT_LIST_HEAD(&l3lh);

	mutex_lock(&l3_offl_llock);
	while (1) {
		l3_entry = list_first_entry_or_null(&l3_offl_lh, struct l3_entry, list);

		if (!l3_entry)
			break;

		if (lcnt + l3_entry->cnt > 8 && !list_empty(&l3_local_lh)) {
			req = atomic64_read(&req_cnt);
			atomic64_set(&ack_cnt, req);
			atomic64_set(&req_processed, req);
			mutex_unlock(&l3_offl_llock);
			goto process;
		}

		lcnt += l3_entry->cnt;

		atomic64_inc(&req_cnt);
		list_del_init(&l3_entry->list);
		list_add_tail(&l3_entry->list, &l3_local_lh);
	}
	mutex_unlock(&l3_offl_llock);

	req = atomic64_read(&req_cnt);
	ack = atomic64_read(&ack_cnt);

	if (req > ack) {
		atomic64_set(&ack_cnt, req);
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(100));
		return;
	}

	proc = atomic64_read(&req_processed);
	if (req == proc) {
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(1000));
		return;
	}

	atomic64_set(&req_processed, req);

process:
	lcnt = 0;

	mutex_lock(&l3_offl_llock);
	list_splice_init(&l3_local_lh, &l3lh);
	mutex_unlock(&l3_offl_llock);

	if (rvu_sw_l3_offl_rule_push(&l3lh))
		pr_err("%s: Error to push rules\n", __func__);

	queue_delayed_work(sw_l3_offl_wq, &l3_offl_work, msecs_to_jiffies(100));
}

int rvu_mbox_handler_fib_notify(struct rvu *rvu,
				struct fib_notify_req *req,
				struct msg_rsp *rsp)
{
	struct l3_entry *l3_entry;
	int sz;

	if (!(rvu->rswitch.flags & RVU_SWITCH_FLAG_FW_READY))
		return 0;

	if (req->cnt > 16)
		return -EINVAL;

	sz = req->cnt * sizeof(struct fib_entry);

	l3_entry = kcalloc(1, sizeof(*l3_entry) + sz, GFP_KERNEL);
	if (!l3_entry)
		return -ENOMEM;

	l3_entry->port_id = rvu_sw_port_id(rvu, req->hdr.pcifunc);
	l3_entry->rvu = rvu;
	l3_entry->cnt = req->cnt;
	INIT_LIST_HEAD(&l3_entry->list);
	memcpy(l3_entry->entry, req->entry, sz);

	mutex_lock(&l3_offl_llock);
	list_add_tail(&l3_entry->list, &l3_offl_lh);
	mutex_unlock(&l3_offl_llock);

	if (!l3_offl_work_running) {
		sw_l3_offl_wq = alloc_workqueue("sw_af_fib_wq", 0, 0);
		l3_offl_work_running = true;
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(1000));
	}

	return 0;
}

void rvu_sw_l3_shutdown(void)
{
	struct l3_entry *entry;
	LIST_HEAD(tlist);

	if (!sw_l3_offl_wq)
		return;

	cancel_delayed_work_sync(&l3_offl_work);
	destroy_workqueue(sw_l3_offl_wq);

	mutex_lock(&l3_offl_llock);
	while (1) {
		entry = list_first_entry_or_null(&l3_offl_lh,
						 struct l3_entry, list);
		if (!entry)
			break;

		list_del_init(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&l3_offl_llock);
}
