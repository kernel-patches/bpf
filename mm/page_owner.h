/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/ internal page_owner and page_owner_iter declarations
 */

#ifndef __MM_PAGE_OWNER_H
#define __MM_PAGE_OWNER_H

#include <linux/jump_label.h>
#include <linux/page_ext.h>
#include <linux/sched.h>
#include <linux/stackdepot.h>

/*
 * mm/page_owner.c
 */
DECLARE_STATIC_KEY_FALSE(page_owner_inited);

struct page_owner {
	unsigned short order;
	short last_migrate_reason;
	gfp_t gfp_mask;
	depot_stack_handle_t handle;
	depot_stack_handle_t free_handle;
	u64 ts_nsec;
	u64 free_ts_nsec;
	char comm[TASK_COMM_LEN];
	pid_t pid;
	pid_t tgid;
	pid_t free_pid;
	pid_t free_tgid;
};

/*
 * Cursor and per-page result of page_owner_next_eligible().
 */
struct page_owner_scan {
	/* resume point */
	unsigned long pfn;
	struct page_owner po_snap;
};

bool page_owner_next_eligible(struct page_owner_scan *scan);

/*
 * mm/page_owner_iter.c
 */
int page_owner_iter_register(void);

#endif /* __MM_PAGE_OWNER_H */
