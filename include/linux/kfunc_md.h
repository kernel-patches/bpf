/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFUNC_MD_H
#define _LINUX_KFUNC_MD_H

#include <linux/kernel.h>

struct kfunc_md {
	int users;
	/* we can use this field later, make sure it is 8-bytes aligned
	 * for now.
	 */
	int pad0;
	void *func;
};

extern struct kfunc_md *kfunc_mds;

struct kfunc_md *kfunc_md_find(void *ip);
struct kfunc_md *kfunc_md_get(void *ip);
void kfunc_md_put(struct kfunc_md *meta);
void kfunc_md_put_by_ip(void *ip);
void kfunc_md_lock(void);
void kfunc_md_unlock(void);

#endif
