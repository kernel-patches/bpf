/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFUNC_MD_H
#define _LINUX_KFUNC_MD_H

#define KFUNC_MD_FL_DEAD		(1 << 0) /* the md shouldn't be reused */

#ifndef __ASSEMBLER__

#include <linux/kernel.h>
#include <linux/bpf.h>

struct kfunc_md_array;

struct kfunc_md {
#ifndef CONFIG_FUNCTION_METADATA_PADDING
	/* this is used for the hash table mode */
	struct hlist_node hash;
	/* this is used for table mode */
	struct rcu_head rcu;
#endif
	unsigned long func;
#ifdef CONFIG_FUNCTION_METADATA
	/* the array is used for the fast mode */
	struct kfunc_md_array *array;
#endif
	struct percpu_ref pcref;
	u32 flags;
	u16 users;
	u8 nr_args;
};

struct kfunc_md *kfunc_md_get(unsigned long ip);
struct kfunc_md *kfunc_md_get_noref(unsigned long ip);
struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args);
void kfunc_md_put_entry(struct kfunc_md *meta);
void kfunc_md_put(unsigned long ip);
void kfunc_md_lock(void);
void kfunc_md_unlock(void);
void kfunc_md_exit(struct kfunc_md *md);
void kfunc_md_enter(struct kfunc_md *md);
bool kfunc_md_arch_support(int *insn, int *data);

#endif
#endif
