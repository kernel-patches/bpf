/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Return hooking with list-based shadow stack.
 */
#ifndef _LINUX_RETHOOK_H
#define _LINUX_RETHOOK_H

#include <linux/compiler.h>
#include <linux/freelist.h>
#include <linux/llist.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>

struct rethook_node;

typedef void (*rethook_handler_t) (struct rethook_node *, void *, struct pt_regs *);

struct rethook {
	void			*data;
	rethook_handler_t	handler;
	struct freelist_head	pool;
	refcount_t		ref;
	struct rcu_head		rcu;
};

struct rethook_node {
	union {
		struct freelist_node freelist;
		struct rcu_head      rcu;
	};
	struct llist_node	llist;
	struct rethook		*rethook;
	unsigned long		ret_addr;
	unsigned long		frame;
};

int rethook_node_init(struct rethook_node *node);

struct rethook *rethook_alloc(void *data, rethook_handler_t handler);
void rethook_free(struct rethook *rh);
void rethook_add_node(struct rethook *rh, struct rethook_node *node);

struct rethook_node *rethook_try_get(struct rethook *rh);
void rethook_node_recycle(struct rethook_node *node);
void rethook_hook_current(struct rethook_node *node, struct pt_regs *regs);

unsigned long rethook_find_ret_addr(struct task_struct *tsk, unsigned long frame,
				    struct llist_node **cur);

/* Arch dependent code must implement this and trampoline code */
void arch_rethook_prepare(struct rethook_node *node, struct pt_regs *regs);
void arch_rethook_trampoline(void);

static inline bool is_rethook_trampoline(unsigned long addr)
{
	return addr == (unsigned long)arch_rethook_trampoline;
}

/* If the architecture needs a fixup the return address, implement it. */
void arch_rethook_fixup_return(struct pt_regs *regs,
			       unsigned long correct_ret_addr);

/* Generic trampoline handler, arch code must prepare asm stub */
unsigned long rethook_trampoline_handler(struct pt_regs *regs,
					 unsigned long frame);

#ifdef CONFIG_RETHOOK
void rethook_flush_task(struct task_struct *tk);
#else
#define rethook_flush_task(tsk)	do { } while (0)
#endif

#endif

