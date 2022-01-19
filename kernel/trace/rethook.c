// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "rethook: " fmt

#include <linux/bug.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <linux/rethook.h>
#include <linux/slab.h>
#include <linux/sort.h>

/* Return hook list (shadow stack by list) */

/*
 * This function is called from delayed_put_task_struct() when a task is
 * dead and cleaned up to recycle any kretprobe instances associated with
 * this task. These left over instances represent probed functions that
 * have been called but will never return.
 */
void rethook_flush_task(struct task_struct *tk)
{
	struct rethook_node *rhn;
	struct llist_node *node;

	preempt_disable();

	node = __llist_del_all(&tk->rethooks);
	while (node) {
		rhn = container_of(node, struct rethook_node, llist);
		node = node->next;
		rethook_recycle(rhn);
	}

	preempt_enable();
}

static void rethook_free_rcu(struct rcu_head *head)
{
	struct rethook *rh = container_of(head, struct rethook, rcu);
	struct rethook_node *rhn;
	struct freelist_node *node;
	int count = 1;

	node = rh->pool.head;
	while (node) {
		rhn = container_of(node, struct rethook_node, freelist);
		node = node->next;
		kfree(rhn);
		count++;
	}

	/* The rh->ref is the number of pooled node + 1 */
	if (refcount_sub_and_test(count, &rh->ref))
		kfree(rh);
}

/**
 * rethook_free() - Free struct rethook.
 * @rh: the struct rethook to be freed.
 *
 * Free the rethook. Before calling this function, user must ensure the
 * @rh::data is cleaned if needed (or, the handler can access it after
 * calling this function.) This function will set the @rh to be freed
 * after all rethook_node are freed (not soon). And the caller must
 * not touch @rh after calling this.
 */
void rethook_free(struct rethook *rh)
{
	rcu_assign_pointer(rh->handler, NULL);

	call_rcu(&rh->rcu, rethook_free_rcu);
}

/**
 * rethook_alloc() - Allocate struct rethook.
 * @data: a data to pass the @handler when hooking the return.
 * @handler: the return hook callback function.
 *
 * Allocate and initialize a new rethook with @data and @handler.
 * Return NULL if memory allocation fails or @handler is NULL.
 * Note that @handler == NULL means this rethook is going to be freed.
 */
struct rethook *rethook_alloc(void *data, rethook_handler_t handler)
{
	struct rethook *rh = kzalloc(sizeof(struct rethook), GFP_KERNEL);

	if (!rh || !handler)
		return NULL;

	rh->data = data;
	rh->handler = handler;
	rh->pool.head = NULL;
	refcount_set(&rh->ref, 1);

	return rh;
}

/**
 * rethook_add_node() - Add a new node to the rethook.
 * @rh: the struct rethook.
 * @node: the struct rethook_node to be added.
 *
 * Add @node to @rh. User must allocate @node (as a part of user's
 * data structure.) The @node fields are initialized in this function.
 */
void rethook_add_node(struct rethook *rh, struct rethook_node *node)
{
	node->rethook = rh;
	freelist_add(&node->freelist, &rh->pool);
	refcount_inc(&rh->ref);
}

static void free_rethook_node_rcu(struct rcu_head *head)
{
	struct rethook_node *node = container_of(head, struct rethook_node, rcu);

	if (refcount_dec_and_test(&node->rethook->ref))
		kfree(node->rethook);
	kfree(node);
}

/**
 * rethook_recycle() - return the node to rethook.
 * @node: The struct rethook_node to be returned.
 *
 * Return back the @node to @node::rethook. If the @node::rethook is already
 * marked as freed, this will free the @node.
 */
void rethook_recycle(struct rethook_node *node)
{
	lockdep_assert_preemption_disabled();

	if (likely(READ_ONCE(node->rethook->handler)))
		freelist_add(&node->freelist, &node->rethook->pool);
	else
		call_rcu(&node->rcu, free_rethook_node_rcu);
}
NOKPROBE_SYMBOL(rethook_recycle);

/**
 * rethook_try_get() - get an unused rethook node.
 * @rh: The struct rethook which pools the nodes.
 *
 * Get an unused rethook node from @rh. If the node pool is empty, this
 * will return NULL. Caller must disable preemption.
 */
struct rethook_node *rethook_try_get(struct rethook *rh)
{
	rethook_handler_t handler = READ_ONCE(rh->handler);
	struct freelist_node *fn;

	lockdep_assert_preemption_disabled();

	/* Check whether @rh is going to be freed. */
	if (unlikely(!handler))
		return NULL;

	fn = freelist_try_get(&rh->pool);
	if (!fn)
		return NULL;

	return container_of(fn, struct rethook_node, freelist);
}
NOKPROBE_SYMBOL(rethook_try_get);

/**
 * rethook_hook() - Hook the current function return.
 * @node: The struct rethook node to hook the function return.
 * @regs: The struct pt_regs for the function entry.
 *
 * Hook the current running function return. This must be called when the
 * function entry (or at least @regs must be the registers of the function
 * entry.)
 */
void rethook_hook(struct rethook_node *node, struct pt_regs *regs)
{
	arch_rethook_prepare(node, regs);
	__llist_add(&node->llist, &current->rethooks);
}
NOKPROBE_SYMBOL(rethook_hook);

/* This assumes the 'tsk' is the current task or the is not running. */
static unsigned long __rethook_find_ret_addr(struct task_struct *tsk,
					     struct llist_node **cur)
{
	struct rethook_node *rh = NULL;
	struct llist_node *node = *cur;

	if (!node)
		node = tsk->rethooks.first;
	else
		node = node->next;

	while (node) {
		rh = container_of(node, struct rethook_node, llist);
		if (rh->ret_addr != (unsigned long)arch_rethook_trampoline) {
			*cur = node;
			return rh->ret_addr;
		}
		node = node->next;
	}
	return 0;
}
NOKPROBE_SYMBOL(__rethook_find_ret_addr);

/**
 * rethook_find_ret_addr -- Find correct return address modified by rethook
 * @tsk: Target task
 * @frame: A frame pointer
 * @cur: a storage of the loop cursor llist_node pointer for next call
 *
 * Find the correct return address modified by a rethook on @tsk in unsigned
 * long type. If it finds the return address, this returns that address value,
 * or this returns 0.
 * The @tsk must be 'current' or a task which is not running. @frame is a hint
 * to get the currect return address - which is compared with the
 * rethook::frame field. The @cur is a loop cursor for searching the
 * kretprobe return addresses on the @tsk. The '*@cur' should be NULL at the
 * first call, but '@cur' itself must NOT NULL.
 */
unsigned long rethook_find_ret_addr(struct task_struct *tsk, unsigned long frame,
				    struct llist_node **cur)
{
	struct rethook_node *rhn = NULL;
	unsigned long ret;

	if (WARN_ON_ONCE(!cur))
		return 0;

	do {
		ret = __rethook_find_ret_addr(tsk, cur);
		if (!ret)
			break;
		rhn = container_of(*cur, struct rethook_node, llist);
	} while (rhn->frame != frame);

	return ret;
}
NOKPROBE_SYMBOL(rethook_find_ret_addr);

void __weak arch_rethook_fixup_return(struct pt_regs *regs,
				      unsigned long correct_ret_addr)
{
	/*
	 * Do nothing by default. If the architecture which uses a
	 * frame pointer to record real return address on the stack,
	 * it should fill this function to fixup the return address
	 * so that stacktrace works from the rethook handler.
	 */
}

/* This function will be called from each arch-defined trampoline. */
unsigned long rethook_trampoline_handler(struct pt_regs *regs,
					 unsigned long frame)
{
	struct llist_node *first, *node = NULL;
	unsigned long correct_ret_addr;
	rethook_handler_t handler;
	struct rethook_node *rhn;

	correct_ret_addr = __rethook_find_ret_addr(current, &node);
	if (!correct_ret_addr) {
		pr_err("rethook: Return address not found! Maybe there is a bug in the kernel\n");
		BUG_ON(1);
	}

	instruction_pointer_set(regs, correct_ret_addr);
	arch_rethook_fixup_return(regs, correct_ret_addr);

	first = current->rethooks.first;
	current->rethooks.first = node->next;
	node->next = NULL;

	/*
	 * This loop must be protected from rethook_free_rcu() because this is
	 * accessing 'rhn->rethook'.
	 */
	preempt_disable();
	while (first) {
		rhn = container_of(first, struct rethook_node, llist);
		if (WARN_ON_ONCE(rhn->frame != frame))
			break;
		handler = READ_ONCE(rhn->rethook->handler);
		if (handler)
			handler(rhn, rhn->rethook->data, regs);

		first = first->next;
		rethook_recycle(rhn);
	}
	preempt_enable();

	return correct_ret_addr;
}
NOKPROBE_SYMBOL(rethook_trampoline_handler);
