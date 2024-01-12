// SPDX-License-Identifier: GPL-2.0
/*
 * Infrastructure to took into function calls and returns.
 * Copyright (c) 2008-2009 Frederic Weisbecker <fweisbec@gmail.com>
 * Mostly borrowed from function tracer which
 * is Copyright (c) Steven Rostedt <srostedt@redhat.com>
 *
 * Highly modified by Steven Rostedt (VMware).
 */
#include <linux/bits.h>
#include <linux/jump_label.h>
#include <linux/suspend.h>
#include <linux/ftrace.h>
#include <linux/slab.h>

#include <trace/events/sched.h>

#include "ftrace_internal.h"
#include "trace.h"

#define FGRAPH_RET_SIZE sizeof(struct ftrace_ret_stack)
#define FGRAPH_RET_INDEX (FGRAPH_RET_SIZE / sizeof(long))

/*
 * On entry to a function (via function_graph_enter()), a new ftrace_ret_stack
 * is allocated on the task's ret_stack with indexes entry, then each
 * fgraph_ops on the fgraph_array[]'s entryfunc is called and if that returns
 * non-zero, the index into the fgraph_array[] for that fgraph_ops is recorded
 * on the indexes entry as a bit flag.
 * As the associated ftrace_ret_stack saved for those fgraph_ops needs to
 * be found, the index to it is also added to the ret_stack along with the
 * index of the fgraph_array[] to each fgraph_ops that needs their retfunc
 * called.
 *
 * The top of the ret_stack (when not empty) will always have a reference
 * to the last ftrace_ret_stack saved. All references to the
 * ftrace_ret_stack has the format of:
 *
 * bits:  0 -  9	offset in words from the previous ftrace_ret_stack
 *			(bitmap type should have FGRAPH_RET_INDEX always)
 * bits: 10 - 11	Type of storage
 *			  0 - reserved
 *			  1 - bitmap of fgraph_array index
 *			  2 - reserved data
 *
 * For bitmap of fgraph_array index
 *  bits: 12 - 27	The bitmap of fgraph_ops fgraph_array index
 *
 * For reserved data:
 *  bits: 12 - 17	The size in words that is stored
 *  bits: 18 - 23	The index of fgraph_array, which shows who is stored
 *
 * That is, at the end of function_graph_enter, if the first and forth
 * fgraph_ops on the fgraph_array[] (index 0 and 3) needs their retfunc called
 * on the return of the function being traced, and the forth fgraph_ops
 * stored two words of data, this is what will be on the task's shadow
 * ret_stack: (the stack grows upward)
 *
 * |                                            | <- task->curr_ret_stack
 * +--------------------------------------------+
 * | data_type(idx:3, size:2,                   |
 * |           offset:FGRAPH_RET_INDEX+3)       | ( Data with size of 2 words)
 * +--------------------------------------------+ ( It is 4 words from the ret_stack)
 * |            STORED DATA WORD 2              |
 * |            STORED DATA WORD 1              |
 * +------i-------------------------------------+
 * | bitmap_type(bitmap:(BIT(3)|BIT(0)),        |
 * |             offset:FGRAPH_RET_INDEX)       | <- the offset is from here
 * +--------------------------------------------+
 * | struct ftrace_ret_stack                    |
 * |   (stores the saved ret pointer)           | <- the offset points here
 * +--------------------------------------------+
 * |                 (X) | (N)                  | ( N words away from
 * |                                            |   previous ret_stack)
 *
 * If a backtrace is required, and the real return pointer needs to be
 * fetched, then it looks at the task's curr_ret_stack index, if it
 * is greater than zero (reserved, or right before poped), it would mask
 * the value by FGRAPH_RET_INDEX_MASK to get the offset index of the
 * ftrace_ret_stack structure stored on the shadow stack.
 */

#define FGRAPH_RET_INDEX_SIZE	10
#define FGRAPH_RET_INDEX_MASK	GENMASK(FGRAPH_RET_INDEX_SIZE - 1, 0)

#define FGRAPH_TYPE_SIZE	2
#define FGRAPH_TYPE_MASK	GENMASK(FGRAPH_TYPE_SIZE - 1, 0)
#define FGRAPH_TYPE_SHIFT	FGRAPH_RET_INDEX_SIZE

enum {
	FGRAPH_TYPE_RESERVED	= 0,
	FGRAPH_TYPE_BITMAP	= 1,
	FGRAPH_TYPE_DATA	= 2,
};

#define FGRAPH_INDEX_SIZE	16
#define FGRAPH_INDEX_MASK	GENMASK(FGRAPH_INDEX_SIZE - 1, 0)
#define FGRAPH_INDEX_SHIFT	(FGRAPH_TYPE_SHIFT + FGRAPH_TYPE_SIZE)

#define FGRAPH_DATA_SIZE	5
#define FGRAPH_DATA_MASK	((1 << FGRAPH_DATA_SIZE) - 1)
#define FGRAPH_DATA_SHIFT	(FGRAPH_TYPE_SHIFT + FGRAPH_TYPE_SIZE)

#define FGRAPH_DATA_INDEX_SIZE	4
#define FGRAPH_DATA_INDEX_MASK	((1 << FGRAPH_DATA_INDEX_SIZE) - 1)
#define FGRAPH_DATA_INDEX_SHIFT	(FGRAPH_DATA_SHIFT + FGRAPH_DATA_SIZE)

#define FGRAPH_MAX_INDEX	\
	((FGRAPH_INDEX_SIZE << FGRAPH_DATA_SIZE) + FGRAPH_RET_INDEX)

#define FGRAPH_ARRAY_SIZE	FGRAPH_INDEX_SIZE

#define SHADOW_STACK_SIZE (PAGE_SIZE)
#define SHADOW_STACK_INDEX (SHADOW_STACK_SIZE / sizeof(long))
/* Leave on a buffer at the end */
#define SHADOW_STACK_MAX_INDEX				\
	(SHADOW_STACK_INDEX - (FGRAPH_RET_INDEX + 1 + FGRAPH_ARRAY_SIZE))

#define RET_STACK(t, index) ((struct ftrace_ret_stack *)(&(t)->ret_stack[index]))

#define FGRAPH_MAX_DATA_SIZE (sizeof(long) * (1 << FGRAPH_DATA_SIZE))

/*
 * Each fgraph_ops has a reservered unsigned long at the end (top) of the
 * ret_stack to store task specific state.
 */
#define SHADOW_STACK_TASK_VARS(ret_stack) \
	((unsigned long *)(&(ret_stack)[SHADOW_STACK_INDEX - FGRAPH_ARRAY_SIZE]))

DEFINE_STATIC_KEY_FALSE(kill_ftrace_graph);
int ftrace_graph_active;

static struct fgraph_ops *fgraph_array[FGRAPH_ARRAY_SIZE];

/* LRU index table for fgraph_array */
static int fgraph_lru_table[FGRAPH_ARRAY_SIZE];
static int fgraph_lru_next;
static int fgraph_lru_last;

static void fgraph_lru_init(void)
{
	int i;

	for (i = 0; i < FGRAPH_ARRAY_SIZE; i++)
		fgraph_lru_table[i] = i;
}

static int fgraph_lru_release_index(int idx)
{
	if (idx < 0 || idx >= FGRAPH_ARRAY_SIZE ||
	    fgraph_lru_table[fgraph_lru_last] != -1)
		return -1;

	fgraph_lru_table[fgraph_lru_last] = idx;
	fgraph_lru_last = (fgraph_lru_last + 1) % FGRAPH_ARRAY_SIZE;
	return 0;
}

static int fgraph_lru_alloc_index(void)
{
	int idx = fgraph_lru_table[fgraph_lru_next];

	if (idx == -1)
		return -1;

	fgraph_lru_table[fgraph_lru_next] = -1;
	fgraph_lru_next = (fgraph_lru_next + 1) % FGRAPH_ARRAY_SIZE;
	return idx;
}

static inline int __get_index(unsigned long val)
{
	return val & FGRAPH_RET_INDEX_MASK;
}

static inline int __get_type(unsigned long val)
{
	return (val >> FGRAPH_TYPE_SHIFT) & FGRAPH_TYPE_MASK;
}

static inline int __get_data_index(unsigned long val)
{
	return (val >> FGRAPH_DATA_INDEX_SHIFT) & FGRAPH_DATA_INDEX_MASK;
}

static inline int __get_data_size(unsigned long val)
{
	return (val >> FGRAPH_DATA_SHIFT) & FGRAPH_DATA_MASK;
}

static inline unsigned long get_fgraph_entry(struct task_struct *t, int index)
{
	return t->ret_stack[index];
}

static inline int get_ret_stack_index(struct task_struct *t, int offset)
{
	return __get_index(t->ret_stack[offset]);
}

static inline int get_fgraph_type(struct task_struct *t, int offset)
{
	return __get_type(t->ret_stack[offset]);
}

static inline unsigned long
get_fgraph_index_bitmap(struct task_struct *t, int offset)
{
	return (t->ret_stack[offset] >> FGRAPH_INDEX_SHIFT) & FGRAPH_INDEX_MASK;
}

static inline void
set_fgraph_index_bitmap(struct task_struct *t, int offset, unsigned long bitmap)
{
	t->ret_stack[offset] = (bitmap << FGRAPH_INDEX_SHIFT) |
		(FGRAPH_TYPE_BITMAP << FGRAPH_TYPE_SHIFT) | FGRAPH_RET_INDEX;
}

static inline bool is_fgraph_index_set(struct task_struct *t, int offset, int idx)
{
	return !!(get_fgraph_index_bitmap(t, offset) & BIT(idx));
}

static inline void
add_fgraph_index_bitmap(struct task_struct *t, int offset, unsigned long bitmap)
{
	t->ret_stack[offset] |= (bitmap << FGRAPH_INDEX_SHIFT);
}

static inline void *get_fgraph_data(struct task_struct *t, int index)
{
	unsigned long val = t->ret_stack[index];

	if (__get_type(val) != FGRAPH_TYPE_DATA)
		return NULL;
	index -= __get_data_size(val);
	return (void *)&t->ret_stack[index];
}

static inline unsigned long make_fgraph_data(int idx, int size, int offset)
{
	return (idx << FGRAPH_DATA_INDEX_SHIFT) | (size << FGRAPH_DATA_SHIFT) |
		(FGRAPH_TYPE_DATA << FGRAPH_TYPE_SHIFT) | offset;
}

/* ftrace_graph_entry set to this to tell some archs to run function graph */
static int entry_run(struct ftrace_graph_ent *trace, struct fgraph_ops *ops)
{
	return 0;
}

/* ftrace_graph_return set to this to tell some archs to run function graph */
static void return_run(struct ftrace_graph_ret *trace, struct fgraph_ops *ops)
{
}

static void ret_stack_set_task_var(struct task_struct *t, int idx, long val)
{
	unsigned long *gvals = SHADOW_STACK_TASK_VARS(t->ret_stack);

	gvals[idx] = val;
}

static unsigned long *
ret_stack_get_task_var(struct task_struct *t, int idx)
{
	unsigned long *gvals = SHADOW_STACK_TASK_VARS(t->ret_stack);

	return &gvals[idx];
}

static void ret_stack_init_task_vars(unsigned long *ret_stack)
{
	unsigned long *gvals = SHADOW_STACK_TASK_VARS(ret_stack);

	memset(gvals, 0, sizeof(*gvals) * FGRAPH_ARRAY_SIZE);
}

/**
 * fgraph_reserve_data - Reserve storage on the task's ret_stack
 * @idx:	The index of fgraph_array
 * @size_bytes: The size in bytes to reserve
 *
 * Reserves space of up to FGRAPH_MAX_DATA_SIZE bytes on the
 * task's ret_stack shadow stack, for a given fgraph_ops during
 * the entryfunc() call. If entryfunc() returns zero, the storage
 * is discarded. An entryfunc() can only call this once per iteration.
 * The fgraph_ops retfunc() can retrieve this stored data with
 * fgraph_retrieve_data().
 *
 * Returns: On success, a pointer to the data on the stack.
 *   Otherwise, NULL if there's not enough space left on the
 *   ret_stack for the data, or if fgraph_reserve_data() was called
 *   more than once for a single entryfunc() call.
 */
void *fgraph_reserve_data(int idx, int size_bytes)
{
	unsigned long val;
	void *data;
	int curr_ret_stack = current->curr_ret_stack;
	int rsrv_ret_stack = current->rsrv_ret_stack;
	int data_size;

	if (size_bytes > FGRAPH_MAX_DATA_SIZE)
		return NULL;

	/*
	 * Since this API is used after pushing ret_stack, curr_ret_stack
	 * should be synchronized with rsrv_ret_stack.
	 */
	if (WARN_ON_ONCE(curr_ret_stack != rsrv_ret_stack))
		return NULL;

	/* Convert to number of longs + data word */
	data_size = DIV_ROUND_UP(size_bytes, sizeof(long));

	val = get_fgraph_entry(current, curr_ret_stack - 1);
	data = &current->ret_stack[curr_ret_stack];

	rsrv_ret_stack += data_size + 1;
	if (unlikely(rsrv_ret_stack >= SHADOW_STACK_MAX_INDEX))
		return NULL;

	val = make_fgraph_data(idx, data_size, __get_index(val) + data_size + 1);

	/* Extend the reserved-ret_stack at first */
	current->rsrv_ret_stack = rsrv_ret_stack;
	/* And sync with interrupts, to see the new rsrv_ret_stack */
	barrier();
	/*
	 * The same reason as the push, this entry must be here before updating
	 * the curr_ret_stack. But any interrupt comes before updating
	 * curr_ret_stack, it may commit it with different reserve entry.
	 * Thus we need to write the data entry after update the curr_ret_stack
	 * again. And these operations must be ordered.
	 */
	current->ret_stack[rsrv_ret_stack - 1] = val;
	barrier();
	current->curr_ret_stack = rsrv_ret_stack;
	barrier();
	current->ret_stack[rsrv_ret_stack - 1] = val;

	return data;
}

/**
 * fgraph_retrieve_data - Retrieve stored data from fgraph_reserve_data()
 * @idx:	the index of fgraph_array (fgraph_ops::idx)
 * @size_bytes: pointer to retrieved data size.
 *
 * This is to be called by a fgraph_ops retfunc(), to retrieve data that
 * was stored by the fgraph_ops entryfunc() on the function entry.
 * That is, this will retrieve the data that was reserved on the
 * entry of the function that corresponds to the exit of the function
 * that the fgraph_ops retfunc() is called on.
 *
 * Returns: The stored data from fgraph_reserve_data() called by the
 *    matching entryfunc() for the retfunc() this is called from.
 *   Or NULL if there was nothing stored.
 */
void *fgraph_retrieve_data(int idx, int *size_bytes)
{
	int index = current->curr_ret_stack - 1;
	unsigned long val;

	val = get_fgraph_entry(current, index);
	while (__get_type(val) == FGRAPH_TYPE_DATA) {
		if (__get_data_index(val) == idx)
			goto found;
		index -= __get_data_size(val) + 1;
		val = get_fgraph_entry(current, index);
	}
	return NULL;
found:
	if (size_bytes)
		*size_bytes = __get_data_size(val) *
			      sizeof(long);
	return get_fgraph_data(current, index);
}

/**
 * fgraph_get_task_var - retrieve a task specific state variable
 * @gops: The ftrace_ops that owns the task specific variable
 *
 * Every registered fgraph_ops has a task state variable
 * reserved on the task's ret_stack. This function returns the
 * address to that variable.
 *
 * Returns the address to the fgraph_ops @gops tasks specific
 * unsigned long variable.
 */
unsigned long *fgraph_get_task_var(struct fgraph_ops *gops)
{
	return ret_stack_get_task_var(current, gops->idx);
}

/*
 * @offset: The index into @t->ret_stack to find the ret_stack entry
 * @index: Where to place the index into @t->ret_stack of that entry
 *
 * Calling this with:
 *
 *   offset = task->curr_ret_stack;
 *   do {
 *	ret_stack = get_ret_stack(task, offset, &offset);
 *   } while (ret_stack);
 *
 * Will iterate through all the ret_stack entries from curr_ret_stack
 * down to the first one.
 */
static inline struct ftrace_ret_stack *
get_ret_stack(struct task_struct *t, int offset, int *index)
{
	int idx;

	BUILD_BUG_ON(FGRAPH_RET_SIZE % sizeof(long));

	if (unlikely(offset <= 0))
		return NULL;

	idx = get_ret_stack_index(t, --offset);
	/*
	 * This can happen if an interrupt comes just before the first push
	 * increments the curr_ret_stack, and that interrupt pushes another
	 * entry. In that case, the frist push is forcibly committed with a
	 * reserved entry which points -1 stack index.
	 */
	if (unlikely(idx > offset))
		return NULL;

	if (WARN_ON_ONCE(idx <= 0))
		return NULL;

	offset -= idx;

	*index = offset;
	return RET_STACK(t, offset);
}

/* Both enabled by default (can be cleared by function_graph tracer flags */
static bool fgraph_sleep_time = true;

#ifdef CONFIG_DYNAMIC_FTRACE
/*
 * archs can override this function if they must do something
 * to enable hook for graph tracer.
 */
int __weak ftrace_enable_ftrace_graph_caller(void)
{
	return 0;
}

/*
 * archs can override this function if they must do something
 * to disable hook for graph tracer.
 */
int __weak ftrace_disable_ftrace_graph_caller(void)
{
	return 0;
}
#endif

int ftrace_graph_entry_stub(struct ftrace_graph_ent *trace,
			    struct fgraph_ops *gops)
{
	return 0;
}

static void ftrace_graph_ret_stub(struct ftrace_graph_ret *trace,
				  struct fgraph_ops *gops)
{
}

static struct fgraph_ops fgraph_stub = {
	.entryfunc = ftrace_graph_entry_stub,
	.retfunc = ftrace_graph_ret_stub,
};

/**
 * ftrace_graph_stop - set to permanently disable function graph tracing
 *
 * In case of an error int function graph tracing, this is called
 * to try to keep function graph tracing from causing any more harm.
 * Usually this is pretty severe and this is called to try to at least
 * get a warning out to the user.
 */
void ftrace_graph_stop(void)
{
	static_branch_enable(&kill_ftrace_graph);
}

/* Add a function return address to the trace stack on thread info.*/
static int
ftrace_push_return_trace(unsigned long ret, unsigned long func,
			 unsigned long frame_pointer, unsigned long *retp,
			 int fgraph_idx)
{
	struct ftrace_ret_stack *ret_stack;
	unsigned long long calltime;
	unsigned long val;
	int index, rindex;

	if (unlikely(ftrace_graph_is_dead()))
		return -EBUSY;

	if (!current->ret_stack)
		return -EBUSY;

	index = READ_ONCE(current->curr_ret_stack);
	rindex = READ_ONCE(current->rsrv_ret_stack);
	if (unlikely(index != rindex)) {
		/*
		 * This interrupts the push operation. Commit previous push
		 * temporarily with reserved entry.
		 */
		if (unlikely(index <= 0))
			/* This will make ret_stack[index - 1] points -1 */
			val = rindex - index;
		else
			val = get_ret_stack_index(current, index - 1) +
			      rindex - index;
		current->ret_stack[rindex - 1] = val;
		/* Forcibly commit it */
		current->curr_ret_stack = index = rindex;
	} else {
		/*
		 * Check whether the previous fgraph callback is pushed by the fgraph
		 * on the same function entry.
		 * But if @func is the self tail-call function, we also need to ensure
		 * the ret_stack is not for the previous call by checking whether the
		 * bit of @fgraph_idx is set or not.
		 */
		ret_stack = get_ret_stack(current, index, &index);
		if (ret_stack && ret_stack->func == func &&
		    get_fgraph_type(current, index + FGRAPH_RET_INDEX) == FGRAPH_TYPE_BITMAP &&
		    !is_fgraph_index_set(current, index + FGRAPH_RET_INDEX, fgraph_idx))
			return index + FGRAPH_RET_INDEX;
		/* Since get_ret_stack() overwrites 'index', recover it. */
		index = rindex;
	}

	val = (FGRAPH_TYPE_RESERVED << FGRAPH_TYPE_SHIFT) | FGRAPH_RET_INDEX;

	BUILD_BUG_ON(SHADOW_STACK_SIZE % sizeof(long));

	/*
	 * We must make sure the ret_stack is tested before we read
	 * anything else.
	 */
	smp_rmb();

	/* The return trace stack is full */
	if (current->curr_ret_stack + FGRAPH_RET_INDEX >= SHADOW_STACK_MAX_INDEX) {
		atomic_inc(&current->trace_overrun);
		return -EBUSY;
	}

	calltime = trace_clock_local();

	ret_stack = RET_STACK(current, index);
	index += FGRAPH_RET_INDEX;

	/*
	 * At first, reserve the ret_stack. Beyond this point, any interrupt
	 * will only overwrite ret_stack[index] by a reserved entry which points
	 * the previous ret_stack or -1.
	 */
	current->rsrv_ret_stack = index + 1;
	/* And ensure that the following happens after reserved */
	barrier();

	current->ret_stack[index] = val;
	ret_stack->ret = ret;
	/*
	 * The unwinders expect curr_ret_stack to point to either zero
	 * or an index where to find the next ret_stack which has actual ret
	 * address. Thus we want to write the ret and the index to find the
	 * ret_stack before we increment the curr_ret_stack.
	 */
	barrier();
	current->curr_ret_stack = index + 1;
	/*
	 * There are two possibilities here.
	 * - More than one interrupts push/pop their entry between update
	 *   rsrv_ret_stack and curr_ret_stack. In this case, curr_ret_stack
	 *   is already equal to the rsrv_ret_stack and
	 *   current->ret_stack[index] is overwritten by reserved entry which
	 *   points the previous ret_stack. But ret_stack->ret is not.
	 * - Or, no interrupts push/pop. So current->ret_stack[index] keeps
	 *   its value.
	 * This next barrier is to ensure that an interrupt coming in
	 * will not overwrite what we are about to write anymore.
	 */
	barrier();

	/* Rewrite the entry again in case it was overwritten. */
	current->ret_stack[index] = val;

	ret_stack->func = func;
	ret_stack->calltime = calltime;
#ifdef HAVE_FUNCTION_GRAPH_FP_TEST
	ret_stack->fp = frame_pointer;
#endif
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
	ret_stack->retp = retp;
#endif
	return index;
}

/*
 * Not all archs define MCOUNT_INSN_SIZE which is used to look for direct
 * functions. But those archs currently don't support direct functions
 * anyway, and ftrace_find_rec_direct() is just a stub for them.
 * Define MCOUNT_INSN_SIZE to keep those archs compiling.
 */
#ifndef MCOUNT_INSN_SIZE
/* Make sure this only works without direct calls */
# ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
#  error MCOUNT_INSN_SIZE not defined with direct calls enabled
# endif
# define MCOUNT_INSN_SIZE 0
#endif

/* If the caller does not use ftrace, call this function. */
int function_graph_enter(unsigned long ret, unsigned long func,
			 unsigned long frame_pointer, unsigned long *retp)
{
	struct ftrace_graph_ent trace;
	unsigned long bitmap = 0;
	int index;
	int i;

#ifndef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
	/*
	 * Skip graph tracing if the return location is served by direct trampoline,
	 * since call sequence and return addresses are unpredictable anyway.
	 * Ex: BPF trampoline may call original function and may skip frame
	 * depending on type of BPF programs attached.
	 */
	if (ftrace_direct_func_count &&
	    ftrace_find_rec_direct(ret - MCOUNT_INSN_SIZE))
		return -EBUSY;
#endif

	trace.func = func;
	trace.depth = ++current->curr_ret_depth;

	index = ftrace_push_return_trace(ret, func, frame_pointer, retp, 0);
	if (index < 0)
		goto out;

	for (i = 0; i < FGRAPH_ARRAY_SIZE; i++) {
		struct fgraph_ops *gops = fgraph_array[i];
		int save_curr_ret_stack;

		if (gops == &fgraph_stub)
			continue;

		save_curr_ret_stack = current->curr_ret_stack;
		if (ftrace_ops_test(&gops->ops, func, NULL) &&
		    gops->entryfunc(&trace, gops))
			bitmap |= BIT(i);
		else
			/* Clear out any saved storage */
			current->curr_ret_stack = save_curr_ret_stack;
	}

	if (!bitmap)
		goto out_ret;

	/*
	 * Since this function uses fgraph_idx = 0 as a tail-call checking
	 * flag, set that bit always.
	 */
	set_fgraph_index_bitmap(current, index, bitmap | BIT(0));

	return 0;
 out_ret:
	current->curr_ret_stack -= FGRAPH_RET_INDEX + 1;
	current->rsrv_ret_stack = current->curr_ret_stack;
 out:
	current->curr_ret_depth--;
	return -EBUSY;
}

/* This is called from ftrace_graph_func() via ftrace */
int function_graph_enter_ops(unsigned long ret, unsigned long func,
			     unsigned long frame_pointer, unsigned long *retp,
			     struct fgraph_ops *gops)
{
	struct ftrace_graph_ent trace;
	int save_curr_ret_stack;
	int index;
	int type;

	/* Check whether the fgraph_ops is unregistered. */
	if (unlikely(fgraph_array[gops->idx] == &fgraph_stub))
		return -ENODEV;

	/* Use start for the distance to ret_stack (skipping over reserve) */
	index = ftrace_push_return_trace(ret, func, frame_pointer, retp, gops->idx);
	if (index < 0)
		return index;
	type = get_fgraph_type(current, index);

	/* This is the first ret_stack for this fentry */
	if (type == FGRAPH_TYPE_RESERVED)
		++current->curr_ret_depth;

	trace.func = func;
	trace.depth = current->curr_ret_depth;
	save_curr_ret_stack = current->curr_ret_stack;
	if (gops->entryfunc(&trace, gops)) {
		if (type == FGRAPH_TYPE_RESERVED)
			set_fgraph_index_bitmap(current, index, BIT(gops->idx));
		else
			add_fgraph_index_bitmap(current, index, BIT(gops->idx));
		return 0;
	} else
		current->curr_ret_stack = save_curr_ret_stack;

	if (type == FGRAPH_TYPE_RESERVED) {
		current->curr_ret_stack -= FGRAPH_RET_INDEX + 1;
		current->rsrv_ret_stack = current->curr_ret_stack;
		current->curr_ret_depth--;
	}
	return -EBUSY;
}

/* Retrieve a function return address to the trace stack on thread info.*/
static struct ftrace_ret_stack *
ftrace_pop_return_trace(struct ftrace_graph_ret *trace, unsigned long *ret,
			unsigned long frame_pointer, int *index)
{
	struct ftrace_ret_stack *ret_stack;

	ret_stack = get_ret_stack(current, current->curr_ret_stack, index);

	if (unlikely(!ret_stack)) {
		ftrace_graph_stop();
		WARN(1, "Bad function graph ret_stack pointer: %d",
		     current->curr_ret_stack);
		/* Might as well panic, otherwise we have no where to go */
		*ret = (unsigned long)panic;
		return NULL;
	}

#ifdef HAVE_FUNCTION_GRAPH_FP_TEST
	/*
	 * The arch may choose to record the frame pointer used
	 * and check it here to make sure that it is what we expect it
	 * to be. If gcc does not set the place holder of the return
	 * address in the frame pointer, and does a copy instead, then
	 * the function graph trace will fail. This test detects this
	 * case.
	 *
	 * Currently, x86_32 with optimize for size (-Os) makes the latest
	 * gcc do the above.
	 *
	 * Note, -mfentry does not use frame pointers, and this test
	 *  is not needed if CC_USING_FENTRY is set.
	 */
	if (unlikely(ret_stack->fp != frame_pointer)) {
		ftrace_graph_stop();
		WARN(1, "Bad frame pointer: expected %lx, received %lx\n"
		     "  from func %ps return to %lx\n",
		     ret_stack->fp,
		     frame_pointer,
		     (void *)ret_stack->func,
		     ret_stack->ret);
		*ret = (unsigned long)panic;
		return NULL;
	}
#endif

	*index += FGRAPH_RET_INDEX;
	*ret = ret_stack->ret;
	trace->func = ret_stack->func;
	trace->calltime = ret_stack->calltime;
	trace->overrun = atomic_read(&current->trace_overrun);
	trace->depth = current->curr_ret_depth;
	/*
	 * We still want to trace interrupts coming in if
	 * max_depth is set to 1. Make sure the decrement is
	 * seen before ftrace_graph_return.
	 */
	barrier();

	return ret_stack;
}

/*
 * Hibernation protection.
 * The state of the current task is too much unstable during
 * suspend/restore to disk. We want to protect against that.
 */
static int
ftrace_suspend_notifier_call(struct notifier_block *bl, unsigned long state,
							void *unused)
{
	switch (state) {
	case PM_HIBERNATION_PREPARE:
		pause_graph_tracing();
		break;

	case PM_POST_HIBERNATION:
		unpause_graph_tracing();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block ftrace_suspend_notifier = {
	.notifier_call = ftrace_suspend_notifier_call,
};

/* fgraph_ret_regs is not defined without CONFIG_FUNCTION_GRAPH_RETVAL */
struct fgraph_ret_regs;

/*
 * Send the trace to the ring-buffer.
 * @return the original return address.
 */
static unsigned long __ftrace_return_to_handler(struct fgraph_ret_regs *ret_regs,
						unsigned long frame_pointer)
{
	struct ftrace_ret_stack *ret_stack;
	struct ftrace_graph_ret trace;
	unsigned long bitmap;
	unsigned long ret;
	int index;
	int i;

	ret_stack = ftrace_pop_return_trace(&trace, &ret, frame_pointer, &index);

	if (unlikely(!ret_stack)) {
		ftrace_graph_stop();
		WARN_ON(1);
		/* Might as well panic. What else to do? */
		return (unsigned long)panic;
	}

	trace.rettime = trace_clock_local();
#ifdef CONFIG_FUNCTION_GRAPH_RETVAL
	trace.retval = fgraph_ret_regs_return_value(ret_regs);
#endif

	bitmap = get_fgraph_index_bitmap(current, index);
	for (i = 0; i < FGRAPH_ARRAY_SIZE; i++) {
		struct fgraph_ops *gops = fgraph_array[i];

		if (!(bitmap & BIT(i)))
			continue;
		if (gops == &fgraph_stub)
			continue;

		gops->retfunc(&trace, gops);
	}

	/*
	 * The ftrace_graph_return() may still access the current
	 * ret_stack structure, we need to make sure the update of
	 * curr_ret_stack is after that.
	 */
	barrier();
	current->curr_ret_stack = index - FGRAPH_RET_INDEX;
	current->rsrv_ret_stack = current->curr_ret_stack;

	current->curr_ret_depth--;
	return ret;
}

/*
 * After all architecures have selected HAVE_FUNCTION_GRAPH_RETVAL, we can
 * leave only ftrace_return_to_handler(ret_regs).
 */
#ifdef CONFIG_HAVE_FUNCTION_GRAPH_RETVAL
unsigned long ftrace_return_to_handler(struct fgraph_ret_regs *ret_regs)
{
	return __ftrace_return_to_handler(ret_regs,
				fgraph_ret_regs_frame_pointer(ret_regs));
}
#else
unsigned long ftrace_return_to_handler(unsigned long frame_pointer)
{
	return __ftrace_return_to_handler(NULL, frame_pointer);
}
#endif

/**
 * ftrace_graph_get_ret_stack - return the entry of the shadow stack
 * @task: The task to read the shadow stack from
 * @idx: Index down the shadow stack
 *
 * Return the ret_struct on the shadow stack of the @task at the
 * call graph at @idx starting with zero. If @idx is zero, it
 * will return the last saved ret_stack entry. If it is greater than
 * zero, it will return the corresponding ret_stack for the depth
 * of saved return addresses.
 */
struct ftrace_ret_stack *
ftrace_graph_get_ret_stack(struct task_struct *task, int idx)
{
	struct ftrace_ret_stack *ret_stack = NULL;
	int index = task->curr_ret_stack;

	if (index < 0)
		return NULL;

	do {
		ret_stack = get_ret_stack(task, index, &index);
	} while (ret_stack && --idx >= 0);

	return ret_stack;
}

/**
 * ftrace_graph_ret_addr - convert a potentially modified stack return address
 *			   to its original value
 *
 * This function can be called by stack unwinding code to convert a found stack
 * return address ('ret') to its original value, in case the function graph
 * tracer has modified it to be 'return_to_handler'.  If the address hasn't
 * been modified, the unchanged value of 'ret' is returned.
 *
 * 'idx' is a state variable which should be initialized by the caller to zero
 * before the first call.
 *
 * 'retp' is a pointer to the return address on the stack.  It's ignored if
 * the arch doesn't have HAVE_FUNCTION_GRAPH_RET_ADDR_PTR defined.
 */
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
unsigned long ftrace_graph_ret_addr(struct task_struct *task, int *idx,
				    unsigned long ret, unsigned long *retp)
{
	struct ftrace_ret_stack *ret_stack;
	int i = task->curr_ret_stack;

	if (ret != (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
		return ret;

	while (i > 0) {
		ret_stack = get_ret_stack(current, i, &i);
		if (!ret_stack)
			break;
		/*
		 * For the tail-call, there would be 2 or more ftrace_ret_stacks on
		 * the ret_stack, which records "return_to_handler" as the return
		 * address excpt for the last one.
		 * But on the real stack, there should be 1 entry because tail-call
		 * reuses the return address on the stack and jump to the next function.
		 * Thus we will continue to find real return address.
		 */
		if (ret_stack->retp == retp &&
		    ret_stack->ret !=
		    (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
			return ret_stack->ret;
	}

	return ret;
}
#else /* !HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */
unsigned long ftrace_graph_ret_addr(struct task_struct *task, int *idx,
				    unsigned long ret, unsigned long *retp)
{
	struct ftrace_ret_stack *ret_stack;
	int task_idx = task->curr_ret_stack;
	int i;

	if (ret != (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
		return ret;

	if (!idx)
		return ret;

	i = *idx;
	do {
		ret_stack = get_ret_stack(task, task_idx, &task_idx);
		if (ret_stack && ret_stack->ret ==
		    (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
			continue;
		i--;
	} while (i >= 0 && ret_stack);

	if (ret_stack)
		return ret_stack->ret;

	return ret;
}
#endif /* HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */

void fgraph_init_ops(struct ftrace_ops *dst_ops,
		     struct ftrace_ops *src_ops)
{
	dst_ops->func = ftrace_graph_func;
	dst_ops->flags = FTRACE_OPS_FL_PID | FTRACE_OPS_GRAPH_STUB;

#ifdef FTRACE_GRAPH_TRAMP_ADDR
	dst_ops->trampoline = FTRACE_GRAPH_TRAMP_ADDR;
	/* trampoline_size is only needed for dynamically allocated tramps */
#endif

#ifdef CONFIG_DYNAMIC_FTRACE
	if (src_ops) {
		dst_ops->func_hash = &src_ops->local_hash;
		mutex_init(&dst_ops->local_hash.regex_lock);
		dst_ops->flags |= FTRACE_OPS_FL_INITIALIZED;
	}
#endif
}

void ftrace_graph_sleep_time_control(bool enable)
{
	fgraph_sleep_time = enable;
}

/*
 * Simply points to ftrace_stub, but with the proper protocol.
 * Defined by the linker script in linux/vmlinux.lds.h
 */
void ftrace_stub_graph(struct ftrace_graph_ret *trace, struct fgraph_ops *gops);

/* The callbacks that hook a function */
trace_func_graph_ret_t ftrace_graph_return = ftrace_stub_graph;
trace_func_graph_ent_t ftrace_graph_entry = ftrace_graph_entry_stub;

/* Try to assign a return stack array on FTRACE_RETSTACK_ALLOC_SIZE tasks. */
static int alloc_retstack_tasklist(unsigned long **ret_stack_list)
{
	int i;
	int ret = 0;
	int start = 0, end = FTRACE_RETSTACK_ALLOC_SIZE;
	struct task_struct *g, *t;

	for (i = 0; i < FTRACE_RETSTACK_ALLOC_SIZE; i++) {
		ret_stack_list[i] = kmalloc(SHADOW_STACK_SIZE, GFP_KERNEL);
		if (!ret_stack_list[i]) {
			start = 0;
			end = i;
			ret = -ENOMEM;
			goto free;
		}
	}

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (start == end) {
			ret = -EAGAIN;
			goto unlock;
		}

		if (t->ret_stack == NULL) {
			atomic_set(&t->trace_overrun, 0);
			ret_stack_init_task_vars(ret_stack_list[start]);
			t->curr_ret_stack = 0;
			t->rsrv_ret_stack = 0;
			t->curr_ret_depth = -1;
			/* Make sure the tasks see the 0 first: */
			smp_wmb();
			t->ret_stack = ret_stack_list[start++];
		}
	}

unlock:
	rcu_read_unlock();
free:
	for (i = start; i < end; i++)
		kfree(ret_stack_list[i]);
	return ret;
}

static void
ftrace_graph_probe_sched_switch(void *ignore, bool preempt,
				struct task_struct *prev,
				struct task_struct *next,
				unsigned int prev_state)
{
	struct ftrace_ret_stack *ret_stack;
	unsigned long long timestamp;
	int index;

	/*
	 * Does the user want to count the time a function was asleep.
	 * If so, do not update the time stamps.
	 */
	if (fgraph_sleep_time)
		return;

	timestamp = trace_clock_local();

	prev->ftrace_timestamp = timestamp;

	/* only process tasks that we timestamped */
	if (!next->ftrace_timestamp)
		return;

	/*
	 * Update all the counters in next to make up for the
	 * time next was sleeping.
	 */
	timestamp -= next->ftrace_timestamp;

	for (index = next->curr_ret_stack; index > 0; ) {
		ret_stack = get_ret_stack(next, index, &index);
		if (ret_stack)
			ret_stack->calltime += timestamp;
	}
}

static DEFINE_PER_CPU(unsigned long *, idle_ret_stack);

static void
graph_init_task(struct task_struct *t, unsigned long *ret_stack)
{
	atomic_set(&t->trace_overrun, 0);
	ret_stack_init_task_vars(ret_stack);
	t->ftrace_timestamp = 0;
	t->curr_ret_stack = 0;
	t->rsrv_ret_stack = 0;
	t->curr_ret_depth = -1;
	/* make curr_ret_stack visible before we add the ret_stack */
	smp_wmb();
	t->ret_stack = ret_stack;
}

/*
 * Allocate a return stack for the idle task. May be the first
 * time through, or it may be done by CPU hotplug online.
 */
void ftrace_graph_init_idle_task(struct task_struct *t, int cpu)
{
	t->curr_ret_stack = 0;
	t->rsrv_ret_stack = 0;
	t->curr_ret_depth = -1;
	/*
	 * The idle task has no parent, it either has its own
	 * stack or no stack at all.
	 */
	if (t->ret_stack)
		WARN_ON(t->ret_stack != per_cpu(idle_ret_stack, cpu));

	if (ftrace_graph_active) {
		unsigned long *ret_stack;

		ret_stack = per_cpu(idle_ret_stack, cpu);
		if (!ret_stack) {
			ret_stack = kmalloc(SHADOW_STACK_SIZE, GFP_KERNEL);
			if (!ret_stack)
				return;
			per_cpu(idle_ret_stack, cpu) = ret_stack;
		}
		graph_init_task(t, ret_stack);
	}
}

/* Allocate a return stack for newly created task */
void ftrace_graph_init_task(struct task_struct *t)
{
	/* Make sure we do not use the parent ret_stack */
	t->ret_stack = NULL;
	t->curr_ret_stack = 0;
	t->rsrv_ret_stack = 0;
	t->curr_ret_depth = -1;

	if (ftrace_graph_active) {
		unsigned long *ret_stack;

		ret_stack = kmalloc(SHADOW_STACK_SIZE, GFP_KERNEL);
		if (!ret_stack)
			return;
		graph_init_task(t, ret_stack);
	}
}

void ftrace_graph_exit_task(struct task_struct *t)
{
	unsigned long *ret_stack = t->ret_stack;

	t->ret_stack = NULL;
	/* NULL must become visible to IRQs before we free it: */
	barrier();

	kfree(ret_stack);
}

/* Allocate a return stack for each task */
static int start_graph_tracing(void)
{
	unsigned long **ret_stack_list;
	int ret, cpu;

	ret_stack_list = kmalloc(SHADOW_STACK_SIZE, GFP_KERNEL);

	if (!ret_stack_list)
		return -ENOMEM;

	/* The cpu_boot init_task->ret_stack will never be freed */
	for_each_online_cpu(cpu) {
		if (!idle_task(cpu)->ret_stack)
			ftrace_graph_init_idle_task(idle_task(cpu), cpu);
	}

	do {
		ret = alloc_retstack_tasklist(ret_stack_list);
	} while (ret == -EAGAIN);

	if (!ret) {
		ret = register_trace_sched_switch(ftrace_graph_probe_sched_switch, NULL);
		if (ret)
			pr_info("ftrace_graph: Couldn't activate tracepoint"
				" probe to kernel_sched_switch\n");
	}

	kfree(ret_stack_list);
	return ret;
}

static void init_task_vars(int idx)
{
	struct task_struct *g, *t;
	int cpu;

	for_each_online_cpu(cpu) {
		if (idle_task(cpu)->ret_stack)
			ret_stack_set_task_var(idle_task(cpu), idx, 0);
	}

	read_lock(&tasklist_lock);
	for_each_process_thread(g, t) {
		if (t->ret_stack)
			ret_stack_set_task_var(t, idx, 0);
	}
	read_unlock(&tasklist_lock);
}

int register_ftrace_graph(struct fgraph_ops *gops)
{
	int command = 0;
	int ret = 0;
	int i;

	mutex_lock(&ftrace_lock);

	if (!gops->ops.func) {
		gops->ops.flags |= FTRACE_OPS_GRAPH_STUB;
		gops->ops.func = ftrace_graph_func;
#ifdef FTRACE_GRAPH_TRAMP_ADDR
		gops->ops.trampoline = FTRACE_GRAPH_TRAMP_ADDR;
#endif
	}

	if (!fgraph_array[0]) {
		/* The array must always have real data on it */
		for (i = 0; i < FGRAPH_ARRAY_SIZE; i++)
			fgraph_array[i] = &fgraph_stub;
		fgraph_lru_init();
	}

	i = fgraph_lru_alloc_index();
	if (i < 0 ||
	    WARN_ON_ONCE(fgraph_array[i] != &fgraph_stub)) {
		ret = -EBUSY;
		goto out;
	}

	fgraph_array[i] = gops;
	gops->idx = i;

	ftrace_graph_active++;

	if (ftrace_graph_active == 1) {
		register_pm_notifier(&ftrace_suspend_notifier);
		ret = start_graph_tracing();
		if (ret) {
			ftrace_graph_active--;
			goto out;
		}
		/*
		 * Some archs just test to see if these are not
		 * the default function
		 */
		ftrace_graph_return = return_run;
		ftrace_graph_entry = entry_run;
		command = FTRACE_START_FUNC_RET;
	} else {
		init_task_vars(gops->idx);
	}

	ret = ftrace_startup(&gops->ops, command);
out:
	mutex_unlock(&ftrace_lock);
	return ret;
}

void unregister_ftrace_graph(struct fgraph_ops *gops)
{
	int command = 0;

	mutex_lock(&ftrace_lock);

	if (unlikely(!ftrace_graph_active))
		goto out;

	if (unlikely(gops->idx < 0 || gops->idx >= FGRAPH_ARRAY_SIZE))
		goto out;

	if (WARN_ON_ONCE(fgraph_array[gops->idx] != gops))
		goto out;

	if (fgraph_lru_release_index(gops->idx) < 0)
		goto out;

	fgraph_array[gops->idx] = &fgraph_stub;

	ftrace_graph_active--;

	if (!ftrace_graph_active)
		command = FTRACE_STOP_FUNC_RET;

	ftrace_shutdown(&gops->ops, command);

	if (!ftrace_graph_active) {
		ftrace_graph_return = ftrace_stub_graph;
		ftrace_graph_entry = ftrace_graph_entry_stub;
		unregister_pm_notifier(&ftrace_suspend_notifier);
		unregister_trace_sched_switch(ftrace_graph_probe_sched_switch, NULL);
	}
 out:
	mutex_unlock(&ftrace_lock);
}
