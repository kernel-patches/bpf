// SPDX-License-Identifier: GPL-2.0
/*
 * fprobe - Simple ftrace probe wrapper for function entry.
 */
#define pr_fmt(fmt) "fprobe: " fmt

#include <linux/err.h>
#include <linux/fprobe.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include "trace.h"

#define FPROBE_IP_HASH_BITS 8
#define FPROBE_IP_TABLE_SIZE (1 << FPROBE_IP_HASH_BITS)

#define FPROBE_HASH_BITS 6
#define FPROBE_TABLE_SIZE (1 << FPROBE_HASH_BITS)

#define SIZE_IN_LONG(x) ((x + sizeof(long) - 1) >> (sizeof(long) == 8 ? 3 : 2))

/*
 * fprobe_table: hold 'fprobe_hlist::hlist' for checking the fprobe still
 *   exists. The key is the address of fprobe instance.
 * fprobe_ip_table: hold 'fprobe_hlist::array[*]' for searching the fprobe
 *   instance related to the funciton address. The key is the ftrace IP
 *   address.
 *
 * When unregistering the fprobe, fprobe_hlist::fp and fprobe_hlist::array[*].fp
 * are set NULL and delete those from both hash tables (by hlist_del_rcu).
 * After an RCU grace period, the fprobe_hlist itself will be released.
 *
 * fprobe_table and fprobe_ip_table can be accessed from either
 *  - Normal hlist traversal and RCU add/del under 'fprobe_mutex' is held.
 *  - RCU hlist traversal under disabling preempt
 */
static struct hlist_head fprobe_table[FPROBE_TABLE_SIZE];
static struct hlist_head fprobe_ip_table[FPROBE_IP_TABLE_SIZE];
static DEFINE_MUTEX(fprobe_mutex);

/*
 * Find first fprobe in the hlist. It will be iterated twice in the entry
 * probe, once for correcting the total required size, the second time is
 * calling back the user handlers.
 * Thus the hlist in the fprobe_table must be sorted and new probe needs to
 * be added *before* the first fprobe.
 */
static struct fprobe_hlist_node *find_first_fprobe_node(unsigned long ip)
{
	struct fprobe_hlist_node *node;
	struct hlist_head *head;

	head = &fprobe_ip_table[hash_ptr((void *)ip, FPROBE_IP_HASH_BITS)];
	hlist_for_each_entry_rcu(node, head, hlist,
				 lockdep_is_held(&fprobe_mutex)) {
		if (node->addr == ip)
			return node;
	}
	return NULL;
}
NOKPROBE_SYMBOL(find_first_fprobe_node);

/* Node insertion and deletion requires the fprobe_mutex */
static void insert_fprobe_node(struct fprobe_hlist_node *node)
{
	unsigned long ip = node->addr;
	struct fprobe_hlist_node *next;
	struct hlist_head *head;

	lockdep_assert_held(&fprobe_mutex);

	next = find_first_fprobe_node(ip);
	if (next) {
		hlist_add_before_rcu(&node->hlist, &next->hlist);
		return;
	}
	head = &fprobe_ip_table[hash_ptr((void *)ip, FPROBE_IP_HASH_BITS)];
	hlist_add_head_rcu(&node->hlist, head);
}

/* Return true if there are synonims */
static bool delete_fprobe_node(struct fprobe_hlist_node *node)
{
	lockdep_assert_held(&fprobe_mutex);

	WRITE_ONCE(node->fp, NULL);
	hlist_del_rcu(&node->hlist);
	return !!find_first_fprobe_node(node->addr);
}

/* Check existence of the fprobe */
static bool is_fprobe_still_exist(struct fprobe *fp)
{
	struct hlist_head *head;
	struct fprobe_hlist *fph;

	head = &fprobe_table[hash_ptr(fp, FPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(fph, head, hlist,
				 lockdep_is_held(&fprobe_mutex)) {
		if (fph->fp == fp)
			return true;
	}
	return false;
}
NOKPROBE_SYMBOL(is_fprobe_still_exist);

static int add_fprobe_hash(struct fprobe *fp)
{
	struct fprobe_hlist *fph = fp->hlist_array;
	struct hlist_head *head;

	lockdep_assert_held(&fprobe_mutex);

	if (WARN_ON_ONCE(!fph))
		return -EINVAL;

	if (is_fprobe_still_exist(fp))
		return -EEXIST;

	head = &fprobe_table[hash_ptr(fp, FPROBE_HASH_BITS)];
	hlist_add_head_rcu(&fp->hlist_array->hlist, head);
	return 0;
}

static int del_fprobe_hash(struct fprobe *fp)
{
	struct fprobe_hlist *fph = fp->hlist_array;

	lockdep_assert_held(&fprobe_mutex);

	if (WARN_ON_ONCE(!fph))
		return -EINVAL;

	if (!is_fprobe_still_exist(fp))
		return -ENOENT;

	fph->fp = NULL;
	hlist_del_rcu(&fph->hlist);
	return 0;
}

/* The entry data size is 4 bits (=16) * sizeof(long) in maximum */
#define FPROBE_HEADER_SIZE_BITS		4
#define MAX_FPROBE_DATA_SIZE_WORD	((1L << FPROBE_HEADER_SIZE_BITS) - 1)
#define MAX_FPROBE_DATA_SIZE		(MAX_FPROBE_DATA_SIZE_WORD * sizeof(long))
#define FPROBE_HEADER_PTR_BITS		(BITS_PER_LONG - FPROBE_HEADER_SIZE_BITS)
#define FPROBE_HEADER_PTR_MASK		GENMASK(FPROBE_HEADER_PTR_BITS - 1, 0)
#define FPROBE_HEADER_SIZE		sizeof(unsigned long)

static inline unsigned long encode_fprobe_header(struct fprobe *fp, int size_words)
{
	if (WARN_ON_ONCE(size_words > MAX_FPROBE_DATA_SIZE_WORD ||
	    ((unsigned long)fp & ~FPROBE_HEADER_PTR_MASK) !=
	    ~FPROBE_HEADER_PTR_MASK)) {
		return 0;
	}
	return ((unsigned long)size_words << FPROBE_HEADER_PTR_BITS) |
		((unsigned long)fp & FPROBE_HEADER_PTR_MASK);
}

/* Return reserved data size in words */
static inline int decode_fprobe_header(unsigned long val, struct fprobe **fp)
{
	unsigned long ptr;

	ptr = (val & FPROBE_HEADER_PTR_MASK) | ~FPROBE_HEADER_PTR_MASK;
	if (fp)
		*fp = (struct fprobe *)ptr;
	return val >> FPROBE_HEADER_PTR_BITS;
}

/*
 * fprobe shadow stack management:
 * Since fprobe shares a single fgraph_ops, it needs to share the stack entry
 * among the probes on the same function exit. Note that a new probe can be
 * registered before a target function is returning, we can not use the hash
 * table to find the corresponding probes. Thus the probe address is stored on
 * the shadow stack with its entry data size.
 *
 */
static inline int __fprobe_handler(unsigned long ip, unsigned long parent_ip,
				   struct fprobe *fp, struct ftrace_regs *fregs,
				   void *data)
{
	if (!fp->entry_handler)
		return 0;

	return fp->entry_handler(fp, ip, parent_ip, fregs, data);
}

static inline int __fprobe_kprobe_handler(unsigned long ip, unsigned long parent_ip,
					  struct fprobe *fp, struct ftrace_regs *fregs,
					  void *data)
{
	int ret;
	/*
	 * This user handler is shared with other kprobes and is not expected to be
	 * called recursively. So if any other kprobe handler is running, this will
	 * exit as kprobe does. See the section 'Share the callbacks with kprobes'
	 * in Documentation/trace/fprobe.rst for more information.
	 */
	if (unlikely(kprobe_running())) {
		fp->nmissed++;
		return 0;
	}

	kprobe_busy_begin();
	ret = __fprobe_handler(ip, parent_ip, fp, fregs, data);
	kprobe_busy_end();
	return ret;
}

static int fprobe_entry(struct ftrace_graph_ent *trace, struct fgraph_ops *gops,
			struct ftrace_regs *fregs)
{
	struct fprobe_hlist_node *node, *first;
	unsigned long *fgraph_data = NULL;
	unsigned long func = trace->func;
	unsigned long header, ret_ip;
	int reserved_words;
	struct fprobe *fp;
	int used, ret;

	if (WARN_ON_ONCE(!fregs))
		return 0;

	first = node = find_first_fprobe_node(func);
	if (unlikely(!first))
		return 0;

	reserved_words = 0;
	hlist_for_each_entry_from_rcu(node, hlist) {
		if (node->addr != func)
			break;
		fp = READ_ONCE(node->fp);
		if (!fp || !fp->exit_handler)
			continue;
		/*
		 * Since fprobe can be enabled until the next loop, we ignore the
		 * fprobe's disabled flag in this loop.
		 */
		reserved_words +=
			SIZE_IN_LONG(fp->entry_data_size) + 1;
	}
	node = first;
	if (reserved_words) {
		fgraph_data = fgraph_reserve_data(gops->idx, reserved_words * sizeof(long));
		if (unlikely(!fgraph_data)) {
			hlist_for_each_entry_from_rcu(node, hlist) {
				if (node->addr != func)
					break;
				fp = READ_ONCE(node->fp);
				if (fp && !fprobe_disabled(fp))
					fp->nmissed++;
			}
			return 0;
		}
	}

	/*
	 * TODO: recursion detection has been done in the fgraph. Thus we need
	 * to add a callback to increment missed counter.
	 */
	ret_ip = ftrace_regs_get_return_address(fregs);
	used = 0;
	hlist_for_each_entry_from_rcu(node, hlist) {
		void *data;

		if (node->addr != func)
			break;
		fp = READ_ONCE(node->fp);
		if (!fp || fprobe_disabled(fp))
			continue;

		if (fp->entry_data_size && fp->exit_handler)
			data = fgraph_data + used + 1;
		else
			data = NULL;

		if (fprobe_shared_with_kprobes(fp))
			ret = __fprobe_kprobe_handler(func, ret_ip, fp, fregs, data);
		else
			ret = __fprobe_handler(func, ret_ip, fp, fregs, data);
		/* If entry_handler returns !0, nmissed is not counted but skips exit_handler. */
		if (!ret && fp->exit_handler) {
			int size_words = SIZE_IN_LONG(fp->entry_data_size);

			header = encode_fprobe_header(fp, size_words);
			if (likely(header)) {
				fgraph_data[used] = header;
				used += size_words + 1;
			}
		}
	}
	if (used < reserved_words)
		memset(fgraph_data + used, 0, reserved_words - used);

	/* If any exit_handler is set, data must be used. */
	return used != 0;
}
NOKPROBE_SYMBOL(fprobe_entry);

static void fprobe_return(struct ftrace_graph_ret *trace,
			  struct fgraph_ops *gops,
			  struct ftrace_regs *fregs)
{
	unsigned long *fgraph_data = NULL;
	unsigned long ret_ip;
	unsigned long val;
	struct fprobe *fp;
	int size, curr;
	int size_words;

	fgraph_data = (unsigned long *)fgraph_retrieve_data(gops->idx, &size);
	if (WARN_ON_ONCE(!fgraph_data))
		return;
	size_words = SIZE_IN_LONG(size);
	ret_ip = ftrace_regs_get_instruction_pointer(fregs);

	preempt_disable();

	curr = 0;
	while (size_words > curr) {
		val = fgraph_data[curr++];
		if (!val)
			break;

		size = decode_fprobe_header(val, &fp);
		if (fp && is_fprobe_still_exist(fp) && !fprobe_disabled(fp)) {
			if (WARN_ON_ONCE(curr + size > size_words))
				break;
			fp->exit_handler(fp, trace->func, ret_ip, fregs,
					 size ? fgraph_data + curr : NULL);
		}
		curr += size;
	}
	preempt_enable();
}
NOKPROBE_SYMBOL(fprobe_return);

static struct fgraph_ops fprobe_graph_ops = {
	.entryfunc	= fprobe_entry,
	.retfunc	= fprobe_return,
};
static int fprobe_graph_active;

/* Add @addrs to the ftrace filter and register fgraph if needed. */
static int fprobe_graph_add_ips(unsigned long *addrs, int num)
{
	int ret;

	lockdep_assert_held(&fprobe_mutex);

	ret = ftrace_set_filter_ips(&fprobe_graph_ops.ops, addrs, num, 0, 0);
	if (ret)
		return ret;

	if (!fprobe_graph_active) {
		ret = register_ftrace_graph(&fprobe_graph_ops);
		if (WARN_ON_ONCE(ret)) {
			ftrace_free_filter(&fprobe_graph_ops.ops);
			return ret;
		}
	}
	fprobe_graph_active++;
	return 0;
}

/* Remove @addrs from the ftrace filter and unregister fgraph if possible. */
static void fprobe_graph_remove_ips(unsigned long *addrs, int num)
{
	lockdep_assert_held(&fprobe_mutex);

	fprobe_graph_active--;
	if (!fprobe_graph_active) {
		/* Q: should we unregister it ? */
		unregister_ftrace_graph(&fprobe_graph_ops);
		return;
	}

	ftrace_set_filter_ips(&fprobe_graph_ops.ops, addrs, num, 1, 0);
}

static int symbols_cmp(const void *a, const void *b)
{
	const char **str_a = (const char **) a;
	const char **str_b = (const char **) b;

	return strcmp(*str_a, *str_b);
}

/* Convert ftrace location address from symbols */
static unsigned long *get_ftrace_locations(const char **syms, int num)
{
	unsigned long *addrs;

	/* Convert symbols to symbol address */
	addrs = kcalloc(num, sizeof(*addrs), GFP_KERNEL);
	if (!addrs)
		return ERR_PTR(-ENOMEM);

	/* ftrace_lookup_symbols expects sorted symbols */
	sort(syms, num, sizeof(*syms), symbols_cmp, NULL);

	if (!ftrace_lookup_symbols(syms, num, addrs))
		return addrs;

	kfree(addrs);
	return ERR_PTR(-ENOENT);
}

struct filter_match_data {
	const char *filter;
	const char *notfilter;
	size_t index;
	size_t size;
	unsigned long *addrs;
};

static int filter_match_callback(void *data, const char *name, unsigned long addr)
{
	struct filter_match_data *match = data;

	if (!glob_match(match->filter, name) ||
	    (match->notfilter && glob_match(match->notfilter, name)))
		return 0;

	if (!ftrace_location(addr))
		return 0;

	if (match->addrs)
		match->addrs[match->index] = addr;

	match->index++;
	return match->index == match->size;
}

/*
 * Make IP list from the filter/no-filter glob patterns.
 * Return the number of matched symbols, or -ENOENT.
 */
static int ip_list_from_filter(const char *filter, const char *notfilter,
			       unsigned long *addrs, size_t size)
{
	struct filter_match_data match = { .filter = filter, .notfilter = notfilter,
		.index = 0, .size = size, .addrs = addrs};
	int ret;

	ret = kallsyms_on_each_symbol(filter_match_callback, &match);
	if (ret < 0)
		return ret;
	ret = module_kallsyms_on_each_symbol(NULL, filter_match_callback, &match);
	if (ret < 0)
		return ret;

	return match.index ?: -ENOENT;
}

static void fprobe_fail_cleanup(struct fprobe *fp)
{
	kfree(fp->hlist_array);
	fp->hlist_array = NULL;
}

/* Initialize the fprobe data structure. */
static int fprobe_init(struct fprobe *fp, unsigned long *addrs, int num)
{
	struct fprobe_hlist *hlist_array;
	unsigned long addr;
	int size, i;

	if (!fp || !addrs || num <= 0)
		return -EINVAL;

	size = ALIGN(fp->entry_data_size, sizeof(long));
	if (size > MAX_FPROBE_DATA_SIZE)
		return -E2BIG;
	fp->entry_data_size = size;

	hlist_array = kzalloc(struct_size(hlist_array, array, num), GFP_KERNEL);
	if (!hlist_array)
		return -ENOMEM;

	fp->nmissed = 0;

	hlist_array->size = num;
	fp->hlist_array = hlist_array;
	hlist_array->fp = fp;
	for (i = 0; i < num; i++) {
		hlist_array->array[i].fp = fp;
		addr = ftrace_location(addrs[i]);
		if (!addr) {
			fprobe_fail_cleanup(fp);
			return -ENOENT;
		}
		hlist_array->array[i].addr = addr;
	}
	return 0;
}

#define FPROBE_IPS_MAX	INT_MAX

/**
 * register_fprobe() - Register fprobe to ftrace by pattern.
 * @fp: A fprobe data structure to be registered.
 * @filter: A wildcard pattern of probed symbols.
 * @notfilter: A wildcard pattern of NOT probed symbols.
 *
 * Register @fp to ftrace for enabling the probe on the symbols matched to @filter.
 * If @notfilter is not NULL, the symbols matched the @notfilter are not probed.
 *
 * Return 0 if @fp is registered successfully, -errno if not.
 */
int register_fprobe(struct fprobe *fp, const char *filter, const char *notfilter)
{
	unsigned long *addrs;
	int ret;

	if (!fp || !filter)
		return -EINVAL;

	ret = ip_list_from_filter(filter, notfilter, NULL, FPROBE_IPS_MAX);
	if (ret < 0)
		return ret;

	addrs = kcalloc(ret, sizeof(unsigned long), GFP_KERNEL);
	if (!addrs)
		return -ENOMEM;
	ret = ip_list_from_filter(filter, notfilter, addrs, ret);
	if (ret > 0)
		ret = register_fprobe_ips(fp, addrs, ret);

	kfree(addrs);
	return ret;
}
EXPORT_SYMBOL_GPL(register_fprobe);

/**
 * register_fprobe_ips() - Register fprobe to ftrace by address.
 * @fp: A fprobe data structure to be registered.
 * @addrs: An array of target function address.
 * @num: The number of entries of @addrs.
 *
 * Register @fp to ftrace for enabling the probe on the address given by @addrs.
 * The @addrs must be the addresses of ftrace location address, which may be
 * the symbol address + arch-dependent offset.
 * If you unsure what this mean, please use other registration functions.
 *
 * Return 0 if @fp is registered successfully, -errno if not.
 */
int register_fprobe_ips(struct fprobe *fp, unsigned long *addrs, int num)
{
	struct fprobe_hlist *hlist_array;
	int ret, i;

	ret = fprobe_init(fp, addrs, num);
	if (ret)
		return ret;

	mutex_lock(&fprobe_mutex);

	hlist_array = fp->hlist_array;
	ret = fprobe_graph_add_ips(addrs, num);
	if (!ret) {
		add_fprobe_hash(fp);
		for (i = 0; i < hlist_array->size; i++)
			insert_fprobe_node(&hlist_array->array[i]);
	}
	mutex_unlock(&fprobe_mutex);

	if (ret)
		fprobe_fail_cleanup(fp);

	return ret;
}
EXPORT_SYMBOL_GPL(register_fprobe_ips);

/**
 * register_fprobe_syms() - Register fprobe to ftrace by symbols.
 * @fp: A fprobe data structure to be registered.
 * @syms: An array of target symbols.
 * @num: The number of entries of @syms.
 *
 * Register @fp to the symbols given by @syms array. This will be useful if
 * you are sure the symbols exist in the kernel.
 *
 * Return 0 if @fp is registered successfully, -errno if not.
 */
int register_fprobe_syms(struct fprobe *fp, const char **syms, int num)
{
	unsigned long *addrs;
	int ret;

	if (!fp || !syms || num <= 0)
		return -EINVAL;

	addrs = get_ftrace_locations(syms, num);
	if (IS_ERR(addrs))
		return PTR_ERR(addrs);

	ret = register_fprobe_ips(fp, addrs, num);

	kfree(addrs);

	return ret;
}
EXPORT_SYMBOL_GPL(register_fprobe_syms);

bool fprobe_is_registered(struct fprobe *fp)
{
	if (!fp || !fp->hlist_array)
		return false;
	return true;
}

/**
 * unregister_fprobe() - Unregister fprobe.
 * @fp: A fprobe data structure to be unregistered.
 *
 * Unregister fprobe (and remove ftrace hooks from the function entries).
 *
 * Return 0 if @fp is unregistered successfully, -errno if not.
 */
int unregister_fprobe(struct fprobe *fp)
{
	struct fprobe_hlist *hlist_array;
	unsigned long *addrs = NULL;
	int ret = 0, i, count;

	mutex_lock(&fprobe_mutex);
	if (!fp || !is_fprobe_still_exist(fp)) {
		ret = -EINVAL;
		goto out;
	}

	hlist_array = fp->hlist_array;
	addrs = kcalloc(hlist_array->size, sizeof(unsigned long), GFP_KERNEL);
	if (!addrs) {
		ret = -ENOMEM;	/* TODO: Fallback to one-by-one loop */
		goto out;
	}

	/* Remove non-synonim ips from table and hash */
	count = 0;
	for (i = 0; i < hlist_array->size; i++) {
		if (!delete_fprobe_node(&hlist_array->array[i]))
			addrs[count++] = hlist_array->array[i].addr;
	}
	del_fprobe_hash(fp);

	if (count)
		fprobe_graph_remove_ips(addrs, count);

	kfree_rcu(hlist_array, rcu);
	fp->hlist_array = NULL;

out:
	mutex_unlock(&fprobe_mutex);

	kfree(addrs);
	return ret;
}
EXPORT_SYMBOL_GPL(unregister_fprobe);
