// SPDX-License-Identifier: GPL-2.0
/*
 *  Generic support for BUG()
 *
 *  This respects the following config options:
 *
 *  CONFIG_BUG - emit BUG traps.  Nothing happens without this.
 *  CONFIG_GENERIC_BUG - enable this code.
 *  CONFIG_GENERIC_BUG_RELATIVE_POINTERS - use 32-bit relative pointers for bug_addr and file
 *  CONFIG_DEBUG_BUGVERBOSE - emit full file+line information for each BUG
 *
 *  CONFIG_BUG and CONFIG_DEBUG_BUGVERBOSE are potentially user-settable
 *  (though they're generally always on).
 *
 *  CONFIG_GENERIC_BUG is set by each architecture using this code.
 *
 *  To use this, your architecture must:
 *
 *  1. Set up the config options:
 *     - Enable CONFIG_GENERIC_BUG if CONFIG_BUG
 *
 *  2. Implement BUG (and optionally BUG_ON, WARN, WARN_ON)
 *     - Define HAVE_ARCH_BUG
 *     - Implement BUG() to generate a faulting instruction
 *     - NOTE: struct bug_entry does not have "file" or "line" entries
 *       when CONFIG_DEBUG_BUGVERBOSE is not enabled, so you must generate
 *       the values accordingly.
 *
 *  3. Implement the trap
 *     - In the illegal instruction trap handler (typically), verify
 *       that the fault was in kernel mode, and call report_bug()
 *     - report_bug() will return whether it was a false alarm, a warning,
 *       or an actual bug.
 *     - You must implement the is_valid_bugaddr(bugaddr) callback which
 *       returns true if the eip is a real kernel address, and it points
 *       to the expected BUG trap instruction.
 *
 *    Jeremy Fitzhardinge <jeremy@goop.org> 2006
 */

#define pr_fmt(fmt) fmt

#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/ftrace.h>
#include <linux/context_tracking.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#include <linux/init.h>
#include <kunit/test-bug.h>

extern struct bug_entry __start___bug_table[], __stop___bug_table[];

static bool main_bug_table_sorted;

static inline unsigned long bug_addr(const struct bug_entry *bug)
{
#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	return (unsigned long)&bug->bug_addr_disp + bug->bug_addr_disp;
#else
	return bug->bug_addr;
#endif
}

static int bug_cmp(const void *a, const void *b)
{
	const struct bug_entry *bug_a = a, *bug_b = b;
	unsigned long addr_a = bug_addr(bug_a), addr_b = bug_addr(bug_b);

	if (addr_a < addr_b)
		return -1;
	if (addr_a > addr_b)
		return 1;
	return 0;
}

static int bug_search_cmp(const void *key, const void *elt)
{
	const struct bug_entry *bug = elt;
	unsigned long addr = *(unsigned long *)key;
	unsigned long bugaddr = bug_addr(bug);

	if (addr < bugaddr)
		return -1;
	if (addr > bugaddr)
		return 1;
	return 0;
}

#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
static void bug_swap(void *a, void *b, int size)
{
	struct bug_entry *x = a, *y = b, tmp;
	int delta = b - a;

	(void)size;

	tmp = *x;
	*x = *y;
	*y = tmp;

	x->bug_addr_disp += delta;
	y->bug_addr_disp -= delta;
#ifdef HAVE_ARCH_BUG_FORMAT
	if (x->format_disp)
		x->format_disp += delta;
	if (y->format_disp)
		y->format_disp -= delta;
#endif
#ifdef CONFIG_DEBUG_BUGVERBOSE
	if (x->file_disp)
		x->file_disp += delta;
	if (y->file_disp)
		y->file_disp -= delta;
#endif
}
#define BUG_SWAP bug_swap
#else
#define BUG_SWAP NULL
#endif

static void sort_bug_table(struct bug_entry *start, struct bug_entry *end)
{
	sort(start, end - start, sizeof(*start), bug_cmp, BUG_SWAP);
}

void __init sort_main_bug_table(void)
{
	sort_bug_table(__start___bug_table, __stop___bug_table);
	main_bug_table_sorted = true;
}

#ifdef CONFIG_MODULES
/* Updates are protected by module mutex */
static LIST_HEAD(module_bug_list);

static struct bug_entry *module_find_bug(unsigned long bugaddr)
{
	struct bug_entry *bug;
	struct module *mod;

	guard(rcu)();
	list_for_each_entry_rcu(mod, &module_bug_list, bug_list) {
		bug = bsearch(&bugaddr, mod->bug_table, mod->num_bugs,
			      sizeof(*mod->bug_table), bug_search_cmp);
		if (bug)
			return bug;
	}
	return NULL;
}

void module_bug_finalize(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs,
			 struct module *mod)
{
	char *secstrings;
	unsigned int i;

	mod->bug_table = NULL;
	mod->num_bugs = 0;

	/* Find the __bug_table section, if present */
	secstrings = (char *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;
	for (i = 1; i < hdr->e_shnum; i++) {
		if (strcmp(secstrings+sechdrs[i].sh_name, "__bug_table"))
			continue;
		mod->bug_table = (void *) sechdrs[i].sh_addr;
		mod->num_bugs = sechdrs[i].sh_size / sizeof(struct bug_entry);
		if (mod->num_bugs > 1)
			sort_bug_table(mod->bug_table,
				       mod->bug_table + mod->num_bugs);
		break;
	}

	/*
	 * Strictly speaking this should have a spinlock to protect against
	 * traversals, but since we only traverse on BUG()s, a spinlock
	 * could potentially lead to deadlock and thus be counter-productive.
	 * Thus, this uses RCU to safely manipulate the bug list, since BUG
	 * must run in non-interruptive state.
	 */
	list_add_rcu(&mod->bug_list, &module_bug_list);
}

void module_bug_cleanup(struct module *mod)
{
	list_del_rcu(&mod->bug_list);
}

#else

static inline struct bug_entry *module_find_bug(unsigned long bugaddr)
{
	return NULL;
}
#endif

void bug_get_file_line(struct bug_entry *bug, const char **file,
		       unsigned int *line)
{
#ifdef CONFIG_DEBUG_BUGVERBOSE
#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	*file = (const char *)&bug->file_disp + bug->file_disp;
#else
	*file = bug->file;
#endif
	*line = bug->line;
#else
	*file = NULL;
	*line = 0;
#endif
}

static const char *bug_get_format(struct bug_entry *bug)
{
	const char *format = NULL;
#ifdef HAVE_ARCH_BUG_FORMAT
#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	/*
	 * Allow an architecture to:
	 *  - relative encode NULL (difficult vs KASLR);
	 *  - use a literal 0 (there are no valid objects inside
	 *    the __bug_table itself to refer to after all);
	 *  - use an empty string.
	 */
	if (bug->format_disp)
		format = (const char *)&bug->format_disp + bug->format_disp;
	if (format && format[0] == '\0')
		format = NULL;
#else
	format = bug->format;
#endif
#endif
	return format;
}

struct bug_entry *find_bug(unsigned long bugaddr)
{
	struct bug_entry *bug;

	if (unlikely(!main_bug_table_sorted)) {
		for (bug = __start___bug_table; bug < __stop___bug_table; ++bug)
			if (bugaddr == bug_addr(bug))
				return bug;
		return module_find_bug(bugaddr);
	}

	bug = bsearch(&bugaddr, __start___bug_table,
		      __stop___bug_table - __start___bug_table,
		      sizeof(*bug), bug_search_cmp);
	if (bug)
		return bug;

	return module_find_bug(bugaddr);
}

static __printf(1, 0)
void __warn_printf(const char *fmt, struct pt_regs *regs)
{
	if (!fmt)
		return;

#ifdef HAVE_ARCH_BUG_FORMAT_ARGS
	if (regs) {
		struct arch_va_list _args;
		va_list *args = __warn_args(&_args, regs);

		if (args) {
			vprintk(fmt, *args);
			return;
		}
	}
#endif

	pr_warn("%s", fmt);
}

static enum bug_trap_type __report_bug(struct bug_entry *bug, unsigned long bugaddr, struct pt_regs *regs)
{
	bool warning, once, done, no_cut, has_args;
	const char *file, *fmt;
	unsigned int line;

	if (!bug) {
		if (!is_valid_bugaddr(bugaddr))
			return BUG_TRAP_TYPE_NONE;

		bug = find_bug(bugaddr);
		if (!bug)
			return BUG_TRAP_TYPE_NONE;
	}

	bug_get_file_line(bug, &file, &line);
	fmt = bug_get_format(bug);

	warning  = bug->flags & BUGFLAG_WARNING;
	once     = bug->flags & BUGFLAG_ONCE;
	done     = bug->flags & BUGFLAG_DONE;
	no_cut   = bug->flags & BUGFLAG_NO_CUT_HERE;
	has_args = bug->flags & BUGFLAG_ARGS;

	/*
	 * Before the once logic so suppressed warnings do not consume
	 * the single-fire budget of WARN_ON_ONCE().
	 */
	if (warning && kunit_is_suppressed_warning(true))
		return BUG_TRAP_TYPE_WARN;

	disable_trace_on_warning();

	if (warning && once) {
		if (done)
			return BUG_TRAP_TYPE_WARN;

		/*
		 * Since this is the only store, concurrency is not an issue.
		 */
		bug->flags |= BUGFLAG_DONE;
	}

	/*
	 * BUG() and WARN_ON() families don't print a custom debug message
	 * before triggering the exception handler, so we must add the
	 * "cut here" line now. WARN() issues its own "cut here" before the
	 * extra debugging message it writes before triggering the handler.
	 */
	if (!no_cut) {
		pr_info(CUT_HERE);
		__warn_printf(fmt, has_args ? regs : NULL);
	}

	if (warning) {
		/* this is a WARN_ON rather than BUG/BUG_ON */
		__warn(file, line, (void *)bugaddr, BUG_GET_TAINT(bug), regs,
		       NULL);
		return BUG_TRAP_TYPE_WARN;
	}

	if (file)
		pr_crit("kernel BUG at %s:%u!\n", file, line);
	else
		pr_crit("kernel BUG at %pB [verbose debug info unavailable]\n",
			(void *)bugaddr);

	return BUG_TRAP_TYPE_BUG;
}

enum bug_trap_type report_bug_entry(struct bug_entry *bug, struct pt_regs *regs)
{
	enum bug_trap_type ret;
	bool rcu;

	rcu = warn_rcu_enter();
	ret = __report_bug(bug, bug_addr(bug), regs);
	warn_rcu_exit(rcu);

	return ret;
}

enum bug_trap_type report_bug(unsigned long bugaddr, struct pt_regs *regs)
{
	enum bug_trap_type ret;
	bool rcu;

	rcu = warn_rcu_enter();
	ret = __report_bug(NULL, bugaddr, regs);
	warn_rcu_exit(rcu);

	return ret;
}

static void clear_once_table(struct bug_entry *start, struct bug_entry *end)
{
	struct bug_entry *bug;

	for (bug = start; bug < end; bug++)
		bug->flags &= ~BUGFLAG_DONE;
}

void generic_bug_clear_once(void)
{
#ifdef CONFIG_MODULES
	struct module *mod;

	scoped_guard(rcu) {
		list_for_each_entry_rcu(mod, &module_bug_list, bug_list)
			clear_once_table(mod->bug_table,
					 mod->bug_table + mod->num_bugs);
	}
#endif

	clear_once_table(__start___bug_table, __stop___bug_table);
}
