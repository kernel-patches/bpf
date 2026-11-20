// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/profile.c
 *  Simple profiling. Manages a direct-mapped profile hit count buffer,
 *  with configurable resolution, support for restricting the cpus on
 *  which profiling is done, and switching between cpu time and
 *  schedule() calls via kernel command line parameters passed at boot.
 *
 *  Scheduler profiling support, Arjan van de Ven and Ingo Molnar,
 *	Red Hat, July 2004
 *  Consolidation of architecture support code for profiling,
 *	Nadia Yvette Chambers, Oracle, July 2004
 *  Amortized hit count accounting via per-cpu open-addressed hashtables
 *	to resolve timer interrupt livelocks, Nadia Yvette Chambers,
 *	Oracle, 2004
 */

#include <linux/export.h>
#include <linux/profile.h>
#include <linux/memblock.h>
#include <linux/notifier.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched/stat.h>

#include <asm/sections.h>
#include <asm/irq_regs.h>
#include <asm/ptrace.h>

struct profile_hit {
	u32 pc, hits;
};
#define PROFILE_GRPSHIFT	3
#define PROFILE_GRPSZ		(1 << PROFILE_GRPSHIFT)
#define NR_PROFILE_HIT		(PAGE_SIZE/sizeof(struct profile_hit))
#define NR_PROFILE_GRP		(NR_PROFILE_HIT/PROFILE_GRPSZ)

static atomic_t *prof_buffer;
static unsigned long prof_len;
static unsigned short int prof_shift;

int prof_on __read_mostly;
EXPORT_SYMBOL_GPL(prof_on);

int profile_setup(char *str)
{
	static const char schedstr[] = "schedule";
	static const char kvmstr[] = "kvm";
	const char *select = NULL;
	int par;

	if (!strncmp(str, schedstr, strlen(schedstr))) {
		prof_on = SCHED_PROFILING;
		select = schedstr;
	} else if (!strncmp(str, kvmstr, strlen(kvmstr))) {
		prof_on = KVM_PROFILING;
		select = kvmstr;
	} else if (get_option(&str, &par)) {
		prof_shift = clamp(par, 0, BITS_PER_LONG - 1);
		prof_on = CPU_PROFILING;
		pr_info("kernel profiling enabled (shift: %u)\n",
			prof_shift);
	}

	if (select) {
		if (str[strlen(select)] == ',')
			str += strlen(select) + 1;
		if (get_option(&str, &par))
			prof_shift = clamp(par, 0, BITS_PER_LONG - 1);
		pr_info("kernel %s profiling enabled (shift: %u)\n",
			select, prof_shift);
	}

	return 1;
}
__setup("profile=", profile_setup);


int __ref profile_init(void)
{
	int buffer_bytes;
	if (!prof_on)
		return 0;

	/* only text is profiled */
	prof_len = (_etext - _stext) >> prof_shift;

	if (!prof_len) {
		pr_warn("profiling shift: %u too large\n", prof_shift);
		prof_on = 0;
		return -EINVAL;
	}

	buffer_bytes = prof_len*sizeof(atomic_t);

	prof_buffer = kzalloc(buffer_bytes, GFP_KERNEL|__GFP_NOWARN);
	if (prof_buffer)
		return 0;

	prof_buffer = alloc_pages_exact(buffer_bytes,
					GFP_KERNEL|__GFP_ZERO|__GFP_NOWARN);
	if (prof_buffer)
		return 0;

	prof_buffer = vzalloc(buffer_bytes);
	if (prof_buffer)
		return 0;

	return -ENOMEM;
}

static void do_profile_hits(int type, void *__pc, unsigned int nr_hits)
{
	unsigned long pc;
	pc = ((unsigned long)__pc - (unsigned long)_stext) >> prof_shift;
	if (pc < prof_len)
		atomic_add(nr_hits, &prof_buffer[pc]);
}

void profile_hits(int type, void *__pc, unsigned int nr_hits)
{
	if (prof_on != type || !prof_buffer)
		return;
	do_profile_hits(type, __pc, nr_hits);
}
EXPORT_SYMBOL_GPL(profile_hits);

void profile_tick(int type)
{
	struct pt_regs *regs = get_irq_regs();

	/* This is the old kernel-only legacy profiling */
	if (!user_mode(regs))
		profile_hit(type, (void *)profile_pc(regs));
}

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uio.h>

/*
 * This function accesses profiling information. The returned data is
 * binary: the sampling step and the actual contents of the profile
 * buffer. Use of the program readprofile is recommended in order to
 * get meaningful info out of these data.
 */
static ssize_t read_profile(struct kiocb *iocb, struct iov_iter *to)
{
	unsigned long p = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	ssize_t read;
	char *pnt;
	unsigned int sample_step = (unsigned int)(1UL << prof_shift);

	if (p >= (prof_len+1)*sizeof(unsigned int))
		return 0;
	if (count > (prof_len+1)*sizeof(unsigned int) - p)
		count = (prof_len+1)*sizeof(unsigned int) - p;
	read = 0;

	while (p < sizeof(unsigned int) && count > 0) {
		if (copy_to_iter((char *)(&sample_step)+p, 1, to) != 1)
			return -EFAULT;
		p++; count--; read++;
	}
	pnt = (char *)prof_buffer + p - sizeof(atomic_t);
	if (copy_to_iter(pnt, count, to) != count)
		return -EFAULT;
	read += count;
	iocb->ki_pos += read;
	return read;
}

/* default is to not implement this call */
int __weak setup_profiling_timer(unsigned mult)
{
	return -EINVAL;
}

/*
 * Writing to /proc/profile resets the counters
 *
 * Writing a 'profiling multiplier' value into it also re-sets the profiling
 * interrupt frequency, on architectures that support this.
 */
static ssize_t write_profile(struct kiocb *iocb, struct iov_iter *from)
{
	size_t count = iov_iter_count(from);
#ifdef CONFIG_SMP
	if (count == sizeof(int)) {
		unsigned int multiplier;

		if (copy_from_iter(&multiplier, sizeof(int), from) != sizeof(int))
			return -EFAULT;
		if (setup_profiling_timer(multiplier))
			return -EINVAL;
	}
#endif
	memset(prof_buffer, 0, prof_len * sizeof(atomic_t));
	return count;
}

static const struct file_operations profile_fops = {
	.read_iter	= read_profile,
	.write_iter	= write_profile,
	.splice_read	= copy_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= default_llseek,
};

int __ref create_proc_profile(void)
{
	struct proc_dir_entry *entry;

	if (!prof_on)
		return 0;
	entry = proc_create_fops("profile", S_IWUSR | S_IRUGO, NULL,
				 &profile_fops);
	if (!entry)
		return -ENOMEM;
	proc_set_size(entry, (1 + prof_len) * sizeof(atomic_t));
	return 0;
}
subsys_initcall(create_proc_profile);
#endif /* CONFIG_PROC_FS */
