// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>

#define LINE_SIZE 80

#include <asm/mtrr.h>

#include "mtrr.h"

#define FILE_FCOUNT(f) (((struct seq_file *)((f)->private_data))->private)

static const char *const mtrr_strings[MTRR_NUM_TYPES] =
{
	"uncachable",		/* 0 */
	"write-combining",	/* 1 */
	"?",			/* 2 */
	"?",			/* 3 */
	"write-through",	/* 4 */
	"write-protect",	/* 5 */
	"write-back",		/* 6 */
};

const char *mtrr_attrib_to_str(int x)
{
	return (x <= 6) ? mtrr_strings[x] : "?";
}

#ifdef CONFIG_PROC_FS

static int
mtrr_file_add(unsigned long base, unsigned long size,
	      unsigned int type, bool increment, struct file *file, int page)
{
	unsigned int *fcount = FILE_FCOUNT(file);
	int reg, max;

	max = num_var_ranges;
	if (fcount == NULL) {
		fcount = kzalloc_objs(*fcount, max);
		if (!fcount)
			return -ENOMEM;
		FILE_FCOUNT(file) = fcount;
	}
	if (!page) {
		if ((base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
			return -EINVAL;
		base >>= PAGE_SHIFT;
		size >>= PAGE_SHIFT;
	}
	reg = mtrr_add_page(base, size, type, true);
	if (reg >= 0)
		++fcount[reg];
	return reg;
}

static int
mtrr_file_del(unsigned long base, unsigned long size,
	      struct file *file, int page)
{
	unsigned int *fcount = FILE_FCOUNT(file);
	int reg;

	if (!page) {
		if ((base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
			return -EINVAL;
		base >>= PAGE_SHIFT;
		size >>= PAGE_SHIFT;
	}
	reg = mtrr_del_page(-1, base, size);
	if (reg < 0)
		return reg;
	if (fcount == NULL)
		return reg;
	if (fcount[reg] < 1)
		return -EINVAL;
	--fcount[reg];
	return reg;
}

/*
 * seq_file can seek but we ignore it.
 *
 * Format of control line:
 *    "base=%Lx size=%Lx type=%s" or "disable=%d"
 */
static ssize_t
mtrr_write(struct file *file, char *buf, size_t len, loff_t * ppos)
{
	int i, err;
	unsigned long reg;
	unsigned long long base, size;
	char *ptr;
	char line[LINE_SIZE];
	int length;

	memset(line, 0, LINE_SIZE);

	len = min_t(size_t, len, LINE_SIZE - 1);
	length = strnlen(buf, len);
	memcpy(line, buf, length);

	ptr = line + length - 1;
	if (length && *ptr == '\n')
		*ptr = '\0';

	if (!strncmp(line, "disable=", 8)) {
		reg = simple_strtoul(line + 8, &ptr, 0);
		err = mtrr_del_page(reg, 0, 0);
		if (err < 0)
			return err;
		return len;
	}

	if (strncmp(line, "base=", 5))
		return -EINVAL;

	base = simple_strtoull(line + 5, &ptr, 0);
	ptr = skip_spaces(ptr);

	if (strncmp(ptr, "size=", 5))
		return -EINVAL;

	size = simple_strtoull(ptr + 5, &ptr, 0);
	if ((base & 0xfff) || (size & 0xfff))
		return -EINVAL;
	ptr = skip_spaces(ptr);

	if (strncmp(ptr, "type=", 5))
		return -EINVAL;
	ptr = skip_spaces(ptr + 5);

	i = match_string(mtrr_strings, MTRR_NUM_TYPES, ptr);
	if (i < 0)
		return i;

	base >>= PAGE_SHIFT;
	size >>= PAGE_SHIFT;
	err = mtrr_add_page((unsigned long)base, (unsigned long)size, i, true);
	if (err < 0)
		return err;
	return len;
}

static long
mtrr_ioctl(struct file *file, unsigned int cmd, void *arg)
{
	int err = 0;
	mtrr_type type;
	unsigned long base;
	unsigned long size;
	struct mtrr_sentry sentry;
	struct mtrr_gentry gentry;

	memset(&gentry, 0, sizeof(gentry));

	switch (cmd) {
	case MTRRIOC_ADD_ENTRY:
	case MTRRIOC_SET_ENTRY:
	case MTRRIOC_DEL_ENTRY:
	case MTRRIOC_KILL_ENTRY:
	case MTRRIOC_ADD_PAGE_ENTRY:
	case MTRRIOC_SET_PAGE_ENTRY:
	case MTRRIOC_DEL_PAGE_ENTRY:
	case MTRRIOC_KILL_PAGE_ENTRY:
		memcpy(&sentry, arg, sizeof(sentry));
		break;
	case MTRRIOC_GET_ENTRY:
	case MTRRIOC_GET_PAGE_ENTRY:
		memcpy(&gentry, arg, sizeof(gentry));
		break;
#ifdef CONFIG_COMPAT
	case MTRRIOC32_ADD_ENTRY:
	case MTRRIOC32_SET_ENTRY:
	case MTRRIOC32_DEL_ENTRY:
	case MTRRIOC32_KILL_ENTRY:
	case MTRRIOC32_ADD_PAGE_ENTRY:
	case MTRRIOC32_SET_PAGE_ENTRY:
	case MTRRIOC32_DEL_PAGE_ENTRY:
	case MTRRIOC32_KILL_PAGE_ENTRY: {
		struct mtrr_sentry32 *s32 = arg;

		sentry.base = s32->base;
		sentry.size = s32->size;
		sentry.type = s32->type;
		break;
	}
	case MTRRIOC32_GET_ENTRY:
	case MTRRIOC32_GET_PAGE_ENTRY: {
		struct mtrr_gentry32 *g32 = arg;

		gentry.regnum = g32->regnum;
		gentry.base = g32->base;
		gentry.size = g32->size;
		gentry.type = g32->type;
		break;
	}
#endif
	}

	switch (cmd) {
	default:
		return -ENOTTY;
	case MTRRIOC_ADD_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_ADD_ENTRY:
#endif
		err =
		    mtrr_file_add(sentry.base, sentry.size, sentry.type, true,
				  file, 0);
		break;
	case MTRRIOC_SET_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_SET_ENTRY:
#endif
		err = mtrr_add(sentry.base, sentry.size, sentry.type, false);
		break;
	case MTRRIOC_DEL_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_DEL_ENTRY:
#endif
		err = mtrr_file_del(sentry.base, sentry.size, file, 0);
		break;
	case MTRRIOC_KILL_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_KILL_ENTRY:
#endif
		err = mtrr_del(-1, sentry.base, sentry.size);
		break;
	case MTRRIOC_GET_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_GET_ENTRY:
#endif
		if (gentry.regnum >= num_var_ranges)
			return -EINVAL;
		mtrr_if->get(gentry.regnum, &base, &size, &type);

		/* Hide entries that go above 4GB */
		if (base + size - 1 >= (1UL << (8 * sizeof(gentry.size) - PAGE_SHIFT))
		    || size >= (1UL << (8 * sizeof(gentry.size) - PAGE_SHIFT)))
			gentry.base = gentry.size = gentry.type = 0;
		else {
			gentry.base = base << PAGE_SHIFT;
			gentry.size = size << PAGE_SHIFT;
			gentry.type = type;
		}

		break;
	case MTRRIOC_ADD_PAGE_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_ADD_PAGE_ENTRY:
#endif
		err =
		    mtrr_file_add(sentry.base, sentry.size, sentry.type, true,
				  file, 1);
		break;
	case MTRRIOC_SET_PAGE_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_SET_PAGE_ENTRY:
#endif
		err =
		    mtrr_add_page(sentry.base, sentry.size, sentry.type, false);
		break;
	case MTRRIOC_DEL_PAGE_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_DEL_PAGE_ENTRY:
#endif
		err = mtrr_file_del(sentry.base, sentry.size, file, 1);
		break;
	case MTRRIOC_KILL_PAGE_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_KILL_PAGE_ENTRY:
#endif
		err = mtrr_del_page(-1, sentry.base, sentry.size);
		break;
	case MTRRIOC_GET_PAGE_ENTRY:
#ifdef CONFIG_COMPAT
	case MTRRIOC32_GET_PAGE_ENTRY:
#endif
		if (gentry.regnum >= num_var_ranges)
			return -EINVAL;
		mtrr_if->get(gentry.regnum, &base, &size, &type);
		/* Hide entries that would overflow */
		if (size != (__typeof__(gentry.size))size)
			gentry.base = gentry.size = gentry.type = 0;
		else {
			gentry.base = base;
			gentry.size = size;
			gentry.type = type;
		}
		break;
	}

	if (err)
		return err;

	switch (cmd) {
	case MTRRIOC_GET_ENTRY:
	case MTRRIOC_GET_PAGE_ENTRY:
		memcpy(arg, &gentry, sizeof(gentry));
		break;
#ifdef CONFIG_COMPAT
	case MTRRIOC32_GET_ENTRY:
	case MTRRIOC32_GET_PAGE_ENTRY: {
		struct mtrr_gentry32 *g32 = arg;

		g32->base = gentry.base;
		g32->size = gentry.size;
		g32->regnum = gentry.regnum;
		g32->type = gentry.type;
		break;
	}
#endif
	}
	return err;
}

static int mtrr_close(struct inode *ino, struct file *file)
{
	unsigned int *fcount = FILE_FCOUNT(file);
	int i, max;

	if (fcount != NULL) {
		max = num_var_ranges;
		for (i = 0; i < max; ++i) {
			while (fcount[i] > 0) {
				mtrr_del(i, 0, 0);
				--fcount[i];
			}
		}
		kfree(fcount);
		FILE_FCOUNT(file) = NULL;
	}
	return 0;
}

static int mtrr_seq_show(struct seq_file *seq, void *offset)
{
	char factor;
	int i, max;
	mtrr_type type;
	unsigned long base, size;

	max = num_var_ranges;
	for (i = 0; i < max; i++) {
		mtrr_if->get(i, &base, &size, &type);
		if (size == 0) {
			mtrr_usage_table[i] = 0;
			continue;
		}
		if (size < (0x100000 >> PAGE_SHIFT)) {
			/* less than 1MB */
			factor = 'K';
			size <<= PAGE_SHIFT - 10;
		} else {
			factor = 'M';
			size >>= 20 - PAGE_SHIFT;
		}
		/* Base can be > 32bit */
		seq_printf(seq, "reg%02i: base=0x%06lx000 (%5luMB), size=%5lu%cB, count=%d: %s\n",
			   i, base, base >> (20 - PAGE_SHIFT),
			   size, factor,
			   mtrr_usage_table[i], mtrr_attrib_to_str(type));
	}
	return 0;
}

static int mtrr_open(struct inode *inode, struct file *file)
{
	if (!mtrr_if)
		return -EIO;
	if (!mtrr_if->get)
		return -ENXIO;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

static const struct proc_ioctl_arg mtrr_ioctl_args[] = {
	PROC_IOCTL_IOC(MTRRIOC_ADD_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_SET_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_DEL_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_GET_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_KILL_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_ADD_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_SET_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_DEL_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_GET_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC_KILL_PAGE_ENTRY),
#ifdef CONFIG_COMPAT
	PROC_IOCTL_IOC(MTRRIOC32_ADD_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_SET_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_DEL_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_GET_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_KILL_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_ADD_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_SET_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_DEL_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_GET_PAGE_ENTRY),
	PROC_IOCTL_IOC(MTRRIOC32_KILL_PAGE_ENTRY),
#endif
};

static const struct proc_ops mtrr_proc_ops = {
	.proc_show		= mtrr_seq_show,
	.proc_open		= mtrr_open,
	.proc_write_buf		= mtrr_write,
	.proc_ioctl_buf		= mtrr_ioctl,
	.proc_ioctl_args	= mtrr_ioctl_args,
	.proc_nr_ioctl_args	= ARRAY_SIZE(mtrr_ioctl_args),
	.proc_release		= mtrr_close,
};

static int __init mtrr_if_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if ((!cpu_has(c, X86_FEATURE_MTRR)) &&
	    (!cpu_has(c, X86_FEATURE_K6_MTRR)) &&
	    (!cpu_has(c, X86_FEATURE_CYRIX_ARR)) &&
	    (!cpu_has(c, X86_FEATURE_CENTAUR_MCR)))
		return -ENODEV;

	proc_create("mtrr", S_IWUSR | S_IRUGO, NULL, &mtrr_proc_ops);
	return 0;
}
arch_initcall(mtrr_if_init);
#endif			/*  CONFIG_PROC_FS  */
