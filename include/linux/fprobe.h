/* SPDX-License-Identifier: GPL-2.0 */
/* Simple ftrace probe wrapper */
#ifndef _LINUX_FPROBE_H
#define _LINUX_FPROBE_H

#include <linux/compiler.h>
#include <linux/ftrace.h>
#include <linux/rethook.h>

struct fprobe {
	const char		**syms;
	unsigned long		*addrs;
	unsigned int		nentry;

	struct ftrace_ops	ftrace;
	unsigned long		nmissed;
	unsigned int		flags;
	struct rethook		*rethook;

	void (*entry_handler)(struct fprobe *fp, unsigned long entry_ip, struct pt_regs *regs);
	void (*exit_handler)(struct fprobe *fp, unsigned long entry_ip, struct pt_regs *regs);
};

#define FPROBE_FL_DISABLED	1

static inline bool fprobe_disabled(struct fprobe *fp)
{
	return (fp) ? fp->flags & FPROBE_FL_DISABLED : false;
}

#ifdef CONFIG_FPROBE
int register_fprobe(struct fprobe *fp);
int unregister_fprobe(struct fprobe *fp);
#else
static inline int register_fprobe(struct fprobe *fp)
{
	return -EOPNOTSUPP;
}
static inline int unregister_fprobe(struct fprobe *fp)
{
	return -EOPNOTSUPP;
}
#endif

static inline void disable_fprobe(struct fprobe *fp)
{
	if (fp)
		fp->flags |= FPROBE_FL_DISABLED;
}

static inline void enable_fprobe(struct fprobe *fp)
{
	if (fp)
		fp->flags &= ~FPROBE_FL_DISABLED;
}

#endif
