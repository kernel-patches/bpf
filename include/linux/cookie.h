/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COOKIE_H
#define __LINUX_COOKIE_H

#include <linux/atomic.h>
#include <linux/percpu.h>

struct gen_cookie {
	u64 __percpu	*local_last;
	atomic64_t	 shared_last ____cacheline_aligned_in_smp;
};

#define COOKIE_LOCAL_BATCH	4096

#define DEFINE_COOKIE(name)					\
	static DEFINE_PER_CPU(u64, __##name);			\
	static struct gen_cookie name = {			\
		.local_last	= &__##name,			\
		.shared_last	= ATOMIC64_INIT(0),		\
	}

static inline u64 gen_cookie_next(struct gen_cookie *gc)
{
	u64 *local_last = &get_cpu_var(*gc->local_last);
	u64 val = *local_last;

	if (__is_defined(CONFIG_SMP) &&
	    unlikely((val & (COOKIE_LOCAL_BATCH - 1)) == 0)) {
		s64 next = atomic64_add_return(COOKIE_LOCAL_BATCH,
					       &gc->shared_last);
		val = next - COOKIE_LOCAL_BATCH;
	}
	val++;
	if (unlikely(!val))
		val++;
	*local_last = val;
	put_cpu_var(local_last);
	return val;
}

#endif /* __LINUX_COOKIE_H */
