/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCAL_LOCK_H
# error "Do not include directly, include linux/local_lock.h"
#endif

#include <linux/percpu-defs.h>
#include <linux/lockdep.h>

#ifndef CONFIG_PREEMPT_RT

typedef struct {
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
	struct task_struct	*owner;
#endif
} local_lock_t;

typedef struct {
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
	struct task_struct	*owner;
#endif
	/*
	 * Same layout as local_lock_t with 'active' field
	 * at the end, since (local_trylock_t *) will be
	 * casted to (local_lock_t *).
	 */
	int active;
} local_trylock_t;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LOCAL_LOCK_DEBUG_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	},						\
	.owner = NULL,

static inline void local_lock_acquire(local_lock_t *l)
{
	lock_map_acquire(&l->dep_map);
	DEBUG_LOCKS_WARN_ON(l->owner);
	l->owner = current;
}

static inline void local_trylock_acquire(local_lock_t *l)
{
	lock_map_acquire_try(&l->dep_map);
	DEBUG_LOCKS_WARN_ON(l->owner);
	l->owner = current;
}

static inline void local_lock_release(local_lock_t *l)
{
	DEBUG_LOCKS_WARN_ON(l->owner != current);
	l->owner = NULL;
	lock_map_release(&l->dep_map);
}

static inline void local_lock_debug_init(local_lock_t *l)
{
	l->owner = NULL;
}
#else /* CONFIG_DEBUG_LOCK_ALLOC */
# define LOCAL_LOCK_DEBUG_INIT(lockname)
static inline void local_lock_acquire(local_lock_t *l) { }
static inline void local_trylock_acquire(local_lock_t *l) { }
static inline void local_lock_release(local_lock_t *l) { }
static inline void local_lock_debug_init(local_lock_t *l) { }
#endif /* !CONFIG_DEBUG_LOCK_ALLOC */

#define INIT_LOCAL_LOCK(lockname)	{ LOCAL_LOCK_DEBUG_INIT(lockname) }

#define __local_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));\
	lockdep_init_map_type(&(lock)->dep_map, #lock, &__key,  \
			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
			      LD_LOCK_PERCPU);			\
	local_lock_debug_init(lock);				\
} while (0)

#define __spinlock_nested_bh_init(lock)				\
do {								\
	static struct lock_class_key __key;			\
								\
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));\
	lockdep_init_map_type(&(lock)->dep_map, #lock, &__key,  \
			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
			      LD_LOCK_NORMAL);			\
	local_lock_debug_init(lock);				\
} while (0)

#define __local_lock(lock)					\
	do {							\
		preempt_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)

#define __local_lock_irq(lock)					\
	do {							\
		local_irq_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)

#define __local_lock_irqsave(lock, flags)			\
	do {							\
		local_trylock_t *tl;				\
		local_lock_t *l;				\
		local_irq_save(flags);				\
		l = (local_lock_t *)this_cpu_ptr(lock);		\
		tl = (local_trylock_t *)l;			\
		_Generic((lock),				\
			local_trylock_t *: ({			\
				lockdep_assert(tl->active == 0);\
				WRITE_ONCE(tl->active, 1);	\
			}),					\
			default:(void)0);			\
		local_lock_acquire(l);				\
	} while (0)


#define __local_trylock_irqsave(lock, flags)			\
	({							\
		local_trylock_t *tl;				\
		local_irq_save(flags);				\
		tl = this_cpu_ptr(lock);			\
		if (READ_ONCE(tl->active) == 1) {		\
			local_irq_restore(flags);		\
			tl = NULL;				\
		} else {					\
			WRITE_ONCE(tl->active, 1);		\
			local_trylock_acquire(			\
				(local_lock_t *)tl);		\
		}						\
		!!tl;						\
	})

#define __local_unlock(lock)					\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		preempt_enable();				\
	} while (0)

#define __local_unlock_irq(lock)				\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		local_irq_enable();				\
	} while (0)

#define __local_unlock_irqrestore(lock, flags)			\
	do {							\
		local_trylock_t *tl;				\
		local_lock_t *l;				\
		l = (local_lock_t *)this_cpu_ptr(lock);		\
		tl = (local_trylock_t *)l;			\
		_Generic((lock),				\
			local_trylock_t *: ({			\
				lockdep_assert(tl->active == 1);\
				WRITE_ONCE(tl->active, 0);	\
			}),					\
			default:(void)0);			\
		local_lock_release(l);				\
		local_irq_restore(flags);			\
	} while (0)

#define __local_lock_nested_bh(lock)				\
	do {							\
		lockdep_assert_in_softirq();			\
		local_lock_acquire(this_cpu_ptr(lock));	\
	} while (0)

#define __local_unlock_nested_bh(lock)				\
	local_lock_release(this_cpu_ptr(lock))

#else /* !CONFIG_PREEMPT_RT */

/*
 * On PREEMPT_RT local_lock maps to a per CPU spinlock, which protects the
 * critical section while staying preemptible.
 */
typedef spinlock_t local_lock_t;
typedef spinlock_t local_trylock_t;

#define INIT_LOCAL_LOCK(lockname) __LOCAL_SPIN_LOCK_UNLOCKED((lockname))

#define __local_lock_init(l)					\
	do {							\
		local_spin_lock_init((l));			\
	} while (0)

#define __local_lock(__lock)					\
	do {							\
		migrate_disable();				\
		spin_lock(this_cpu_ptr((__lock)));		\
	} while (0)

#define __local_lock_irq(lock)			__local_lock(lock)

#define __local_lock_irqsave(lock, flags)			\
	do {							\
		typecheck(unsigned long, flags);		\
		flags = 0;					\
		__local_lock(lock);				\
	} while (0)

#define __local_trylock_irqsave(lock, flags)			\
	({							\
		__label__ out;					\
		int ret = 0;					\
		typecheck(unsigned long, flags);		\
		flags = 0;					\
		if (in_nmi() || in_hardirq())			\
			goto out;				\
		migrate_disable();				\
		ret = spin_trylock(this_cpu_ptr((lock)));	\
		if (!ret)					\
			migrate_enable();			\
	out:							\
		ret;						\
	})

#define __local_unlock(__lock)					\
	do {							\
		spin_unlock(this_cpu_ptr((__lock)));		\
		migrate_enable();				\
	} while (0)

#define __local_unlock_irq(lock)		__local_unlock(lock)

#define __local_unlock_irqrestore(lock, flags)	__local_unlock(lock)

#define __local_lock_nested_bh(lock)				\
do {								\
	lockdep_assert_in_softirq_func();			\
	spin_lock(this_cpu_ptr(lock));				\
} while (0)

#define __local_unlock_nested_bh(lock)				\
do {								\
	spin_unlock(this_cpu_ptr((lock)));			\
} while (0)

#endif /* CONFIG_PREEMPT_RT */
