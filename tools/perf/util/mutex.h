/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_MUTEX_H
#define __PERF_MUTEX_H

#include <pthread.h>
#include <stdbool.h>
#include <linux/compiler.h>

/*
 * A wrapper around the mutex implementation that allows perf to error check
 * usage, etc.
 */
context_lock_struct(mutex) {
	pthread_mutex_t lock;
};

/*
 * Statically initialized mutex, for the file scope ones. Error checking
 * in !NDEBUG builds, like mutex_init(); the glibc-only errorcheck
 * initializer falls back to the default type elsewhere.
 */
#if !defined(NDEBUG) && defined(PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP)
#define __PERF_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#else
#define __PERF_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif
#define DEFINE_MUTEX(name) struct mutex name = { .lock = __PERF_MUTEX_INITIALIZER }

/*
 * Runs fn() exactly once however many threads race to it, the rest wait
 * for it to finish; per call site state, so multiple sites wanting the
 * same once use a common helper, as in the kernel's DO_ONCE().
 */
#define DO_ONCE(fn, ...)						       \
	({								       \
		static bool ___done;					       \
		static DEFINE_MUTEX(___once_lock);			       \
		bool ___ret = false;					       \
									       \
		if (!__atomic_load_n(&___done, __ATOMIC_ACQUIRE)) {	       \
			mutex_lock(&___once_lock);			       \
			if (!___done) {					       \
				fn(__VA_ARGS__);			       \
				__atomic_store_n(&___done, true,	       \
						 __ATOMIC_RELEASE);	       \
				___ret = true;				       \
			}						       \
			mutex_unlock(&___once_lock);			       \
		}							       \
		___ret;							       \
	})

/* A wrapper around the condition variable implementation. */
struct cond {
	pthread_cond_t cond;
};

/* Default initialize the mtx struct. */
void mutex_init(struct mutex *mtx);
/*
 * Initialize the mtx struct and set the process-shared rather than default
 * process-private attribute.
 */
void mutex_init_pshared(struct mutex *mtx);
/* Initializes a mutex that may be recursively held on the same thread. */
void mutex_init_recursive(struct mutex *mtx);
/*
 * As mutex_init_pshared(), plus the robust attribute: a process dying while
 * holding it doesn't leave it locked, but the takeover isn't reported and the
 * data it protects may be mid update.  Returns false when not available.
 */
bool mutex_init_pshared_robust(struct mutex *mtx);
void mutex_destroy(struct mutex *mtx);

void mutex_lock(struct mutex *mtx) __acquires(mtx);
void mutex_unlock(struct mutex *mtx) __releases(mtx);
/* Tries to acquire the lock and returns true on success. */
bool mutex_trylock(struct mutex *mtx) __cond_acquires(true, mtx);

/* Default initialize the cond struct. */
void cond_init(struct cond *cnd);
/*
 * Initialize the cond struct and specify the process-shared rather than default
 * process-private attribute.
 */
void cond_init_pshared(struct cond *cnd);
void cond_destroy(struct cond *cnd);

void cond_wait(struct cond *cnd, struct mutex *mtx) __must_hold(mtx);
void cond_signal(struct cond *cnd);
void cond_broadcast(struct cond *cnd);

#endif /* __PERF_MUTEX_H */
