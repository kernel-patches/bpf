#ifndef _PERF_RWSEM_H
#define _PERF_RWSEM_H

#include <pthread.h>
#include "mutex.h"

/*
 * Mutexes have additional error checking. Enable to use a mutex rather than a
 * rwlock for debugging.
 */
#define RWS_ERRORCHECK 0

context_lock_struct(rw_semaphore) {
#if RWS_ERRORCHECK
	struct mutex mtx;
#else
	pthread_rwlock_t lock;
#endif
};

int init_rwsem(struct rw_semaphore *sem);
int exit_rwsem(struct rw_semaphore *sem);

int down_read(struct rw_semaphore *sem) __acquires_shared(sem);
int up_read(struct rw_semaphore *sem) __releases_shared(sem);

int down_write(struct rw_semaphore *sem) __acquires(sem);
int up_write(struct rw_semaphore *sem) __releases(sem);

#endif /* _PERF_RWSEM_H */
