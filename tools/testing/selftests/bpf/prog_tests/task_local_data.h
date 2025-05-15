/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TASK_LOCAL_DATA_H
#define __TASK_LOCAL_DATA_H

#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <bpf/bpf.h>

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

#define PAGE_SIZE 4096

#ifndef __round_mask
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#endif
#ifndef round_up
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))
#endif

#define TLD_DATA_SIZE PAGE_SIZE
#define TLD_DATA_CNT 63
#define TLD_NAME_LEN 62

typedef struct {
	__s16 off;
} tld_key_t;

struct tld_metadata {
	char name[TLD_NAME_LEN];
	__u16 size;
};

struct u_tld_metadata {
	__u8 cnt;
	__u8 padding[63];
	struct tld_metadata metadata[TLD_DATA_CNT];
};

struct u_tld_data {
	char data[TLD_DATA_SIZE];
};

struct tld_map_value {
	struct u_tld_data *data;
	struct u_tld_metadata *metadata;
};

struct u_tld_metadata *tld_metadata_p __attribute__((weak));
__thread struct u_tld_data *tld_data_p __attribute__((weak));

static int __tld_init_metadata(int map_fd)
{
	struct u_tld_metadata *new_metadata;
	struct tld_map_value map_val;
	int task_fd = 0, err;

	task_fd = syscall(SYS_pidfd_open, getpid(), 0);
	if (task_fd < 0) {
		err = -errno;
		goto out;
	}

	new_metadata = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!new_metadata) {
		err = -ENOMEM;
		goto out;
	}

	memset(new_metadata, 0, PAGE_SIZE);

	map_val.data = NULL;
	map_val.metadata = new_metadata;

	/*
	 * bpf_map_update_elem(.., pid_fd,..., BPF_NOEXIST) guarantees that
	 * only one tld_create_key() can update tld_metadata_p.
	 */
	err = bpf_map_update_elem(map_fd, &task_fd, &map_val, BPF_NOEXIST);
	if (err) {
		free(new_metadata);
		if (err == -EEXIST || err == -EAGAIN)
			err = 0;
		goto out;
	}

	WRITE_ONCE(tld_metadata_p, new_metadata);
out:
	if (task_fd > 0)
		close(task_fd);
	return err;
}

static int __tld_init_data(int map_fd)
{
	struct u_tld_data *new_data = NULL;
	struct tld_map_value map_val;
	int err, task_fd = 0;

	task_fd = syscall(SYS_pidfd_open, gettid(), PIDFD_THREAD);
	if (task_fd < 0) {
		err = -errno;
		goto out;
	}

	new_data = aligned_alloc(PAGE_SIZE, TLD_DATA_SIZE);
	if (!new_data) {
		err = -ENOMEM;
		goto out;
	}

	map_val.data = new_data;
	map_val.metadata = READ_ONCE(tld_metadata_p);

	err = bpf_map_update_elem(map_fd, &task_fd, &map_val, 0);
	if (err) {
		free(new_data);
		goto out;
	}

	tld_data_p = new_data;
out:
	if (task_fd > 0)
		close(task_fd);
	return err;
}

/**
 * tld_create_key() - Create a key associated with a TLD.
 *
 * @map_fd: A file descriptor of the underlying task local storage map,
 * tld_data_map
 * @name: The name the TLD will be associated with
 * @size: Size of the TLD
 *
 * Returns an opaque object key. Use tld_key_is_err() or tld_key_err_or_zero() to
 * check if the key creation succeed. Pass to tld_get_data() to get a pointer to
 * the TLD. bpf programs can also fetch the same key by name.
 */
__attribute__((unused))
static tld_key_t tld_create_key(int map_fd, const char *name, size_t size)
{
	int err, i, cnt, sz, off = 0;

	if (!READ_ONCE(tld_metadata_p)) {
		err = __tld_init_metadata(map_fd);
		if (err)
			return (tld_key_t) {.off = err};
	}

	if (!tld_data_p) {
		err = __tld_init_data(map_fd);
		if (err)
			return (tld_key_t) {.off = err};
	}

	size = round_up(size, 8);

	for (i = 0; i < TLD_DATA_CNT; i++) {
retry:
		cnt = __atomic_load_n(&tld_metadata_p->cnt, __ATOMIC_RELAXED);
		if (i < cnt) {
			/*
			 * Pending tld_create_key() uses size to signal if the metadata has
			 * been fully updated.
			 */
			while (!(sz = __atomic_load_n(&tld_metadata_p->metadata[i].size,
						      __ATOMIC_ACQUIRE)))
				sched_yield();

			if (!strncmp(tld_metadata_p->metadata[i].name, name, TLD_NAME_LEN))
				return (tld_key_t) {.off = -EEXIST};

			off += sz;
			continue;
		}

		if (off + size > TLD_DATA_SIZE)
			return (tld_key_t) {.off = -E2BIG};

		/*
		 * Only one tld_create_key() can increase the current cnt by one and
		 * takes the latest available slot. Other threads will check again if a new
		 * TLD can still be added, and then compete for the new slot after the
		 * succeeding thread update the size.
		 */
		if (!__atomic_compare_exchange_n(&tld_metadata_p->cnt, &cnt, cnt + 1, true,
						 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			goto retry;

		strncpy(tld_metadata_p->metadata[i].name, name, TLD_NAME_LEN);
		__atomic_store_n(&tld_metadata_p->metadata[i].size, size, __ATOMIC_RELEASE);
		return (tld_key_t) {.off = off};
	}

	return (tld_key_t) {.off = -ENOSPC};
}

__attribute__((unused))
static inline bool tld_key_is_err(tld_key_t key)
{
	return key.off < 0;
}

__attribute__((unused))
static inline int tld_key_err_or_zero(tld_key_t key)
{
	return tld_key_is_err(key) ? key.off : 0;
}

/**
 * tld_get_data() - Gets a pointer to the TLD associated with the key.
 *
 * @map_fd: A file descriptor of the underlying task local storage map,
 * tld_data_map
 * @key: A key object returned by tld_create_key().
 *
 * Returns a pointer to the TLD if the key is valid; NULL if no key has been
 * added, not enough memory for TLD for this thread, or the key is invalid.
 *
 * Threads that call tld_get_data() must call tld_free() on exit to prevent
 * memory leak.
 */
__attribute__((unused))
static void *tld_get_data(int map_fd, tld_key_t key)
{
	if (!READ_ONCE(tld_metadata_p))
		return NULL;

	if (!tld_data_p && __tld_init_data(map_fd))
		return NULL;

	return tld_data_p->data + key.off;
}

/**
 * tld_free() - Frees task local data memory of the calling thread
 */
__attribute__((unused))
static void tld_free(void)
{
	if (tld_data_p)
		free(tld_data_p);
}

#endif /* __TASK_LOCAL_DATA_H */
