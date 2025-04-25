#include <errno.h>
#include <bpf/bpf_helpers.h>

#include "task_local_data_common.h"

#define PAGE_IDX_MASK 0x8000

/* Overview
 *
 * Task local data (TLD) allows sharing per-task information between users and
 * bpf programs without explicit storage layout managenent. TLD APIs use to
 * string keys to access data. Internally, TLD shares user pages throguh two
 * UPTRs in a task local storage: udata and umetadata. Data are stored in udata.
 * Keys and the offsets of the corresponding data in udata are stored in umetadata.
 *
 * Usage
 *
 * Users should initialize every task local data once for every new task before
 * using them with bpf_tld_init_var(). It should be done ideally in non-critical
 * paths first (e.g., sched_ext_ops::init_task) as it compare key strings and
 * cache the offsets of data.
 *
 * First, user should define struct task_local_data_offsets, which will be used
 * to cache the offsets of task local data. Each member of the struct should
 * be a short integer with name same as the key name defined in the user space.
 * Another task local storage map will be created to save the offsets. For example:
 *
 * struct task_local_data_offsets {
 *     short priority;
 *     short in_critical_section;
 * };
 *
 * Task local data APIs take a pointer to bpf_task_local_data object as the first
 * argument. The object should be declared as a stack variable and initialized via
 * bpf_tld_init(). Then, in a bpf program, to cache the offset for a key-value pair,
 * call bpf_tld_init_var(). For example, in init_task program:
 *
 *     struct bpf_task_local_data tld;
 *
 *     err = bpf_tld_init(task, &tld);
 *     if (err)
 *         return 0;
 *
 *     bpf_tld_init_var(&tld, priority);
 *     bpf_tld_init_var(&tld, in_critical_section);
 *
 * Subsequently and in other bpf programs, to lookup task local data, call
 * bpf_tld_lookup(). For example:
 *
 *     int *p;
 *
 *     p = bpf_tld_lookup(&tld, priority, sizeof(int));
 *     if (p)
 *         // do something depending on *p
 */

struct task_local_data_offsets;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_local_data_map_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} task_local_data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_local_data_offsets);
} task_local_data_off_map SEC(".maps");

struct bpf_task_local_data {
	struct task_local_data_map_value *data_map;
	struct task_local_data_offsets *off_map;
};

/**
 * @brief bpf_tld_init() initializes a bpf_task_local_data object.
 *
 * @param task The task_struct of the target task
 * @param tld A pointer to a bpf_task_local_data object to be initialized
 * @return -EINVAL if task KV store is not initialized by the user space for this task;
 * -ENOMEM if cached offset map creation fails. In both cases, users can abort, or
 * conitnue without calling task KV store APIs as if no key-value pairs are set.
 */
__attribute__((unused))
static int bpf_tld_init(struct task_struct *task, struct bpf_task_local_data *tld)
{
	tld->data_map = bpf_task_storage_get(&task_local_data_map, task, 0, 0);
	if (!tld->data_map)
		return -EINVAL;

	tld->off_map = bpf_task_storage_get(&task_local_data_off_map, task, 0,
					    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tld->off_map)
		return -ENOMEM;

	return 0;
}

/**
 * @brief bpf_tld_init_var() lookups the metadata with a key and caches the offset of
 * the value corresponding to the key.
 *
 * @param tld A pointer to a valid bpf_task_local_data object initialized by bpf_tld_init()
 * @param key The key used to lookup the task KV store. Should be one of the
 * symbols defined in struct task_local_data_offsets, not a string
 */
#define bpf_tld_init_var(tld, key)					\
	({								\
		(tld)->off_map->key = bpf_tld_fetch_off(tld, #key);	\
	})

__attribute__((unused))
static short bpf_tld_fetch_off(struct bpf_task_local_data *tld, const char *key)
{
	int i, umetadata_off, umetadata_cnt, udata_start;
	void *umetadata, *key_i, *off_i;
	short off = 0;

	if (!tld->data_map || !tld->data_map->umetadata)
		goto out;

	udata_start = tld->data_map->udata_start;
	umetadata_cnt = tld->data_map->umetadata_cnt;
	umetadata = tld->data_map->umetadata->meta;

	bpf_for(i, 0, umetadata_cnt) {
		umetadata_off = i * sizeof(struct key_meta);
		if (umetadata_off > PAGE_SIZE - sizeof(struct key_meta))
			break;

		key_i = umetadata + umetadata_off + offsetof(struct key_meta, key);
		off_i = umetadata + umetadata_off + offsetof(struct key_meta, off);

		if (!bpf_strncmp(key_i, TASK_LOCAL_DATA_KEY_LEN, key)) {
			off = *(short *)(off_i) + udata_start;
			if (off >= PAGE_SIZE)
				off = (off - PAGE_SIZE) | PAGE_IDX_MASK;
			/* Shift cached offset by 1 so that 0 means not initialized */
			off += 1;
			break;
		}
	}
out:
	return off;
}

/**
 * @brief bpf_tld_lookup() lookups the task KV store using the cached offset
 * corresponding to the key.
 *
 * @param tld A pointer to a valid bpf_task_local_data object initialized by bpf_tld_init()
 * @param key The key used to lookup the task KV store. Should be one of the
 * symbols defined in struct task_local_data_offsets, not a string
 * @param size The size of the value. Must be a known constant value
 * @return A pointer to the value corresponding to the key; NULL if the offset
 * if not cached or the size is too big
 */
#define bpf_tld_lookup(tld, key, size)	__bpf_tld_lookup(tld, (tld)->off_map->key, size)
__attribute__((unused))
static void *__bpf_tld_lookup(struct bpf_task_local_data *tld, short cached_off, int size)
{
	short page_off, page_idx;

	if (!cached_off--)
		return NULL;

	page_off = cached_off & ~PAGE_IDX_MASK;
	page_idx = !!(cached_off & PAGE_IDX_MASK);

	if (page_idx) {
		return (tld->data_map->udata[1].page && page_off < PAGE_SIZE - size) ?
			(void *)tld->data_map->udata[1].page + page_off : NULL;
	} else {
		return (tld->data_map->udata[0].page && page_off < PAGE_SIZE - size) ?
			(void *)tld->data_map->udata[0].page + page_off : NULL;
	}
}
