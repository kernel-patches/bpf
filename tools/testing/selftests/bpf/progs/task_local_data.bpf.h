/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TASK_LOCAL_DATA_BPF_H
#define __TASK_LOCAL_DATA_BPF_H

/*
 * Task local data is a library that facilitates sharing per-task data
 * between user space and bpf programs.
 *
 *
 * PREREQUISITE
 *
 * A TLD, an entry of data in task local data, first needs to be created by the
 * user space. This is done by calling user space API, tld_create_key(), with
 * the name of the TLD and the size.
 *
 *     tld_key_t prio, in_cs;
 *
 *     prio = tld_create_key("priority", sizeof(int));
 *     in_cs = tld_create_key("in_critical_section", sizeof(bool));
 *
 * A key associated with the TLD, which has an opaque type tld_key_t, will be
 * returned. It can be used to get a pointer to the TLD in the user space by
 * calling tld_get_data().
 *
 *
 * USAGE
 *
 * Similar to user space, bpf programs locate a TLD using the same key.
 * tld_fetch_key() allows bpf programs to retrieve a key created in the user
 * space by name, which is specified in the second argument of tld_create_key().
 * tld_fetch_key() additionally will cache the key in a task local storage map,
 * tld_key_map, to avoid performing costly string comparisons every time when
 * accessing a TLD. This requires the developer to define the map value type of
 * tld_key_map, struct tld_keys. It only needs to contain keys used by bpf
 * programs in the compilation unit.
 *
 * struct tld_keys {
 *     tld_key_t prio;
 *     tld_key_t in_cs;
 * };
 *
 * Then, for every new task, a bpf program will fetch and cache keys once and
 * for all. This should be done ideally in a non-critical path (e.g., in
 * sched_ext_ops::init_task).
 *
 *     struct tld_object tld_obj;
 *
 *     err = tld_object_init(task, &tld);
 *     if (err)
 *         return 0;
 *
 *     tld_fetch_key(&tld_obj, "priority", prio);
 *     tld_fetch_key(&tld_obj, "in_critical_section", in_cs);
 *
 * Note that, the first argument of tld_fetch_key() is a pointer to tld_object.
 * It should be declared as a stack variable and initialized via tld_object_init().
 *
 * Finally, just like user space programs, bpf programs can get a pointer to a
 * TLD by calling tld_get_data(), with cached keys.
 *
 *     int *p;
 *
 *     p = tld_get_data(&tld_obj, prio, sizeof(int));
 *     if (p)
 *         // do something depending on *p
 */
#include <errno.h>
#include <bpf/bpf_helpers.h>

#define TLD_DATA_SIZE __PAGE_SIZE
#define TLD_DATA_CNT 63
#define TLD_NAME_LEN 62

typedef struct {
	__s16 off;
} tld_key_t;

struct u_tld_data *dummy_data;
struct u_tld_metadata *dummy_metadata;

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
	struct u_tld_data __uptr *data;
	struct u_tld_metadata __uptr *metadata;
};

struct tld_object {
	struct tld_map_value *data_map;
	struct tld_keys *key_map;
};

/*
 * Map value of tld_key_map for caching keys. Must be defined by the developer.
 * Members should be tld_key_t and passed to the 3rd argument of tld_fetch_key().
 */
struct tld_keys;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tld_map_value);
} tld_data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tld_keys);
} tld_key_map SEC(".maps");

/**
 * tld_object_init() - Initializes a tld_object.
 *
 * @task: The task_struct of the target task
 * @tld_obj: A pointer to a tld_object to be initialized
 *
 * Returns 0 on success; -ENODATA if the task has no TLD; -ENOMEM if the creation
 * of tld_key_map fails
 */
__attribute__((unused))
static int tld_object_init(struct task_struct *task, struct tld_object *tld_obj)
{
	tld_obj->data_map = bpf_task_storage_get(&tld_data_map, task, 0, 0);
	if (!tld_obj->data_map)
		return -ENODATA;

	tld_obj->key_map = bpf_task_storage_get(&tld_key_map, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tld_obj->key_map)
		return -ENOMEM;

	return 0;
}

/**
 * tld_fetch_key() - Fetches the key to a TLD by name. The key has to be created
 * by user space first with tld_create_key().
 *
 * @tld_obj: A pointer to a valid tld_object initialized by tld_object_init()
 * @name: The name of the key associated with a TLD
 * @key: The key in struct tld_keys to be saved to
 *
 * Returns a positive integer on success; 0 otherwise
 */
#define tld_fetch_key(tld_obj, name, key)					\
	({									\
		(tld_obj)->key_map->key.off = __tld_fetch_key(tld_obj, name);	\
	})

__attribute__((unused))
static u16 __tld_fetch_key(struct tld_object *tld_obj, const char *name)
{
	int i, meta_off, cnt;
	void *metadata, *nm, *sz;
	u16 off = 0;

	if (!tld_obj->data_map || !tld_obj->data_map->metadata)
		return 0;

	cnt = tld_obj->data_map->metadata->cnt;
	metadata = tld_obj->data_map->metadata->metadata;

	bpf_for(i, 0, cnt) {
		meta_off = i * sizeof(struct tld_metadata);
		if (meta_off > TLD_DATA_SIZE - offsetof(struct u_tld_metadata, metadata)
					   - sizeof(struct tld_metadata))
			break;

		nm = metadata + meta_off + offsetof(struct tld_metadata, name);
		sz = metadata + meta_off + offsetof(struct tld_metadata, size);

		/*
		 * Reserve 0 for uninitialized keys. Increase the offset of a valid key
		 * by one and subtract it later in tld_get_data().
		 */
		if (!bpf_strncmp(nm, TLD_NAME_LEN, name))
			return off + 1;

		off += *(u16 *)sz;
	}

	return 0;
}

/**
 * tld_get_data() - Retrieves a pointer to the TLD associated with the key.
 *
 * @tld_obj: A pointer to a valid tld_object initialized by tld_object_init()
 * @key: The key of a TLD saved in tld_maps
 * @size: The size of the TLD. Must be a known constant value
 *
 * Returns a pointer to the TLD data associated with the key; NULL if the key
 * is not valid or the size is too big
 */
#define tld_get_data(tld_obj, key, size) \
	__tld_get_data(tld_obj, (tld_obj)->key_map->key.off - 1, size)

__attribute__((unused))
__always_inline void *__tld_get_data(struct tld_object *tld_obj, u32 off, u32 size)
{
	return (tld_obj->data_map->data && off >= 0 && off < TLD_DATA_SIZE - size) ?
		(void *)tld_obj->data_map->data + off : NULL;
}

#endif
