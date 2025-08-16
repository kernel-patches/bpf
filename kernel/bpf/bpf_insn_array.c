// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/sort.h>

#define MAX_INSN_ARRAY_ENTRIES 256

struct bpf_insn_array {
	struct bpf_map map;
	struct mutex state_mutex;
	int state;
	long *ips;
	DECLARE_FLEX_ARRAY(struct bpf_insn_ptr, ptrs);
};

enum {
	INSN_ARRAY_STATE_FREE = 0,
	INSN_ARRAY_STATE_INIT,
	INSN_ARRAY_STATE_READY,
};

#define cast_insn_array(MAP_PTR) \
	container_of(MAP_PTR, struct bpf_insn_array, map)

#define INSN_DELETED ((u32)-1)

static inline u32 insn_array_alloc_size(u32 max_entries)
{
	const u32 base_size = sizeof(struct bpf_insn_array);
	const u32 entry_size = sizeof(struct bpf_insn_ptr);

	return base_size + entry_size * max_entries;
}

static int insn_array_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries == 0 ||
	    attr->key_size != 4 ||
	    attr->value_size != 8 ||
	    attr->map_flags != 0)
		return -EINVAL;

	if (attr->max_entries > MAX_INSN_ARRAY_ENTRIES)
		return -E2BIG;

	return 0;
}

static void insn_array_free(struct bpf_map *map)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);

	kfree(insn_array->ips);
	bpf_map_area_free(insn_array);
}

static struct bpf_map *insn_array_alloc(union bpf_attr *attr)
{
	u64 size = insn_array_alloc_size(attr->max_entries);
	struct bpf_insn_array *insn_array;

	insn_array = bpf_map_area_alloc(size, NUMA_NO_NODE);
	if (!insn_array)
		return ERR_PTR(-ENOMEM);

	insn_array->ips = kcalloc(attr->max_entries, sizeof(long), GFP_KERNEL);
	if (!insn_array->ips) {
		insn_array_free(&insn_array->map);
		return ERR_PTR(-ENOMEM);
	}

	bpf_map_init_from_attr(&insn_array->map, attr);

	mutex_init(&insn_array->state_mutex);
	insn_array->state = INSN_ARRAY_STATE_FREE;

	return &insn_array->map;
}

static int insn_array_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= insn_array->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == insn_array->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

static void *insn_array_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= insn_array->map.max_entries))
		return NULL;

	return &insn_array->ptrs[index].user_value;
}

static long insn_array_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	u32 index = *(u32 *)key;
	struct bpf_insn_array_value val = {};
	guard(mutex)(&insn_array->state_mutex);

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		return -EINVAL;

	if (unlikely(index >= insn_array->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags & BPF_NOEXIST))
		return -EEXIST;

	/* No updates for maps in use */
	if (insn_array->state != INSN_ARRAY_STATE_FREE)
		return -EBUSY;

	copy_map_value(map, &val, value);
	if (val.jitted_off || val.xlated_off == INSN_DELETED)
		return -EINVAL;

	insn_array->ptrs[index].orig_xlated_off = val.xlated_off;
	insn_array->ptrs[index].user_value.xlated_off = val.xlated_off;

	return 0;
}

static long insn_array_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

static int insn_array_check_btf(const struct bpf_map *map,
			      const struct btf *btf,
			      const struct btf_type *key_type,
			      const struct btf_type *value_type)
{
	if (!btf_type_is_i32(key_type))
		return -EINVAL;

	if (!btf_type_is_i64(value_type))
		return -EINVAL;

	return 0;
}

static u64 insn_array_mem_usage(const struct bpf_map *map)
{
	u64 extra_size = 0;

	extra_size += sizeof(long) * map->max_entries; /* insn_array->ips */

	return insn_array_alloc_size(map->max_entries) + extra_size;
}

BTF_ID_LIST_SINGLE(insn_array_btf_ids, struct, bpf_insn_array)

const struct bpf_map_ops insn_array_map_ops = {
	.map_alloc_check = insn_array_alloc_check,
	.map_alloc = insn_array_alloc,
	.map_free = insn_array_free,
	.map_get_next_key = insn_array_get_next_key,
	.map_lookup_elem = insn_array_lookup_elem,
	.map_update_elem = insn_array_update_elem,
	.map_delete_elem = insn_array_delete_elem,
	.map_check_btf = insn_array_check_btf,
	.map_mem_usage = insn_array_mem_usage,
	.map_btf_id = &insn_array_btf_ids[0],
};

static bool is_insn_array(const struct bpf_map *map)
{
	return map->map_type == BPF_MAP_TYPE_INSN_ARRAY;
}

static inline bool valid_offsets(const struct bpf_insn_array *insn_array,
				 const struct bpf_prog *prog)
{
	u32 off;
	int i;

	for (i = 0; i < insn_array->map.max_entries; i++) {
		off = insn_array->ptrs[i].orig_xlated_off;

		if (off >= prog->len)
			return false;

		if (off > 0) {
			if (prog->insnsi[off-1].code == (BPF_LD | BPF_DW | BPF_IMM))
				return false;
		}
	}

	return true;
}

int bpf_insn_array_init(struct bpf_map *map, const struct bpf_prog *prog)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	int i;

	if (!valid_offsets(insn_array, prog))
		return -EINVAL;

	/*
	 * There can be only one program using the map
	 */
	mutex_lock(&insn_array->state_mutex);
	if (insn_array->state != INSN_ARRAY_STATE_FREE) {
		mutex_unlock(&insn_array->state_mutex);
		return -EBUSY;
	}
	insn_array->state = INSN_ARRAY_STATE_INIT;
	mutex_unlock(&insn_array->state_mutex);

	/*
	 * Reset all the map indexes to the original values.  This is needed,
	 * e.g., when a replay of verification with different log level should
	 * be performed.
	 */
	for (i = 0; i < map->max_entries; i++)
		insn_array->ptrs[i].user_value.xlated_off = insn_array->ptrs[i].orig_xlated_off;

	return 0;
}

int bpf_insn_array_ready(struct bpf_map *map)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	guard(mutex)(&insn_array->state_mutex);
	int i;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_array->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		if (!insn_array->ips[i]) {
			/*
			 * Set the map free on failure; the program owning it
			 * might be re-loaded with different log level
			 */
			insn_array->state = INSN_ARRAY_STATE_FREE;
			return -EFAULT;
		}
	}

	insn_array->state = INSN_ARRAY_STATE_READY;
	return 0;
}

void bpf_insn_array_release(struct bpf_map *map)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	guard(mutex)(&insn_array->state_mutex);

	insn_array->state = INSN_ARRAY_STATE_FREE;
}

void bpf_insn_array_adjust(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	int i;

	if (len <= 1)
		return;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_array->ptrs[i].user_value.xlated_off <= off)
			continue;
		if (insn_array->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		insn_array->ptrs[i].user_value.xlated_off += len - 1;
	}
}

void bpf_insn_array_adjust_after_remove(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_array *insn_array = cast_insn_array(map);
	int i;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_array->ptrs[i].user_value.xlated_off < off)
			continue;
		if (insn_array->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		if (insn_array->ptrs[i].user_value.xlated_off >= off &&
		    insn_array->ptrs[i].user_value.xlated_off < off + len)
			insn_array->ptrs[i].user_value.xlated_off = INSN_DELETED;
		else
			insn_array->ptrs[i].user_value.xlated_off -= len;
	}
}

void bpf_prog_update_insn_ptr(struct bpf_prog *prog,
			      u32 xlated_off,
			      u32 jitted_off,
			      void *jitted_ip)
{
	struct bpf_insn_array *insn_array;
	struct bpf_map *map;
	int i, j;

	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		map = prog->aux->used_maps[i];
		if (!is_insn_array(map))
			continue;

		insn_array = cast_insn_array(map);
		for (j = 0; j < map->max_entries; j++) {
			if (insn_array->ptrs[j].user_value.xlated_off == xlated_off) {
				insn_array->ips[j] = (long)jitted_ip;
				insn_array->ptrs[j].jitted_ip = jitted_ip;
				insn_array->ptrs[j].user_value.jitted_off = jitted_off;
			}
		}
	}
}
