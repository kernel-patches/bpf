// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>

#define MAX_ISET_ENTRIES 128

struct bpf_insn_set {
	struct bpf_map map;
	struct mutex state_mutex;
	int state;
	DECLARE_FLEX_ARRAY(struct bpf_insn_ptr, ptrs);
};

enum {
	INSN_SET_STATE_FREE = 0,
	INSN_SET_STATE_INIT,
	INSN_SET_STATE_READY,
};

#define cast_insn_set(MAP_PTR) \
	container_of(MAP_PTR, struct bpf_insn_set, map)

static inline u32 insn_set_alloc_size(u32 max_entries)
{
	const u32 base_size = sizeof(struct bpf_insn_set);
	const u32 entry_size = sizeof(struct bpf_insn_ptr);

	return base_size + entry_size * max_entries;
}

static int insn_set_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries == 0 ||
	    attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags != 0)
		return -EINVAL;

	if (attr->max_entries > MAX_ISET_ENTRIES)
		return -E2BIG;

	return 0;
}

static struct bpf_map *insn_set_alloc(union bpf_attr *attr)
{
	u64 size = insn_set_alloc_size(attr->max_entries);
	struct bpf_insn_set *insn_set;

	insn_set = bpf_map_area_alloc(size, NUMA_NO_NODE);
	if (!insn_set)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&insn_set->map, attr);

	mutex_init(&insn_set->state_mutex);
	insn_set->state = INSN_SET_STATE_FREE;

	return &insn_set->map;
}

static int insn_set_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= insn_set->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == insn_set->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

static void *insn_set_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= insn_set->map.max_entries))
		return NULL;

	return &insn_set->ptrs[index].xlated_off;
}

static long insn_set_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	u32 index = *(u32 *)key;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		return -EINVAL;

	if (unlikely(index >= insn_set->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags & BPF_NOEXIST))
		return -EEXIST;

	copy_map_value(map, &insn_set->ptrs[index].orig_xlated_off, value);
	insn_set->ptrs[index].xlated_off = insn_set->ptrs[index].orig_xlated_off;

	return 0;
}

static long insn_set_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

static int insn_set_check_btf(const struct bpf_map *map,
			      const struct btf *btf,
			      const struct btf_type *key_type,
			      const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	if (BTF_INFO_KIND(value_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	int_data = *(u32 *)(value_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

static void insn_set_free(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	bpf_map_area_free(insn_set);
}

static u64 insn_set_mem_usage(const struct bpf_map *map)
{
	return insn_set_alloc_size(map->max_entries);
}

BTF_ID_LIST_SINGLE(insn_set_btf_ids, struct, bpf_insn_set)

const struct bpf_map_ops insn_set_map_ops = {
	.map_alloc_check = insn_set_alloc_check,
	.map_alloc = insn_set_alloc,
	.map_free = insn_set_free,
	.map_get_next_key = insn_set_get_next_key,
	.map_lookup_elem = insn_set_lookup_elem,
	.map_update_elem = insn_set_update_elem,
	.map_delete_elem = insn_set_delete_elem,
	.map_check_btf = insn_set_check_btf,
	.map_mem_usage = insn_set_mem_usage,
	.map_btf_id = &insn_set_btf_ids[0],
};

static inline bool is_frozen(struct bpf_map *map)
{
	bool ret = true;

	mutex_lock(&map->freeze_mutex);
	if (!map->frozen)
		ret = false;
	mutex_unlock(&map->freeze_mutex);

	return ret;
}

static inline bool valid_offsets(const struct bpf_insn_set *insn_set,
				 const struct bpf_prog *prog)
{
	u32 off, prev_off;
	int i;

	for (i = 0; i < insn_set->map.max_entries; i++) {
		off = insn_set->ptrs[i].orig_xlated_off;

		if (off >= prog->len)
			return false;

		if (off > 0) {
			if (prog->insnsi[off-1].code == (BPF_LD | BPF_DW | BPF_IMM))
				return false;
		}

		if (i > 0) {
			prev_off = insn_set->ptrs[i-1].orig_xlated_off;
			if (off <= prev_off)
				return false;
		}
	}

	return true;
}

int bpf_insn_set_init(struct bpf_map *map, const struct bpf_prog *prog)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	if (!is_frozen(map))
		return -EINVAL;

	if (!valid_offsets(insn_set, prog))
		return -EINVAL;

	/*
	 * There can be only one program using the map
	 */
	mutex_lock(&insn_set->state_mutex);
	if (insn_set->state != INSN_SET_STATE_FREE) {
		mutex_unlock(&insn_set->state_mutex);
		return -EBUSY;
	}
	insn_set->state = INSN_SET_STATE_INIT;
	mutex_unlock(&insn_set->state_mutex);

	/*
	 * Reset all the map indexes to the original values.  This is needed,
	 * e.g., when a replay of verification with different log level should
	 * be performed.
	 */
	for (i = 0; i < map->max_entries; i++)
		insn_set->ptrs[i].xlated_off = insn_set->ptrs[i].orig_xlated_off;

	return 0;
}

void bpf_insn_set_ready(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	insn_set->state = INSN_SET_STATE_READY;
}

void bpf_insn_set_release(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	insn_set->state = INSN_SET_STATE_FREE;
}

#define INSN_DELETED ((u32)-1)

void bpf_insn_set_adjust(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	if (len <= 1)
		return;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].xlated_off <= off)
			continue;
		if (insn_set->ptrs[i].xlated_off == INSN_DELETED)
			continue;
		insn_set->ptrs[i].xlated_off += len - 1;
	}
}

void bpf_insn_set_adjust_after_remove(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].xlated_off < off)
			continue;
		if (insn_set->ptrs[i].xlated_off == INSN_DELETED)
			continue;
		if (insn_set->ptrs[i].xlated_off >= off &&
		    insn_set->ptrs[i].xlated_off < off + len)
			insn_set->ptrs[i].xlated_off = INSN_DELETED;
		else
			insn_set->ptrs[i].xlated_off -= len;
	}
}
