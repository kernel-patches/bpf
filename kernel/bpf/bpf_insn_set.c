// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/sort.h>

#define MAX_ISET_ENTRIES 256

struct bpf_insn_set {
	struct bpf_map map;
	struct mutex state_mutex;
	int state;
	u32 **unique_offsets;
	u32 unique_offsets_cnt;
	long *ips;
	DECLARE_FLEX_ARRAY(struct bpf_insn_ptr, ptrs);
};

enum {
	INSN_SET_STATE_FREE = 0,
	INSN_SET_STATE_INIT,
	INSN_SET_STATE_READY,
};

#define cast_insn_set(MAP_PTR) \
	container_of(MAP_PTR, struct bpf_insn_set, map)

#define INSN_DELETED ((u32)-1)

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
	    attr->value_size != 8 ||
	    attr->map_flags != 0)
		return -EINVAL;

	if (attr->max_entries > MAX_ISET_ENTRIES)
		return -E2BIG;

	return 0;
}

static void insn_set_free(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	kfree(insn_set->unique_offsets);
	kfree(insn_set->ips);
	bpf_map_area_free(insn_set);
}

static struct bpf_map *insn_set_alloc(union bpf_attr *attr)
{
	u64 size = insn_set_alloc_size(attr->max_entries);
	struct bpf_insn_set *insn_set;

	insn_set = bpf_map_area_alloc(size, NUMA_NO_NODE);
	if (!insn_set)
		return ERR_PTR(-ENOMEM);

	insn_set->ips = kcalloc(attr->max_entries, sizeof(long), GFP_KERNEL);
	if (!insn_set->ips) {
		insn_set_free(&insn_set->map);
		return ERR_PTR(-ENOMEM);
	}

	insn_set->unique_offsets = kzalloc(sizeof(long) * attr->max_entries, GFP_KERNEL);
	if (!insn_set->unique_offsets) {
		insn_set_free(&insn_set->map);
		return ERR_PTR(-ENOMEM);
	}

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

	return &insn_set->ptrs[index].user_value;
}

static long insn_set_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	u32 index = *(u32 *)key;
	struct bpf_insn_set_value val = {};

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		return -EINVAL;

	if (unlikely(index >= insn_set->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags & BPF_NOEXIST))
		return -EEXIST;

	copy_map_value(map, &val, value);
	if (val.jitted_off || val.xlated_off == INSN_DELETED)
		return -EINVAL;

	insn_set->ptrs[index].orig_xlated_off = val.xlated_off;
	insn_set->ptrs[index].user_value.xlated_off = val.xlated_off;

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

static u64 insn_set_mem_usage(const struct bpf_map *map)
{
	u64 extra_size = 0;

	extra_size += sizeof(long) * map->max_entries; /* insn_set->ips */
	extra_size += 4 * map->max_entries; /* insn_set->unique_offsets */

	return insn_set_alloc_size(map->max_entries) + extra_size;
}

static int insn_set_map_direct_value_addr(const struct bpf_map *map, u64 *imm, u32 off)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	/* for now, just reject all such loads */
	if (off > 0)
		return -EINVAL;

	/* from BPF's point of view, this map is a jump table */
	*imm = (unsigned long)insn_set->ips;

	return 0;
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
	.map_direct_value_addr = insn_set_map_direct_value_addr,
	.map_btf_id = &insn_set_btf_ids[0],
};

static inline bool is_frozen(struct bpf_map *map)
{
	guard(mutex)(&map->freeze_mutex);

	return map->frozen;
}

static bool is_insn_set(const struct bpf_map *map)
{
	return map->map_type == BPF_MAP_TYPE_INSN_SET;
}

static inline bool valid_offsets(const struct bpf_insn_set *insn_set,
				 const struct bpf_prog *prog)
{
	u32 off;
	int i;

	for (i = 0; i < insn_set->map.max_entries; i++) {
		off = insn_set->ptrs[i].orig_xlated_off;

		if (off >= prog->len)
			return false;

		if (off > 0) {
			if (prog->insnsi[off-1].code == (BPF_LD | BPF_DW | BPF_IMM))
				return false;
		}
	}

	return true;
}

static int cmp_unique_offsets(const void *a, const void *b)
{
	return *(u32 *)a - *(u32 *)b;
}

static int bpf_insn_set_init_unique_offsets(struct bpf_insn_set *insn_set)
{
	u32 cnt = insn_set->map.max_entries, ucnt = 1;
	u32 **off = insn_set->unique_offsets;
	int i;

	/* [0,3,2,4,6,5,5,5,1,1,0,0] */
	for (i = 0; i < cnt; i++)
		off[i] = &insn_set->ptrs[i].user_value.xlated_off;

	/* [0,0,0,1,1,2,3,4,5,5,5,6] */
	sort(off, cnt, sizeof(off[0]), cmp_unique_offsets, NULL);

	/*
	 * [0,1,2,3,4,5,6,x,x,x,x,x]
	 *  \.........../
	 *    unique_offsets_cnt
	 */
	for (i = 1; i < cnt; i++)
		if (*off[i] != *off[ucnt-1])
			off[ucnt++] = off[i];

	insn_set->unique_offsets_cnt = ucnt;
	return 0;
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
		insn_set->ptrs[i].user_value.xlated_off = insn_set->ptrs[i].orig_xlated_off;

	/*
	 * Prepare a set of unique offsets
	 */
	return bpf_insn_set_init_unique_offsets(insn_set);
}

int bpf_insn_set_ready(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		if (!insn_set->ips[i])
			return -EFAULT;
	}

	insn_set->state = INSN_SET_STATE_READY;
	return 0;
}

void bpf_insn_set_release(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	insn_set->state = INSN_SET_STATE_FREE;
}

void bpf_insn_set_adjust(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	if (len <= 1)
		return;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].user_value.xlated_off <= off)
			continue;
		if (insn_set->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		insn_set->ptrs[i].user_value.xlated_off += len - 1;
	}
}

void bpf_insn_set_adjust_after_remove(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);
	int i;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].user_value.xlated_off < off)
			continue;
		if (insn_set->ptrs[i].user_value.xlated_off == INSN_DELETED)
			continue;
		if (insn_set->ptrs[i].user_value.xlated_off >= off &&
		    insn_set->ptrs[i].user_value.xlated_off < off + len)
			insn_set->ptrs[i].user_value.xlated_off = INSN_DELETED;
		else
			insn_set->ptrs[i].user_value.xlated_off -= len;
	}
}

void bpf_prog_update_insn_ptr(struct bpf_prog *prog,
			      u32 xlated_off,
			      u32 jitted_off,
			      u32 jitted_len,
			      int jitted_jump_offset,
			      void *jitted_ip)
{
	struct bpf_insn_set *insn_set;
	struct bpf_map *map;
	int i, j;

	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		map = prog->aux->used_maps[i];
		if (!is_insn_set(map))
			continue;

		insn_set = cast_insn_set(map);
		for (j = 0; j < map->max_entries; j++) {
			if (insn_set->ptrs[j].user_value.xlated_off == xlated_off) {
				insn_set->ips[j] = (long)jitted_ip;
				insn_set->ptrs[j].jitted_ip = jitted_ip;
				insn_set->ptrs[j].jitted_len = jitted_len;
				insn_set->ptrs[j].jitted_jump_offset = jitted_jump_offset;
				insn_set->ptrs[j].user_value.jitted_off = jitted_off;
			}
		}
	}
}

int bpf_insn_set_iter_xlated_offset(struct bpf_map *map, u32 iter_no)
{
	struct bpf_insn_set *insn_set = cast_insn_set(map);

	if (iter_no >= insn_set->unique_offsets_cnt)
		return -ENOENT;

	return *insn_set->unique_offsets[iter_no];
}
