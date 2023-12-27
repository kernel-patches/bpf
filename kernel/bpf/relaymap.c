// SPDX-License-Identifier: GPL-2.0
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/filter.h>
#include <linux/relay.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/err.h>

#define RELAY_CREATE_FLAG_MASK (BPF_F_OVERWRITE)

struct bpf_relay_map {
	struct bpf_map map;
	struct rchan *relay_chan;
	struct rchan_callbacks relay_cb;
};

static struct dentry *create_buf_file_handler(const char *filename,
				       struct dentry *parent, umode_t mode,
				       struct rchan_buf *buf, int *is_global)
{
	/* Because we do relay_late_setup_files(), create_buf_file(NULL, NULL, ...)
	 * will be called by relay_open.
	 */
	if (!filename)
		return NULL;

	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

/* For non-overwrite, use default subbuf_start cb */
static int subbuf_start_overwrite(struct rchan_buf *buf, void *subbuf,
				       void *prev_subbuf, size_t prev_padding)
{
	return 1;
}

/* bpf_attr is used as follows:
 * - key size: must be 0
 * - value size: value will be used as directory name by map_update_elem
 *   (to create relay files). If passed as 0, it will be set to NAME_MAX as
 *   default
 *
 * - max_entries: subbuf size
 * - map_extra: subbuf num, default as 8
 *
 * When alloc, we do not set up relay files considering dir_name conflicts.
 * Instead we use relay_late_setup_files() in map_update_elem(), and thus the
 * value is used as dir_name, and map->name is used as base_filename.
 */
static struct bpf_map *relay_map_alloc(union bpf_attr *attr)
{
	struct bpf_relay_map *rmap;

	if (unlikely(attr->map_flags & ~RELAY_CREATE_FLAG_MASK))
		return ERR_PTR(-EINVAL);

	/* key size must be 0 in relay map */
	if (unlikely(attr->key_size))
		return ERR_PTR(-EINVAL);

	/* value size is used as directory name length */
	if (unlikely(attr->value_size > NAME_MAX)) {
		pr_warn("value_size should be no more than %d\n", NAME_MAX);
		return ERR_PTR(-EINVAL);
	} else if (attr->value_size == 0)
		attr->value_size = NAME_MAX;

	/* set default subbuf num */
	if (unlikely(attr->map_extra & ~UINT_MAX))
		return ERR_PTR(-EINVAL);
	attr->map_extra = attr->map_extra & UINT_MAX;
	if (!attr->map_extra)
		attr->map_extra = 8;

	if (strlen(attr->map_name) == 0)
		return ERR_PTR(-EINVAL);

	rmap = bpf_map_area_alloc(sizeof(*rmap), NUMA_NO_NODE);
	if (!rmap)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&rmap->map, attr);

	rmap->relay_cb.create_buf_file = create_buf_file_handler;
	rmap->relay_cb.remove_buf_file = remove_buf_file_handler;
	if (attr->map_flags & BPF_F_OVERWRITE)
		rmap->relay_cb.subbuf_start = subbuf_start_overwrite;

	rmap->relay_chan = relay_open(NULL, NULL,
				attr->max_entries, attr->map_extra,
				&rmap->relay_cb, NULL);
	if (!rmap->relay_chan) {
		bpf_map_area_free(rmap);
		return ERR_PTR(-EINVAL);
	}

	return &rmap->map;
}

static void relay_map_free(struct bpf_map *map)
{
	struct bpf_relay_map *rmap;
	struct dentry *parent;

	rmap = container_of(map, struct bpf_relay_map, map);

	parent = rmap->relay_chan->parent;
	relay_close(rmap->relay_chan);
	/* relay_chan->parent should be removed mannually if exists. */
	debugfs_remove_recursive(parent);
	bpf_map_area_free(rmap);
}

static void *relay_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static long relay_map_update_elem(struct bpf_map *map, void *key, void *value,
				   u64 flags)
{
	struct bpf_relay_map *rmap;
	struct dentry *parent;
	int err;

	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(key))
		return -EINVAL;

	/* If the directory already exists, debugfs_create_dir will fail. It could
	 * have been created by map_update_elem before, or another system that uses
	 * debugfs.
	 *
	 * Note that the directory name passed as value should not be longer than
	 * map->value_size, including the '\0' at the end.
	 */
	((char *)value)[map->value_size - 1] = '\0';
	parent = debugfs_create_dir(value, NULL);
	if (IS_ERR_OR_NULL(parent))
		return PTR_ERR(parent);

	/* We don't need a lock here, because the relay channel is protected in
	 * relay_late_setup_files() with a mutex.
	 */
	rmap = container_of(map, struct bpf_relay_map, map);
	err = relay_late_setup_files(rmap->relay_chan, map->name, parent);
	if (err) {
		debugfs_remove_recursive(parent);
		return err;
	}

	return 0;
}

static long relay_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static int relay_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	return -EOPNOTSUPP;
}

static u64 relay_map_mem_usage(const struct bpf_map *map)
{
	struct bpf_relay_map *rmap;
	u64 usage = sizeof(struct bpf_relay_map);

	rmap = container_of(map, struct bpf_relay_map, map);
	usage += sizeof(struct rchan);
	usage += (sizeof(struct rchan_buf) + rmap->relay_chan->alloc_size)
			 * num_online_cpus();
	return usage;
}

BTF_ID_LIST_SINGLE(relay_map_btf_ids, struct, bpf_relay_map)
const struct bpf_map_ops relay_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = relay_map_alloc,
	.map_free = relay_map_free,
	.map_lookup_elem = relay_map_lookup_elem,
	.map_update_elem = relay_map_update_elem,
	.map_delete_elem = relay_map_delete_elem,
	.map_get_next_key = relay_map_get_next_key,
	.map_mem_usage = relay_map_mem_usage,
	.map_btf_id = &relay_map_btf_ids[0],
};
