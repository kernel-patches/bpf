#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <linux/err.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "task_local_storage_helpers.h"
#include "uptr_kv_store.h"

struct kv_store {
	int data_map_fd;
	int task_fd;
	int page_cnt;
	char *data_map_pin_path;
	struct kv_store_data_map_value data;
};

static struct kv_store_page *__kv_store_add_page(struct kv_store *kvs)
{
	struct kv_store_page *p;

	if (kvs->page_cnt > KVS_MAX_PAGE_ENTRIES)
		return ERR_PTR(-ENOSPC);

	p = mmap(NULL, sizeof(struct kv_store_page), PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return ERR_PTR(-ENOMEM);

	kvs->data.pages[kvs->page_cnt].page = p;
	kvs->page_cnt++;

	return p;
}

static void __kv_store_del_page(struct kv_store *kvs)
{
	struct kv_store_page *p;

	p = kvs->data.pages[kvs->page_cnt - 1].page;
	kvs->data.pages[kvs->page_cnt - 1].page = NULL;
	kvs->page_cnt--;
	munmap(p, sizeof(*p));
}

static struct kv_store_meta *kvs_store_get_meta(struct kv_store *kvs, int key)
{
	return key < KVS_MAX_VAL_ENTRIES ? &kvs->data.metas->meta[key] : NULL;
}

void kv_store_close(struct kv_store *kvs)
{
	int i;

	munmap(kvs->data.metas, sizeof(struct kv_store_metas));

	for (i = 0; i < kvs->page_cnt; i++)
		__kv_store_del_page(kvs);

	if (kvs->data_map_pin_path)
		unlink(kvs->data_map_pin_path);

	free(kvs);
}

struct kv_store *kv_store_init(int pid, struct bpf_map *data_map, const char *pin_path)
{
	struct kv_store_page *p;
	struct kv_store *kvs;
	int err;

	kvs = calloc(1, sizeof(*kvs));
	if (!kvs) {
		errno = -ENOMEM;
		return NULL;
	}

	kvs->data.metas = mmap(NULL, sizeof(struct kv_store_page),
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (kvs->data.metas == MAP_FAILED) {
		errno = -ENOMEM;
		return NULL;
	}

	p = __kv_store_add_page(kvs);
	if (IS_ERR(p)) {
		errno = PTR_ERR(p);
		goto err;
	}

	kvs->data_map_fd = bpf_map__fd(data_map);
	if (!kvs->data_map_fd) {
		errno = -ENOENT;
		goto err;
	}

	kvs->task_fd = sys_pidfd_open(pid, 0);
	if (!kvs->task_fd) {
		errno = -ESRCH;
		goto err;
	}

	err = bpf_map_update_elem(kvs->data_map_fd, &kvs->task_fd, &kvs->data, 0);
	if (err) {
		errno = err;
		goto err;
	}

	kvs->data_map_pin_path = strdup(pin_path);
	if (!kvs->data_map_pin_path)
		goto err;

	err = bpf_map__pin(data_map, kvs->data_map_pin_path);
	if (err) {
		errno = err;
		goto err;
	}

	return kvs;
err:
	kv_store_close(kvs);
	return NULL;
}

int kv_store_data_map_set_reuse(struct kv_store *kvs, struct bpf_map *data_map)
{
	return bpf_map__reuse_fd(data_map, kvs->data_map_fd);
}

void *kv_store_get(struct kv_store *kvs, int key)
{
	struct kv_store_meta *meta;
	struct kv_store_page *p;

	meta = kvs_store_get_meta(kvs, key);
	if (!meta || !meta->init)
		return NULL;

	p = kvs->data.pages[meta->page_idx].page;

	return p->data + meta->page_off;
}

static int linear_off(const struct kv_store_meta *meta)
{
	if (!meta->init)
		return KVS_MAX_PAGE_ENTRIES * KVS_MAX_VAL_SIZE;

	return meta->page_idx * KVS_MAX_VAL_SIZE + meta->page_off;
}

static int comp_meta(const void *m1, const void *m2)
{
	struct kv_store_meta *meta1 = (struct kv_store_meta *)m1;
	struct kv_store_meta *meta2 = (struct kv_store_meta *)m2;
	int off1, off2;

	off1 = linear_off(meta1);
	off2 = linear_off(meta2);

	if (off1 > off2)
		return 1;
	else if (off1 < off2)
		return -1;
	else
		return 0;
}

static int kv_store_find_next_slot(struct kv_store *kvs, int size, struct kv_store_meta *meta)
{
	struct kv_store_meta metas[KVS_MAX_VAL_ENTRIES];
	int i, err, off, next_off = 0;
	struct kv_store_page *p;

	memcpy(metas, kvs->data.metas, sizeof(struct kv_store_meta) * KVS_MAX_VAL_ENTRIES);

	qsort(metas, KVS_MAX_VAL_ENTRIES, sizeof(struct kv_store_meta), comp_meta);

	for (i = 0; i < KVS_MAX_VAL_ENTRIES; i++) {
		off = linear_off(&metas[i]);
		if (off - next_off >= size &&
		    next_off / PAGE_SIZE == (next_off + size - 1) / PAGE_SIZE) {
			break;
		}
		next_off = off + metas[i].size;
	}

	meta->page_idx = next_off / PAGE_SIZE;
	meta->page_off = next_off % PAGE_SIZE;
	meta->size = size;

	if (meta->page_idx >= kvs->page_cnt) {
		p = __kv_store_add_page(kvs);
		if (!p)
			return -ENOMEM;

		err = bpf_map_update_elem(kvs->data_map_fd, &kvs->task_fd, &kvs->data, 0);
		if (err) {
			__kv_store_del_page(kvs);
			return err;
		}
	}

	return 0;
}

int kv_store_put(struct kv_store *kvs, int key, void *val, unsigned int val_size)
{
	struct kv_store_meta *meta;
	struct kv_store_page *p;
	int err;

	meta = kvs_store_get_meta(kvs, key);
	if (!meta)
		return -ENOENT;

	if (!meta->init) {
		if (val_size > KVS_MAX_VAL_SIZE)
			return -E2BIG;

		err = kv_store_find_next_slot(kvs, val_size, meta);
		if (err)
			return err;
	}

	p = kvs->data.pages[meta->page_idx].page;
	val_size = val_size < meta->size ? val_size : meta->size;
	memcpy((char *)p->data + meta->page_off, val, val_size);
	meta->init = 1;
	return 0;
}

void kv_store_delete(struct kv_store *kvs, int key)
{
	struct kv_store_meta *meta;
	struct kv_store_page *p;

	meta = kvs_store_get_meta(kvs, key);
	if (!meta)
		return;

	p = kvs->data.pages[meta->page_idx].page;
	memset(p->data + meta->page_off, 0, meta->size);
	memset(meta, 0, sizeof(*meta));
}

int kv_store_update_value_size(struct kv_store *kvs, int key, unsigned int val_size)
{
	struct kv_store_meta *meta, new_meta;
	struct kv_store_page *old_p, *new_p;
	int err;

	if (val_size > KVS_MAX_VAL_SIZE)
		return -E2BIG;

	meta = kvs_store_get_meta(kvs, key);
	if (!meta || !meta->init)
		return -ENOENT;

	if (val_size <= meta->size) {
		meta->size = val_size;
		return 0;
	}

	err = kv_store_find_next_slot(kvs, val_size, &new_meta);
	if (err)
		return -ENOSPC;

	old_p = kvs->data.pages[meta->page_idx].page;
	new_p = kvs->data.pages[new_meta.page_idx].page;

	memcpy(new_p->data + new_meta.page_off,
	       old_p->data + meta->page_off, meta->size);

	return 0;
}
