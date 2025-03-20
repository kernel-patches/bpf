#ifndef _UPTR_KV_STORE_H
#define _UPTR_KV_STORE_H

#include <errno.h>
#include <string.h>
#include <bpf/bpf_helpers.h>

#include "uptr_kv_store_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct kv_store_data_map_value);
} data_map SEC(".maps");

static int bpf_dynptr_from_kv_store(struct kv_store_data_map_value *data, int key,
				    unsigned int val_size, struct bpf_dynptr *ptr,
				    struct kv_store_meta **meta)
{
	struct kv_store_page *p = NULL;
	u16 _key = 0;

	if (!data || !data->metas)
		return -ENOENT;

	/* workaround. llvm generates memory access with unbound key with the following code:
	 * if (key >= KVS_MAX_VAL_ENTRIES)
	 *         return -ENOENT;
	 *
	 * ; *meta = &data->metas->meta[key]; @ uptr_kv_store.h:37
	 * 62: (bc) w2 = w2                      ; frame1: R2_w=scalar(id=3,smin=0,smax=umax=0xffffffff,smax32=1023,var_off=(0x0; 0xffffffff))
	 * 63: (67) r2 <<= 32                    ; frame1: R2_w=scalar(smax=0x3ff00000000,umax=0xffffffff00000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffff00000000))
	 * 64: (c7) r2 s>>= 32                   ; frame1: R2_w=scalar(smin=0xffffffff80000000,smax=smax32=1023)
	 * 65: (67) r2 <<= 2                     ; frame1: R2_w=scalar(smax=0x7ffffffffffffffc,umax=0xfffffffffffffffc,smax32=0x7ffffffc,umax32=0xfffffffc,var_off=(0x0; 0xfffffffffffffffc))
	 * 66: (0f) r6 += r2
	 * math between mem pointer and register with unbounded min value is not allowed
	 */
	_key += key;
	if (_key >= KVS_MAX_VAL_ENTRIES)
		return -ENOENT;

	*meta = &data->metas->meta[_key];
	if (!(*meta)->init)
		return -ENOENT;

	/* workaround for variable offset uptr access:
	 * p = data->pages[meta->page_idx].page;
	 */
	switch((*meta)->page_idx) {
	case 0: p = data->pages[0].page; break;
	case 1: p = data->pages[1].page; break;
	case 2: p = data->pages[2].page; break;
	case 3: p = data->pages[3].page; break;
	case 4: p = data->pages[4].page; break;
	case 5: p = data->pages[5].page; break;
	case 6: p = data->pages[6].page; break;
	case 7: p = data->pages[7].page; break;
	}

	if (!p)
		return -ENOENT;

	val_size = val_size < (*meta)->size ? val_size : (*meta)->size;

	if ((*meta)->page_off >= KVS_MAX_VAL_SIZE)
		return -EINVAL;

	return bpf_dynptr_from_mem(p->data, KVS_MAX_VAL_SIZE, 0, ptr);
}

__attribute__((unused))
static int kv_store_put(struct kv_store_data_map_value *data, int key,
			void *val, unsigned int val_size)
{
	struct kv_store_meta *meta;
	struct bpf_dynptr ptr;
	int err;

	err = bpf_dynptr_from_kv_store(data, key, val_size, &ptr, &meta);
	if (err)
		return err;

	return bpf_dynptr_write(&ptr, meta->page_off, val, val_size, 0);
}

__attribute__((unused))
static int kv_store_get(struct kv_store_data_map_value *data, int key,
			void *val, unsigned int val_size)
{
	struct kv_store_meta *meta;
	struct bpf_dynptr ptr;
	int err;

	err = bpf_dynptr_from_kv_store(data, key, val_size, &ptr, &meta);
	if (err)
		return err;

	return bpf_dynptr_read(val, val_size, &ptr, meta->page_off, 0);
}

__attribute__((unused))
static int kv_store_delete(struct kv_store_data_map_value *data, int key)
{
	struct kv_store_meta *meta;
	u16 _key = 0;

	if (!data || !data->metas)
		return -ENOENT;

	_key += key;
	if (_key >= KVS_MAX_VAL_ENTRIES)
		return -ENOENT;

	meta = &data->metas->meta[_key];
	meta->init = 0;
	return 0;
}

#endif
