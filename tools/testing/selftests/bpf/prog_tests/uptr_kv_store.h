#ifndef _UPTR_KV_STORE_H
#define _UPTR_KV_STORE_H

#include "uptr_kv_store_common.h"

struct kv_store;

void kv_store_close(struct kv_store *kvs);

struct kv_store *kv_store_init(int pid, struct bpf_map *data_map, const char *pin_path);

int kv_store_data_map_set_reuse(struct kv_store *kvs, struct bpf_map *data_map);

void *kv_store_get(struct kv_store *kvs, int key);

int kv_store_put(struct kv_store *kvs, int key, void *val, unsigned int val_size);

void kv_store_delete(struct kv_store *kvs, int key);

int kv_store_update_value_size(struct kv_store *kvs, int key, unsigned int val_size);

#endif
