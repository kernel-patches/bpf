#ifndef _UPTR_KV_STORE_COMMON_H
#define _UPTR_KV_STORE_COMMON_H

#define PAGE_SIZE		4096
#define KVS_MAX_KEY_SIZE 	32
#define KVS_MAX_VAL_SIZE 	PAGE_SIZE
#define KVS_MAX_VAL_ENTRIES 	1024

#define KVS_VALUE_INFO_PAGE_IDX_BIT	3
#define KVS_VALUE_INFO_PAGE_OFF_BIT	12
#define KVS_VALUE_INFO_VAL_SIZE_BIT	12

#define KVS_MAX_PAGE_ENTRIES	(1 << KVS_VALUE_INFO_PAGE_IDX_BIT)

#ifdef __BPF__
struct kv_store_page *dummy_page;
struct kv_store_metas *dummy_metas;
#else
#define __uptr
#define __kptr
#endif

struct kv_store_meta {
	__u32 page_idx:KVS_VALUE_INFO_PAGE_IDX_BIT;
	__u32 page_off:KVS_VALUE_INFO_PAGE_OFF_BIT;
	__u32 size:KVS_VALUE_INFO_VAL_SIZE_BIT;
	__u32 init:1;
};

struct kv_store_metas {
	struct kv_store_meta meta[KVS_MAX_VAL_ENTRIES];
};

struct kv_store_page_entry {
	struct kv_store_page __uptr *page;
};

struct kv_store_data_map_value {
	struct kv_store_metas __uptr *metas;
	struct kv_store_page_entry pages[KVS_MAX_PAGE_ENTRIES];
};

struct kv_store_page {
	char data[KVS_MAX_VAL_SIZE];
};

#endif
