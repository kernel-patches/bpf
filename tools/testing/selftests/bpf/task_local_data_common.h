#ifndef __BPF_TASK_KV_STORE_COMMON_H__
#define __BPF_TASK_KV_STORE_COMMON_H__

#ifdef __BPF__
struct data_page *dummy_data_page;
struct meta_page *dummy_meta_page;
#else
#define __uptr
#endif


#define TASK_LOCAL_DATA_MAP_PIN_PATH "/sys/fs/bpf/task_local_data_map"
#define TASK_LOCAL_DATA_KEY_LEN 62
#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))

struct data_page {
	char data[PAGE_SIZE];
};

struct data_page_entry {
	struct data_page __uptr *page;
};

struct key_meta {
	char key[TASK_LOCAL_DATA_KEY_LEN];
	short off;
};

struct meta_page {
	struct key_meta meta[64];
};

struct task_local_data_map_value {
	struct data_page_entry udata[2];
	struct meta_page __uptr *umetadata;
	short umetadata_cnt;
	short udata_start;
};

#endif
