#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>

#include <bpf/bpf.h>

#include "bpf_util.h"
#include "task_local_data.h"
#include "task_local_storage_helpers.h"

#define PIDFD_THREAD       O_EXCL

/* To find the start of udata for each thread, insert a dummy variable to udata.
 * Contructors generated for every task local data will figured out the offset
 * from the beginning of udata to the dummy symbol. Then, every thread can infer
 * the start of udata by subtracting the offset from the address of dummy.
 */
static __thread struct udata_dummy {} udata_dummy SEC("udata");

static __thread bool task_local_data_thread_inited;

struct task_local_data {
	void *udata_start;
	void *udata_end;
	int udata_start_dummy_off;
	struct meta_page *umetadata;
	int umetadata_cnt;
	bool umetadata_init;
	short udata_sizes[64];
	pthread_mutex_t lock;
} task_local_data = {
	.udata_start = (void *)-1UL,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static void tld_set_data_key_meta(int i, const char *key, short off)
{
	task_local_data.umetadata->meta[i].off = off;
	strncpy(task_local_data.umetadata->meta[i].key, key, TASK_LOCAL_DATA_KEY_LEN);
}

static struct key_meta *tld_get_data_key_meta(int i)
{
	return &task_local_data.umetadata->meta[i];
}

static void tld_set_data_size(int i, int size)
{
	task_local_data.udata_sizes[i] = size;
}

static int tld_get_data_size(int i)
{
	return task_local_data.udata_sizes[i];
}

void __bpf_tld_var_init(const char *key, void *var, int size)
{
	int i;

	i = task_local_data.umetadata_cnt++;

	if (!task_local_data.umetadata) {
		if (task_local_data.umetadata_cnt > 1)
			return;

		task_local_data.umetadata = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
		if (!task_local_data.umetadata)
			return;
	}

	if (var < task_local_data.udata_start) {
		task_local_data.udata_start = var;
		task_local_data.udata_start_dummy_off =
			(void *)&udata_dummy - task_local_data.udata_start;
	}

	if (var + size > task_local_data.udata_end)
		task_local_data.udata_end = var + size;

	tld_set_data_key_meta(i, key, var - (void *)&udata_dummy);
	tld_set_data_size(i, size);
}

int bpf_tld_thread_init(void)
{
	unsigned long udata_size, udata_start, udata_start_page, udata_end_page;
	struct task_local_data_map_value map_val;
	int i, task_id, task_fd, map_fd, err;

	if (!task_local_data.umetadata_cnt || task_local_data_thread_inited)
		return 0;

	if (task_local_data.umetadata_cnt && !task_local_data.umetadata)
		return -ENOMEM;

	udata_start = (unsigned long)&udata_dummy + task_local_data.udata_start_dummy_off;

	pthread_mutex_lock(&task_local_data.lock);
	for (i = 0; i < task_local_data.umetadata_cnt; i++) {
		struct key_meta *km = tld_get_data_key_meta(i);
		int size = tld_get_data_size(i);
		int off;

		if (!task_local_data.umetadata_init) {
			/* Constructors save the offset from udata_dummy to each data
			 * Now as all ctors have run and the offset between the start of
			 * udata and udata_dummy is known, adjust the offsets of data
			 * to be relative to the start of udata
			 */
			km->off -= task_local_data.udata_start_dummy_off;

			/* Data exceeding a page may not be able to be covered by
			 * two udata UPTRs in every thread
			 */
			if (km->off >= PAGE_SIZE)
				return -EOPNOTSUPP;
		}

		/* A task local data should not span across two pages. */
		off = km->off + udata_start;
		if ((off & PAGE_MASK) != ((off + size - 1) & PAGE_MASK))
			return -EOPNOTSUPP;
	}
	task_local_data.umetadata_init = true;
	pthread_mutex_unlock(&task_local_data.lock);

	udata_size = task_local_data.udata_end - task_local_data.udata_start;
	udata_start_page = udata_start & PAGE_MASK;
	udata_end_page = (udata_start + udata_size) & PAGE_MASK;

	/* The whole udata can span across two pages for a thread. Use two UPTRs
	 * to cover the second page in case it happens.
	 */
	map_val.udata_start = udata_start & ~PAGE_MASK;
	map_val.udata[0].page = (struct data_page *)(udata_start_page);
	map_val.udata[1].page = (udata_start_page == udata_end_page) ? NULL :
		(struct data_page *)(udata_start_page + PAGE_SIZE);

	/* umetadata is shared by all threads under the assumption that all
	 * task local data are defined statically and linked together
	 */
	map_val.umetadata = task_local_data.umetadata;
	map_val.umetadata_cnt = task_local_data.umetadata_cnt;

	map_fd = bpf_obj_get(TASK_LOCAL_DATA_MAP_PIN_PATH);
	if (map_fd < 0)
		return -errno;

	task_id = sys_gettid();
	task_fd = sys_pidfd_open(task_id, PIDFD_THREAD);
	err = bpf_map_update_elem(map_fd, &task_fd, &map_val, 0);
	if (err)
		return err;

	task_local_data_thread_inited = true;
	return 0;
}
