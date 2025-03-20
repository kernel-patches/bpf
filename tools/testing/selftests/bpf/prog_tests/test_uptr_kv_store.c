#include <test_progs.h>

#include "uptr_kv_store.h"
#include "test_uptr_kv_store_common.h"
#include "test_uptr_kv_store.skel.h"

static void test_uptr_kv_store_basic(void)
{
	int err, i, pid, int_val, *int_val_p, max_int_entries;
	struct test_uptr_kv_store *skel;
	struct kv_store *kvs = NULL;

	skel = test_uptr_kv_store__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->target_pid = -1;
	err = test_uptr_kv_store__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		return;

	kvs = kv_store_init(getpid(), skel->maps.data_map, "/sys/fs/bpf/kv_store_data_map");
	if (!ASSERT_OK_PTR(kvs, "kv_store_init"))
		return;

	max_int_entries = KVS_MAX_VAL_ENTRIES;

	err = kv_store_update_value_size(kvs, 0, KVS_MAX_VAL_SIZE);
	ASSERT_ERR(err, "kv_store_update_value_size");

	err = kv_store_put(kvs, 0, &int_val, KVS_MAX_VAL_SIZE + 1);
	ASSERT_ERR(err, "kv_store_put");

	for (i = 0; i < max_int_entries; i++) {
		int_val_p = kv_store_get(kvs, i);
		if (!ASSERT_ERR_PTR(int_val_p, "kv_store_get int_val"))
			goto out;

		err = kv_store_put(kvs, i, &i, sizeof(i));
		if (!ASSERT_OK(err, "kv_store_put int_val"))
			goto out;
	}

	pid = sys_gettid();
	skel->bss->target_pid = pid;
	for (i = 0; i < max_int_entries; i++) {
		skel->bss->test_key = i;
		skel->bss->test_op = KVS_INT_GET;
		sys_gettid();
		ASSERT_EQ(skel->bss->test_int_val, i, "bpf: check int_val[i] = i");

		skel->bss->test_int_val += 1;
		skel->bss->test_op = KVS_INT_PUT;
		sys_gettid();
	}
	skel->bss->target_pid = -1;

	for (i = 0; i < max_int_entries; i++) {
		int_val_p = kv_store_get(kvs, i);
		if (!ASSERT_OK_PTR(int_val_p, "kv_store_get int_val"))
			goto out;

		ASSERT_EQ(*int_val_p, i + 1, "user space: check int_val[i] == i + 1");
	}

	err = kv_store_put(kvs, max_int_entries, &int_val, sizeof(int));
	ASSERT_EQ(err, -ENOENT, "kv_store_put int_val");

out:
	kv_store_close(kvs);
}

void test_uptr_kv_store(void)
{
	if (test__start_subtest("uptr_kv_store_basic"))
		test_uptr_kv_store_basic();
}
