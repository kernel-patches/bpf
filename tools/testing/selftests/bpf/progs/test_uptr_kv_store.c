#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "uptr_kv_store.h"
#include "test_uptr_kv_store_common.h"

pid_t target_pid = 0;
int test_op;
int test_key;
int test_int_val;

SEC("tp_btf/sys_enter")
int on_enter(__u64 *ctx)
{
	struct kv_store_data_map_value *data;
	struct task_struct *task;

	task = bpf_get_current_task_btf();
	if (task->pid != target_pid)
		return 0;

	data = bpf_task_storage_get(&data_map, task, 0, 0);

	switch (test_op) {
	case KVS_INT_PUT:
		kv_store_put(data, test_key, &test_int_val, 4);
		break;
	case KVS_INT_GET:
		kv_store_get(data, test_key, &test_int_val, 4);
		break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

