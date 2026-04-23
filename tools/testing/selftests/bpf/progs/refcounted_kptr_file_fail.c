// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct file_map_value {
	struct file __kptr * file;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct file_map_value);
	__uint(max_entries, 1);
} stashed_files SEC(".maps");

SEC("lsm.s/file_open")
__failure __msg("R2 type=ctx expected=ptr_, trusted_ptr_, rcu_ptr_")
int stash_unref_ctx_file(struct file *ctx_file)
{
	struct file_map_value *mapval;
	int zero = 0;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	/* ctx_file is just the hook argument, not an acquired file reference. */
	bpf_kptr_xchg(&mapval->file, ctx_file);
	return 0;
}

SEC("lsm.s/file_open")
__failure
__msg("Unreleased reference")
int stash_xchg_file_kptr_unreleased(struct file *ctx_file)
{
	struct file_map_value *mapval;
	struct file *file = NULL;
	int zero = 0;

	(void)ctx_file;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;

	file = bpf_kptr_xchg(&mapval->file, file);
	if (file)
		bpf_put_file(file);

	file = bpf_kptr_xchg(&mapval->file, NULL);
	if (!file)
		return 0;

	/* Retrieved kptr is never released. */
	return 0;
}

SEC("lsm.s/file_open")
__failure
__msg("Possibly NULL pointer passed to trusted R1")
int stash_xchg_file_kptr_no_null_check(struct file *ctx_file)
{
	struct file_map_value *mapval;
	struct file *file = NULL;
	int zero = 0;

	(void)ctx_file;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;

	file = bpf_kptr_xchg(&mapval->file, file);
	if (file)
		bpf_put_file(file);

	file = bpf_kptr_xchg(&mapval->file, NULL);
	bpf_put_file(file);
	return 0;
}

SEC("lsm.s/file_open")
__failure
__msg("R1 must be referenced or trusted")
int put_map_owned_file(struct file *ctx_file)
{
	struct file_map_value *mapval;
	struct file *file = NULL;
	int zero = 0;

	(void)ctx_file;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;

	file = bpf_kptr_xchg(&mapval->file, file);
	if (file)
		bpf_put_file(file);

	bpf_rcu_read_lock();
	file = mapval->file;
	if (!file) {
		bpf_rcu_read_unlock();
		return 0;
	}

	/* Can't release a kptr while it is still owned by the map. */
	bpf_put_file(file);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("lsm.s/file_open")
__failure
__msg("release kernel function bpf_put_file expects")
int BPF_PROG(put_unref_ctx_file, struct file *file)
{
	/* Can't release the unacquired LSM hook argument. */
	bpf_put_file(file);
	return 0;
}

char _license[] SEC("license") = "GPL";
