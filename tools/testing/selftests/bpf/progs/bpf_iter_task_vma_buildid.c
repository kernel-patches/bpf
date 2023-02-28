// SPDX-License-Identifier: GPL-2.0

#include "bpf_iter.h"
#include "err.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

#define VM_EXEC		0x00000004
#define D_PATH_BUF_SIZE	1024

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, char[D_PATH_BUF_SIZE]);
	__type(value, struct build_id);
} files SEC(".maps");

static char path[D_PATH_BUF_SIZE];
static struct build_id build_id;

SEC("iter/task_vma")
int proc_maps(struct bpf_iter__task_vma *ctx)
{
	struct vm_area_struct *vma = ctx->vma;
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	unsigned long file_key;
	struct inode *inode;
	struct file *file;

	if (task == (void *)0 || vma == (void *)0)
		return 0;

	if (!(vma->vm_flags & VM_EXEC))
		return 0;

	file = vma->vm_file;
	if (!file)
		return 0;

	__builtin_memset(path, 0x0, D_PATH_BUF_SIZE);
	bpf_d_path(&file->f_path, (char *) &path, D_PATH_BUF_SIZE);

	if (bpf_map_lookup_elem(&files, &path))
		return 0;

	inode = file->f_inode;
	if (IS_ERR_OR_NULL(inode->i_build_id)) {
		/* On error return empty build id. */
		__builtin_memset(&build_id.data, 0x0, sizeof(build_id.data));
		build_id.sz = 20;
	} else {
		__builtin_memcpy(&build_id, inode->i_build_id, sizeof(*inode->i_build_id));
	}

	bpf_map_update_elem(&files, &path, &build_id, 0);
	return 0;
}
