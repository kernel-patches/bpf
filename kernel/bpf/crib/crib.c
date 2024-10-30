// SPDX-License-Identifier: GPL-2.0
/*
 * Checkpoint/Restore In eBPF (CRIB)
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

BTF_KFUNCS_START(bpf_crib_kfuncs)

BTF_ID_FLAGS(func, bpf_iter_task_file_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_task_file_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_task_file_get_fd)
BTF_ID_FLAGS(func, bpf_iter_task_file_destroy, KF_ITER_DESTROY)

BTF_ID_FLAGS(func, bpf_fget_task, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_get_file_ops_type, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_put_file, KF_RELEASE)

BTF_KFUNCS_END(bpf_crib_kfuncs)

static const struct btf_kfunc_id_set bpf_crib_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_crib_kfuncs,
};

static int __init bpf_crib_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_crib_kfunc_set);
}

late_initcall(bpf_crib_init);
