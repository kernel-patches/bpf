// SPDX-License-Identifier: GPL-2.0
/*
 * Checkpoint/Restore In eBPF (CRIB): Common
 *
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <linux/bpf_crib.h>
#include <linux/init.h>
#include <linux/fdtable.h>

__bpf_kfunc_start_defs();

/**
 * bpf_file_from_task_fd() - Get a pointer to the struct file
 * corresponding to the task file descriptor.
 *
 * Note that this function acquires a reference to struct file.
 *
 * @task: specified struct task_struct
 * @fd: file descriptor
 *
 * @returns the corresponding struct file pointer if found,
 * otherwise returns NULL.
 */
__bpf_kfunc struct file *bpf_file_from_task_fd(struct task_struct *task, int fd)
{
	struct file *file;

	rcu_read_lock();
	file = task_lookup_fdget_rcu(task, fd);
	rcu_read_unlock();

	return file;
}

/**
 * bpf_file_release() - Release the reference acquired on struct file.
 *
 * @file: struct file that has acquired the reference
 */
__bpf_kfunc void bpf_file_release(struct file *file)
{
	fput(file);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_crib_kfuncs)

BTF_ID_FLAGS(func, bpf_file_from_task_fd, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_file_release, KF_RELEASE)

BTF_ID_FLAGS(func, bpf_iter_task_file_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_task_file_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_task_file_get_fd, KF_ITER_GETTER)
BTF_ID_FLAGS(func, bpf_iter_task_file_destroy, KF_ITER_DESTROY)

BTF_KFUNCS_END(bpf_crib_kfuncs)

static int bpf_prog_run_crib(struct bpf_prog *prog,
			      const union bpf_attr *kattr,
			      union bpf_attr __user *uattr)
{
	void __user *ctx_in = u64_to_user_ptr(kattr->test.ctx_in);
	__u32 ctx_size_in = kattr->test.ctx_size_in;
	void *ctx = NULL;
	u32 retval;
	int err = 0;

	/* doesn't support data_in/out, ctx_out, duration, or repeat or flags */
	if (kattr->test.data_in || kattr->test.data_out ||
	    kattr->test.ctx_out || kattr->test.duration ||
	    kattr->test.repeat || kattr->test.flags ||
	    kattr->test.batch_size)
		return -EINVAL;

	if (ctx_size_in < prog->aux->max_ctx_offset ||
	    ctx_size_in > U16_MAX)
		return -EINVAL;

	if (ctx_size_in) {
		ctx = memdup_user(ctx_in, ctx_size_in);
		if (IS_ERR(ctx))
			return PTR_ERR(ctx);
	}

	rcu_read_lock_trace();
	retval = bpf_prog_run_pin_on_cpu(prog, ctx);
	rcu_read_unlock_trace();

	if (copy_to_user(&uattr->test.retval, &retval, sizeof(u32))) {
		err = -EFAULT;
		goto out;
	}
out:
	if (ctx_size_in)
		kfree(ctx);

	return err;
}

static const struct bpf_func_proto *
bpf_crib_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_crib_is_valid_access(int off, int size,
					 enum bpf_access_type type,
					 const struct bpf_prog *prog,
					 struct bpf_insn_access_aux *info)
{
	/*
	 * Changing the context is not allowed, and all dumped data
	 * is returned to userspace via ringbuf.
	 */
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= U16_MAX)
		return false;
	if (off % size != 0)
		return false;

	return true;
}

const struct bpf_prog_ops bpf_crib_prog_ops = {
	.test_run = bpf_prog_run_crib,
};

const struct bpf_verifier_ops bpf_crib_verifier_ops = {
	.get_func_proto		= bpf_crib_func_proto,
	.is_valid_access	= bpf_crib_is_valid_access,
};

static const struct btf_kfunc_id_set bpf_crib_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_crib_kfuncs,
};

static int __init bpf_crib_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_CRIB, &bpf_crib_kfunc_set);
}

late_initcall(bpf_crib_init);
