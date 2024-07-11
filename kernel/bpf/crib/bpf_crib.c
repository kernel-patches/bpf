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
#include <net/sock.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/tcp.h>

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

/**
 * bpf_sock_acquire() - Acquire a reference to struct sock
 *
 * @sk: struct sock that needs to acquire a reference
 *
 * @returns struct sock that has acquired the reference
 */
__bpf_kfunc struct sock *bpf_sock_acquire(struct sock *sk)
{
	sock_hold(sk);
	return sk;
}

/**
 * bpf_sock_release() - Release the reference acquired on struct sock.
 *
 * @sk: struct sock that has acquired the reference
 */
__bpf_kfunc void bpf_sock_release(struct sock *sk)
{
	sock_put(sk);
}

/**
 * bpf_sock_from_socket() - Get struct sock from struct socket, and acquire
 * a reference to struct sock.
 *
 * Note that this function acquires a reference to struct sock.
 *
 * @sock: specified struct socket
 *
 * @returns a pointer to the struct sock
 */
__bpf_kfunc struct sock *bpf_sock_from_socket(struct socket *sock)
{
	struct sock *sk = sock->sk;

	bpf_sock_acquire(sk);
	return sk;
}

/**
 * bpf_sock_from_task_fd() - Get a pointer to the struct sock
 * corresponding to the task file descriptor.
 *
 * Note that this function acquires a reference to struct sock.
 *
 * @task: specified struct task_struct
 * @fd: file descriptor
 *
 * @returns the corresponding struct sock pointer if found,
 * otherwise returns NULL.
 */
__bpf_kfunc struct sock *bpf_sock_from_task_fd(struct task_struct *task, int fd)
{
	struct file *file;
	struct socket *sock;
	struct sock *sk;

	file = bpf_file_from_task_fd(task, fd);
	if (!file)
		return NULL;

	sock = sock_from_file(file);
	if (!sock) {
		bpf_file_release(file);
		return NULL;
	}

	sk = sock->sk;

	bpf_sock_acquire(sk);
	bpf_file_release(file);
	return sk;
}

/**
 * bpf_socket_from_file() - Get struct socket from struct file
 *
 * @file: specified struct file
 *
 * @returns struct socket from struct file
 */
__bpf_kfunc struct socket *bpf_socket_from_file(struct file *file)
{
	return sock_from_file(file);
}

/**
 * bpf_sock_common_from_sock() - Get struct sock_common from struct sock
 *
 * @sk: specified struct sock
 *
 * @returns struct sock_common from struct sock
 */
__bpf_kfunc struct sock_common *bpf_sock_common_from_sock(struct sock *sk)
{
	return &sk->__sk_common;
}

/**
 * bpf_tcp_sock_from_sock() - Get struct tcp_sock from struct sock
 *
 * @sk: specified struct sock
 *
 * @returns struct tcp_sock from struct sock
 */
__bpf_kfunc struct tcp_sock *bpf_tcp_sock_from_sock(struct sock *sk)
{
	return tcp_sk(sk);
}

/**
 * bpf_udp_sock_from_sock() - Get struct udp_sock from struct sock
 *
 * @sk: specified struct sock
 *
 * @returns struct udp_sock from struct sock
 */
__bpf_kfunc struct udp_sock *bpf_udp_sock_from_sock(struct sock *sk)
{
	return udp_sk(sk);
}

/**
 * bpf_receive_queue_from_sock() - Get receive queue in struct sock
 *
 * @sk: specified struct sock
 *
 * @returns receive queue in struct sock
 */
__bpf_kfunc struct sk_buff_head *bpf_receive_queue_from_sock(struct sock *sk)
{
	return &sk->sk_receive_queue;
}

/**
 * bpf_write_queue_from_sock() - Get write queue in struct sock
 *
 * @sk: specified struct sock
 *
 * @returns write queue in struct sock
 */
__bpf_kfunc struct sk_buff_head *bpf_write_queue_from_sock(struct sock *sk)
{
	return &sk->sk_write_queue;
}

/**
 * bpf_reader_queue_from_udp_sock() - Get reader queue in struct udp_sock
 *
 * @up: specified struct udp_sock
 *
 * @returns reader queue in struct udp_sock
 */
__bpf_kfunc struct sk_buff_head *bpf_reader_queue_from_udp_sock(struct udp_sock *up)
{
	return &up->reader_queue;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_crib_kfuncs)

BTF_ID_FLAGS(func, bpf_file_from_task_fd, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_file_release, KF_RELEASE)

BTF_ID_FLAGS(func, bpf_iter_task_file_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_task_file_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_task_file_get_fd, KF_ITER_GETTER)
BTF_ID_FLAGS(func, bpf_iter_task_file_destroy, KF_ITER_DESTROY)

BTF_ID_FLAGS(func, bpf_sock_acquire, KF_ACQUIRE | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_sock_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_sock_from_socket, KF_ACQUIRE | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_sock_from_task_fd, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)

BTF_ID_FLAGS(func, bpf_socket_from_file, KF_OBTAIN | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_sock_common_from_sock, KF_OBTAIN)
BTF_ID_FLAGS(func, bpf_tcp_sock_from_sock, KF_OBTAIN)
BTF_ID_FLAGS(func, bpf_udp_sock_from_sock, KF_OBTAIN)
BTF_ID_FLAGS(func, bpf_receive_queue_from_sock, KF_OBTAIN)
BTF_ID_FLAGS(func, bpf_write_queue_from_sock, KF_OBTAIN)
BTF_ID_FLAGS(func, bpf_reader_queue_from_udp_sock, KF_OBTAIN)

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
