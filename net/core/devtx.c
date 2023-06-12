// SPDX-License-Identifier: GPL-2.0-only

#include <net/devtx.h>
#include <linux/filter.h>

DEFINE_STATIC_KEY_FALSE(devtx_enabled);
EXPORT_SYMBOL_GPL(devtx_enabled);

static void devtx_run(struct net_device *netdev, struct devtx_frame *ctx, struct bpf_prog **pprog)
{
	struct bpf_prog *prog;
	void *real_ctx[1] = {ctx};

	prog = rcu_dereference(*pprog);
	if (likely(prog))
		bpf_prog_run(prog, real_ctx);
}

void devtx_submit(struct net_device *netdev, struct devtx_frame *ctx)
{
	rcu_read_lock();
	devtx_run(netdev, ctx, &netdev->devtx_sb);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(devtx_submit);

void devtx_complete(struct net_device *netdev, struct devtx_frame *ctx)
{
	rcu_read_lock();
	devtx_run(netdev, ctx, &netdev->devtx_cp);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(devtx_complete);

/**
 * devtx_sb - Called for every egress netdev packet
 *
 * Note: this function is never actually called by the kernel and declared
 * only to allow loading an attaching appropriate tracepoints.
 */
__weak noinline void devtx_sb(struct devtx_frame *ctx)
{
}

/**
 * devtx_cp - Called upon egress netdev packet completion
 *
 * Note: this function is never actually called by the kernel and declared
 * only to allow loading an attaching appropriate tracepoints.
 */
__weak noinline void devtx_cp(struct devtx_frame *ctx)
{
}

BTF_SET8_START(bpf_devtx_hook_ids)
BTF_ID_FLAGS(func, devtx_sb)
BTF_ID_FLAGS(func, devtx_cp)
BTF_SET8_END(bpf_devtx_hook_ids)

static const struct btf_kfunc_id_set bpf_devtx_hook_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_devtx_hook_ids,
};

static DEFINE_MUTEX(devtx_attach_lock);

static int __bpf_devtx_detach(struct net_device *netdev, struct bpf_prog **pprog)
{
	if (!*pprog)
		return -EINVAL;
	bpf_prog_put(*pprog);
	*pprog = NULL;

	static_branch_dec(&devtx_enabled);
	return 0;
}

static int __bpf_devtx_attach(struct net_device *netdev, int prog_fd,
			      const char *attach_func_name, struct bpf_prog **pprog)
{
	struct bpf_prog *prog;
	int ret = 0;

	if (prog_fd < 0)
		return __bpf_devtx_detach(netdev, pprog);

	if (*pprog)
		return -EBUSY;

	prog = bpf_prog_get(prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->type != BPF_PROG_TYPE_TRACING ||
	    prog->expected_attach_type != BPF_TRACE_FENTRY ||
	    !bpf_prog_is_dev_bound(prog->aux) ||
	    !bpf_offload_dev_match(prog, netdev) ||
	    strcmp(prog->aux->attach_func_name, attach_func_name)) {
		bpf_prog_put(prog);
		return -EINVAL;
	}

	*pprog = prog;
	static_branch_inc(&devtx_enabled);

	return ret;
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");

/**
 * bpf_devtx_sb_attach - Attach devtx 'packet submit' program
 * @ifindex: netdev interface index.
 * @prog_fd: BPF program file descriptor.
 *
 * Return:
 * * Returns 0 on success or ``-errno`` on error.
 */
__bpf_kfunc int bpf_devtx_sb_attach(int ifindex, int prog_fd)
{
	struct net_device *netdev;
	int ret;

	netdev = dev_get_by_index(current->nsproxy->net_ns, ifindex);
	if (!netdev)
		return -EINVAL;

	mutex_lock(&devtx_attach_lock);
	ret = __bpf_devtx_attach(netdev, prog_fd, "devtx_sb", &netdev->devtx_sb);
	mutex_unlock(&devtx_attach_lock);

	dev_put(netdev);

	return ret;
}

/**
 * bpf_devtx_cp_attach - Attach devtx 'packet complete' program
 * @ifindex: netdev interface index.
 * @prog_fd: BPF program file descriptor.
 *
 * Return:
 * * Returns 0 on success or ``-errno`` on error.
 */
__bpf_kfunc int bpf_devtx_cp_attach(int ifindex, int prog_fd)
{
	struct net_device *netdev;
	int ret;

	netdev = dev_get_by_index(current->nsproxy->net_ns, ifindex);
	if (!netdev)
		return -EINVAL;

	mutex_lock(&devtx_attach_lock);
	ret = __bpf_devtx_attach(netdev, prog_fd, "devtx_cp", &netdev->devtx_cp);
	mutex_unlock(&devtx_attach_lock);

	dev_put(netdev);

	return ret;
}

__diag_pop();

bool is_devtx_kfunc(u32 kfunc_id)
{
	return !!btf_id_set8_contains(&bpf_devtx_hook_ids, kfunc_id);
}

void devtx_shutdown(struct net_device *netdev)
{
	mutex_lock(&devtx_attach_lock);
	__bpf_devtx_detach(netdev, &netdev->devtx_sb);
	__bpf_devtx_detach(netdev, &netdev->devtx_cp);
	mutex_unlock(&devtx_attach_lock);
}

BTF_SET8_START(bpf_devtx_syscall_kfunc_ids)
BTF_ID_FLAGS(func, bpf_devtx_sb_attach)
BTF_ID_FLAGS(func, bpf_devtx_cp_attach)
BTF_SET8_END(bpf_devtx_syscall_kfunc_ids)

static const struct btf_kfunc_id_set bpf_devtx_syscall_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_devtx_syscall_kfunc_ids,
};

static int __init devtx_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_devtx_hook_set);
	if (ret) {
		pr_warn("failed to register devtx hooks: %d", ret);
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_devtx_syscall_kfunc_set);
	if (ret) {
		pr_warn("failed to register syscall kfuncs: %d", ret);
		return ret;
	}

	return 0;
}
late_initcall(devtx_init);
