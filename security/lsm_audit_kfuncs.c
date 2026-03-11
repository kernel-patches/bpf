// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Cloudflare */

#include <linux/audit.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/gfp_types.h>
#include <linux/in6.h>
#include <linux/lsm_audit.h>
#include <linux/socket.h>
#include <linux/types.h>

struct bpf_audit_context {
	struct audit_buffer *ab;
	u64 log_once_mask;
};

static struct bpf_mem_alloc bpf_audit_context_ma;

static inline u64 log_once(struct bpf_audit_context *ac, u64 mask)
{
	u64 set = (ac->log_once_mask & mask);

	ac->log_once_mask |= mask;
	return set;
}

static inline int __audit_log_lsm_data(struct bpf_audit_context *ac,
				       struct common_audit_data *ad)
{
	if (log_once(ac, BIT_ULL(ad->type)))
		return -EINVAL;

	audit_log_lsm_data(ac->ab, ad);
	return 0;
}

__bpf_kfunc_start_defs();

__bpf_kfunc
struct bpf_audit_context *bpf_audit_log_start(struct bpf_prog_aux *aux)
{
	char comm[sizeof(current->comm)];
	struct bpf_audit_context *ac;

	ac = bpf_mem_cache_alloc(&bpf_audit_context_ma);
	if (!ac)
		return NULL;

	memset(ac, 0, sizeof(*ac));
	ac->ab = audit_log_start(audit_context(),
				 (aux->might_sleep) ? GFP_KERNEL : GFP_ATOMIC,
				 AUDIT_BPF_LSM_ACCESS);
	if (!ac->ab) {
		bpf_mem_cache_free(&bpf_audit_context_ma, ac);
		return NULL;
	}

	audit_log_format(ac->ab, "prog-id=%d", aux->id);

	/* Audit may not have a filter configured for syscalls. Include
	 * potentionally redundant pid & comm information
	 */
	audit_log_format(ac->ab, " pid=%d comm=", task_tgid_nr(current));
	audit_log_untrustedstring(ac->ab, get_task_comm(comm, current));

	return ac;
}

__bpf_kfunc void bpf_audit_log_end(struct bpf_audit_context *ac)
{
	audit_log_end(ac->ab);
	bpf_mem_cache_free(&bpf_audit_context_ma, ac);
}

__bpf_kfunc int bpf_audit_log_cause(struct bpf_audit_context *ac,
				    const char *cause__str)
{
	if (log_once(ac, BIT_ULL(LSM_AUDIT_DATA_CAUSE)))
		return -EINVAL;

	audit_log_format(ac->ab, " cause=");
	audit_log_untrustedstring(ac->ab, cause__str);
	return 0;
}

__bpf_kfunc int bpf_audit_log_cap(struct bpf_audit_context *ac, int cap)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_CAP;
	ad.u.cap = cap;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_path(struct bpf_audit_context *ac,
				   const struct path *path)
{
	struct common_audit_data ad;

	/* DATA_PATH prints similar to DATA_FILE */
	if (log_once(ac, BIT_ULL(LSM_AUDIT_DATA_FILE)))
		return -EINVAL;

	ad.type = LSM_AUDIT_DATA_PATH;
	ad.u.path = *path;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_file(struct bpf_audit_context *ac,
				   struct file *file)
{
	struct common_audit_data ad;

	/* DATA_PATH prints similar to DATA_FILE */
	if (log_once(ac, BIT_ULL(LSM_AUDIT_DATA_PATH)))
		return -EINVAL;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_ioctl_op(struct bpf_audit_context *ac,
				       struct file *file, u16 cmd)
{
	struct lsm_ioctlop_audit op = { .path = file->f_path, .cmd = cmd };
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_IOCTL_OP;
	ad.u.op = &op;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_dentry(struct bpf_audit_context *ac,
				     struct dentry *dentry)
{
	struct common_audit_data ad;

	/* DATA_DENTRY prints similar to DATA_INODE */
	if (log_once(ac, BIT_ULL(LSM_AUDIT_DATA_INODE)))
		return -EINVAL;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_inode(struct bpf_audit_context *ac,
				    struct inode *inode)
{
	struct common_audit_data ad;

	/* DATA_DENTRY prints similar to DATA_INODE */
	if (log_once(ac, BIT_ULL(LSM_AUDIT_DATA_DENTRY)))
		return -EINVAL;

	ad.type = LSM_AUDIT_DATA_INODE;
	ad.u.inode = inode;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_task(struct bpf_audit_context *ac,
				   struct task_struct *tsk)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_TASK;
	ad.u.tsk = tsk;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int bpf_audit_log_net_sock(struct bpf_audit_context *ac, int netif,
				       const struct socket *sock)
{
	struct lsm_network_audit net = { .sk = sock->sk, .netif = netif };
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_NET;
	ad.u.net = &net;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc int
bpf_audit_log_net_sockaddr(struct bpf_audit_context *ac, int netif,
			   const struct sockaddr *saddr__nullable,
			   const struct sockaddr *daddr__nullable, int addrlen)
{
	struct lsm_network_audit net;
	struct common_audit_data ad;

	net.netif = netif;

	if (!saddr__nullable && !daddr__nullable)
		return -EINVAL;

	if (saddr__nullable && daddr__nullable &&
	    saddr__nullable->sa_family != daddr__nullable->sa_family)
		return -EINVAL;

	if (saddr__nullable)
		net.family = saddr__nullable->sa_family;
	else
		net.family = daddr__nullable->sa_family;

	switch (net.family) {
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		if (addrlen < SIN6_LEN_RFC2133)
			return -EINVAL;

		if (saddr__nullable) {
			struct sockaddr_in6 *saddr =
				(struct sockaddr_in6 *)saddr__nullable;
			net.fam.v6.saddr = saddr->sin6_addr;
			net.sport = saddr->sin6_port;
		}

		if (daddr__nullable) {
			struct sockaddr_in6 *daddr =
				(struct sockaddr_in6 *)daddr__nullable;
			net.fam.v6.daddr = daddr->sin6_addr;
			net.dport = daddr->sin6_port;
		}
		break;
#endif
	case AF_INET:
		if (addrlen < sizeof(struct sockaddr_in))
			return -EINVAL;

		if (saddr__nullable) {
			struct sockaddr_in *saddr =
				(struct sockaddr_in *)saddr__nullable;
			net.fam.v4.saddr = saddr->sin_addr.s_addr;
			net.sport = saddr->sin_port;
		}

		if (daddr__nullable) {
			struct sockaddr_in *daddr =
				(struct sockaddr_in *)daddr__nullable;
			net.fam.v4.daddr = daddr->sin_addr.s_addr;
			net.dport = daddr->sin_port;
		}
		break;
	default:
		return -EAFNOSUPPORT;
	}

	ad.type = LSM_AUDIT_DATA_NET;
	ad.u.net = &net;
	return __audit_log_lsm_data(ac, &ad);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(lsm_audit_set_ids)

BTF_ID_FLAGS(func, bpf_audit_log_start,
	     KF_ACQUIRE | KF_DESTRUCTIVE | KF_IMPLICIT_ARGS | KF_RET_NULL);

BTF_ID_FLAGS(func, bpf_audit_log_end, KF_DESTRUCTIVE | KF_RELEASE);

/* The following have a recursion opportunity if a LSM is attached to any of
 * the following functions, and a bpf_audit_log_*() is called.
 *  security_current_getlsmprop_subj,
 *  security_lsmprop_to_secctx, or
 *  security_release_secctx
 */
BTF_ID_FLAGS(func, bpf_audit_log_cause, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_cap, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_path, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_file, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_ioctl_op, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_dentry, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_inode, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_task, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_net_sock, KF_DESTRUCTIVE);
BTF_ID_FLAGS(func, bpf_audit_log_net_sockaddr, KF_DESTRUCTIVE);

BTF_KFUNCS_END(lsm_audit_set_ids)

static int bpf_lsm_audit_kfuncs_filter(const struct bpf_prog *prog,
				       u32 kfunc_id)
{
	if (!btf_id_set8_contains(&lsm_audit_set_ids, kfunc_id))
		return 0;

	return prog->type != BPF_PROG_TYPE_LSM ? -EACCES : 0;
}

static const struct btf_kfunc_id_set bpf_lsm_audit_set = {
	.owner = THIS_MODULE,
	.set = &lsm_audit_set_ids,
	.filter = bpf_lsm_audit_kfuncs_filter,
};

static int lsm_audit_init_bpf(void)
{
	int ret;

	ret = bpf_mem_alloc_init(&bpf_audit_context_ma,
				 sizeof(struct bpf_audit_context), false);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
						 &bpf_lsm_audit_set);
}

late_initcall(lsm_audit_init_bpf)
