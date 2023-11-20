// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/lsm_hooks.h>

extern int mod_lsm_add_hooks(const struct security_hook_mappings *maps);

/* List of registered modular callbacks. */
static struct {
#define LSM_HOOK(RET, DEFAULT, NAME, ...) struct hlist_head NAME;
#include <linux/lsm_hook_defs.h>
} mod_lsm_dynamic_hooks;

#define LSM_RET_DEFAULT(NAME) (NAME##_default)
#define DECLARE_LSM_RET_DEFAULT_void(DEFAULT, NAME)
#define DECLARE_LSM_RET_DEFAULT_int(DEFAULT, NAME) \
	static const int __maybe_unused LSM_RET_DEFAULT(NAME) = (DEFAULT);

#define call_void_hook(FUNC, ...)				\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &mod_lsm_dynamic_hooks.FUNC, list) \
			P->hook.FUNC(__VA_ARGS__);		\
	} while (0)

#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &mod_lsm_dynamic_hooks.FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})

#include <linux/lsm_hook_args.h>
#define LSM_PLAIN_INT_HOOK(RET, DEFAULT, NAME, ...)			\
	static int mod_lsm_##NAME(__VA_ARGS__)				\
	{								\
		struct security_hook_list *P;				\
									\
		hlist_for_each_entry(P, &mod_lsm_dynamic_hooks.NAME, list) { \
			int RC = P->hook.NAME(LSM_CALL_ARGS_##NAME);	\
									\
			if (RC != DEFAULT)				\
				return RC;				\
		}							\
		return DEFAULT;						\
	}
#define LSM_CUSTOM_INT_HOOK LSM_PLAIN_INT_HOOK
#define LSM_SPECIAL_INT_HOOK(RET, DEFAULT, NAME, ...) DECLARE_LSM_RET_DEFAULT_int(DEFAULT, NAME)
#define LSM_PLAIN_VOID_HOOK(RET, DEFAULT, NAME, ...)			\
	static void mod_lsm_##NAME(__VA_ARGS__)				\
	{								\
		struct security_hook_list *P;				\
									\
		hlist_for_each_entry(P, &mod_lsm_dynamic_hooks.NAME, list) \
			P->hook.NAME(LSM_CALL_ARGS_##NAME);		\
	}
#define LSM_CUSTOM_VOID_HOOK(RET, DEFAULT, NAME, ...)
#define LSM_SPECIAL_VOID_HOOK(RET, DEFAULT, NAME, ...) DECLARE_LSM_RET_DEFAULT_void(DEFAULT, NAME)
#include <linux/lsm_hook_defs.h>

static int mod_lsm_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	return call_int_hook(settime, 0, ts, tz);
}

static int mod_lsm_vm_enough_memory(struct mm_struct *mm, long pages)
{
	struct security_hook_list *hp;
	int cap_sys_admin = 1;
	int rc;

	hlist_for_each_entry(hp, &mod_lsm_dynamic_hooks.vm_enough_memory, list) {
		rc = hp->hook.vm_enough_memory(mm, pages);
		if (rc <= 0) {
			cap_sys_admin = 0;
			break;
		}
	}
	return cap_sys_admin;
}

static int mod_lsm_fs_context_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct security_hook_list *hp;
	int trc;
	int rc = -ENOPARAM;

	hlist_for_each_entry(hp, &mod_lsm_dynamic_hooks.fs_context_parse_param, list) {
		trc = hp->hook.fs_context_parse_param(fc, param);
		if (trc == 0)
			rc = 0;
		else if (trc != -ENOPARAM)
			return trc;
	}
	return rc;
}

static int mod_lsm_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr, struct xattr *xattrs,
				       int *xattr_count)
{
	struct security_hook_list *hp;
	int ret = -EOPNOTSUPP;

	hlist_for_each_entry(hp, &mod_lsm_dynamic_hooks.inode_init_security, list) {
		ret = hp->hook.inode_init_security(inode, dir, qstr, xattrs, xattr_count);
		if (ret && ret != -EOPNOTSUPP)
			return ret;
	}
	return ret;
}

static void mod_lsm_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value,
					size_t size, int flags)
{
	call_void_hook(inode_post_setxattr, dentry, name, value, size, flags);
}

static void mod_lsm_task_free(struct task_struct *task)
{
	call_void_hook(task_free, task);
}

static void mod_lsm_cred_free(struct cred *cred)
{
	call_void_hook(cred_free, cred);
}

static void mod_lsm_cred_transfer(struct cred *new, const struct cred *old)
{
	call_void_hook(cred_transfer, new, old);
}

static void mod_lsm_cred_getsecid(const struct cred *c, u32 *secid)
{
	call_void_hook(cred_getsecid, c, secid);
}

static void mod_lsm_current_getsecid_subj(u32 *secid)
{
	call_void_hook(current_getsecid_subj, secid);
}

static void mod_lsm_task_getsecid_obj(struct task_struct *p, u32 *secid)
{
	call_void_hook(task_getsecid_obj, p, secid);
}

static int mod_lsm_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			      unsigned long arg4, unsigned long arg5)
{
	int thisrc;
	int rc = LSM_RET_DEFAULT(task_prctl);
	struct security_hook_list *hp;

	hlist_for_each_entry(hp, &mod_lsm_dynamic_hooks.task_prctl, list) {
		thisrc = hp->hook.task_prctl(option, arg2, arg3, arg4, arg5);
		if (thisrc != LSM_RET_DEFAULT(task_prctl)) {
			rc = thisrc;
			if (thisrc != 0)
				break;
		}
	}
	return rc;
}

static int mod_lsm_userns_create(const struct cred *cred)
{
	return call_int_hook(userns_create, 0, cred);
}

static void mod_lsm_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	call_void_hook(ipc_getsecid, ipcp, secid);
}


static void mod_lsm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	call_void_hook(d_instantiate, dentry, inode);
}

static int mod_lsm_getprocattr(struct task_struct *p, const char *name, char **value)
{
	/* Can't work because "lsm" argument is not available. */
	return LSM_RET_DEFAULT(getprocattr);
}

static int mod_lsm_setprocattr(const char *name, void *value, size_t size)
{
	/* Can't work because "lsm" argument is not available. */
	return LSM_RET_DEFAULT(setprocattr);
}

static void mod_lsm_release_secctx(char *secdata, u32 seclen)
{
	call_void_hook(release_secctx, secdata, seclen);
}

static void mod_lsm_inode_invalidate_secctx(struct inode *inode)
{
	call_void_hook(inode_invalidate_secctx, inode);
}

static int mod_lsm_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return call_int_hook(inode_getsecctx, -EOPNOTSUPP, inode, ctx, ctxlen);
}

#ifdef CONFIG_SECURITY_NETWORK
static int mod_lsm_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return call_int_hook(socket_sock_rcv_skb, 0, sk, skb);
}

static int mod_lsm_socket_getpeersec_stream(struct socket *sock, sockptr_t optval,
					    sockptr_t optlen, unsigned int len)
{
	return call_int_hook(socket_getpeersec_stream, -ENOPROTOOPT, sock, optval, optlen, len);
}

static int mod_lsm_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return call_int_hook(socket_getpeersec_dgram, -ENOPROTOOPT, sock, skb, secid);
}

static int mod_lsm_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return call_int_hook(sk_alloc_security, 0, sk, family, priority);
}

static void mod_lsm_sk_free_security(struct sock *sk)
{
	call_void_hook(sk_free_security, sk);
}

static void mod_lsm_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	call_void_hook(sk_clone_security, sk, newsk);
}
#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int mod_lsm_xfrm_state_pol_flow_match(struct xfrm_state *x, struct xfrm_policy *xp,
					     const struct flowi_common *flic)
{
	struct security_hook_list *hp;
	int rc = LSM_RET_DEFAULT(xfrm_state_pol_flow_match);

	hlist_for_each_entry(hp, &mod_lsm_dynamic_hooks.xfrm_state_pol_flow_match, list) {
		rc = hp->hook.xfrm_state_pol_flow_match(x, xp, flic);
		break;
	}
	return rc;
}
#endif

/* Initialize all built-in callbacks here. */
#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_INIT(NAME, mod_lsm_##NAME),
static struct security_hook_list mod_lsm_builtin_hooks[] __ro_after_init = {
#include <linux/lsm_hook_defs.h>
};

static int mod_lsm_enabled __ro_after_init = 1;
static struct lsm_blob_sizes mod_lsm_blob_sizes __ro_after_init = { };

static int __init mod_lsm_init(void)
{
	/* Initialize modular callbacks list. */
#define LSM_HOOK(RET, DEFAULT, NAME, ...) INIT_HLIST_HEAD(&mod_lsm_dynamic_hooks.NAME);
#include <linux/lsm_hook_defs.h>
	/* Register built-in callbacks. */
	security_add_hooks(mod_lsm_builtin_hooks, ARRAY_SIZE(mod_lsm_builtin_hooks), "mod_lsm");
	return 0;
}

DEFINE_LSM(mod_lsm) = {
	.name = "mod_lsm",
	.enabled = &mod_lsm_enabled,
	.flags = 0,
	.blobs = &mod_lsm_blob_sizes,
	.init = mod_lsm_init,
};

/* The only exported function for registering modular callbacks. */
int mod_lsm_add_hooks(const struct security_hook_mappings *maps)
{
	struct security_hook_list *entry;
	int count = 0;

	if (!mod_lsm_enabled) {
		pr_info_once("Loadable LSM support is not enabled.\n");
		return -EOPNOTSUPP;
	}

	/* Count how meny callbacks are implemented. */
#define LSM_HOOK(RET, DEFAULT, NAME, ...) do { if (maps->NAME) count++; } while (0);
#include <linux/lsm_hook_defs.h>
	if (!count)
		return -EINVAL;
	/* Allocate memory for registering implemented callbacks. */
	entry = kmalloc_array(count, sizeof(struct security_hook_list), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	/* Registering imdividual callbacks. */
	count = 0;
#define LSM_HOOK(RET, DEFAULT, NAME, ...) do { if (maps->NAME) {	\
			entry[count].hook.NAME = maps->NAME;		\
			hlist_add_tail_rcu(&entry[count].list, &mod_lsm_dynamic_hooks.NAME); \
			count++;					\
		} } while (0);
#include <linux/lsm_hook_defs.h>
	return 0;
}
EXPORT_SYMBOL_GPL(mod_lsm_add_hooks);
