// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2025 Google LLC.
 */

#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/ipc.h>
#include <linux/bpf_lsm.h>

/*
 * Strong definition of the mmap_file() BPF LSM hook. The __nullable suffix on
 * the struct file pointer parameter name marks it as PTR_MAYBE_NULL. This
 * explicitly enforces that BPF LSM programs check for NULL before attempting to
 * dereference it.
 */
noinline int bpf_lsm_mmap_file(struct file *file__nullable, unsigned long reqprot,
			       unsigned long prot, unsigned long flags)
{
	return 0;
}

/*
 * Strong definition of the inode_init_security() BPF LSM hook. Both the
 * qstr and the xattr array are NULL for some callers, so the __nullable
 * suffix marks it as PTR_MAYBE_NULL. BPF LSM programs have to check before
 * dereferencing them or handing them to bpf_inode_init_xattr().
 */
noinline int bpf_lsm_inode_init_security(struct inode *inode, struct inode *dir,
					 const struct qstr *qstr__nullable,
					 struct xattr *xattrs__nullable,
					 int *xattr_count)
{
	return -EOPNOTSUPP;
}

/*
 * Strong definitions of the IPC control BPF LSM hooks. The informational
 * commands have no object to authorize, so they pass a NULL struct
 * kern_ipc_perm: shmctl_ipc_info() and shmctl_shm_info() call
 * security_shm_shmctl(NULL, IPC_INFO | SHM_INFO), semctl_info() calls
 * security_sem_semctl(NULL, cmd) and msgctl_info() calls
 * security_msg_queue_msgctl(NULL, cmd). The __nullable suffix marks perm as
 * PTR_MAYBE_NULL so that BPF LSM programs have to check it before
 * dereferencing it. Without these overrides the hooks fall back to the
 * __weak prototypes generated from lsm_hook_defs.h in bpf_lsm.c, which carry
 * no annotation and let the verifier type perm as non-nullable.
 */
noinline int bpf_lsm_shm_shmctl(struct kern_ipc_perm *perm__nullable, int cmd)
{
	return 0;
}

noinline int bpf_lsm_sem_semctl(struct kern_ipc_perm *perm__nullable, int cmd)
{
	return 0;
}

noinline int bpf_lsm_msg_queue_msgctl(struct kern_ipc_perm *perm__nullable,
				      int cmd)
{
	return 0;
}
