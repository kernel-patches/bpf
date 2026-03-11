// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

char _license[] SEC("license") = "GPL";

SEC("lsm/socket_bind")
int BPF_PROG(test_sockaddr_src, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	switch (address->sa_family) {
	case AF_INET:
		bpf_audit_log_cause(ac, "bind4");
		break;
	case AF_INET6:
		bpf_audit_log_cause(ac, "bind6");
	}

	bpf_audit_log_net_sockaddr(ac, 1, address, NULL, addrlen);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(test_sockaddr_dest, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	switch (address->sa_family) {
	case AF_INET:
		bpf_audit_log_cause(ac, "connect4");
		break;
	case AF_INET6:
		bpf_audit_log_cause(ac, "connect6");
	}

	bpf_audit_log_net_sockaddr(ac, 1, NULL, address, addrlen);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(test_sockaddr_both_null, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "sockaddr_both_null");
	bpf_audit_log_net_sockaddr(ac, 1, NULL, NULL, addrlen);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(test_sockaddr_small_addrlen, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	struct bpf_audit_context *ac;

	if (address->sa_family != AF_INET)
		return -EINVAL;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "sockaddr_small_addrlen");
	bpf_audit_log_net_sockaddr(ac, 1, address, NULL, 1);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(test_sock, struct socket *sock, int level, int optname)
{
	struct bpf_audit_context *ac;
	struct sock *sk = sock->sk;

	if (!sk)
		return -EINVAL;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	switch (sk->__sk_common.skc_family) {
	case AF_INET:
		bpf_audit_log_cause(ac, "sock4");
		break;
	case AF_INET6:
		bpf_audit_log_cause(ac, "sock6");
	}

	bpf_audit_log_net_sock(ac, 1, sock);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(test_sock_unix, struct socket *sock, int level, int optname)
{
	struct bpf_audit_context *ac;
	struct sock *sk = sock->sk;

	if (!sk || sk->__sk_common.skc_family != AF_UNIX)
		return -EINVAL;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "sock_unix");
	bpf_audit_log_net_sock(ac, 0, sock);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_file, struct file *file)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "file");
	bpf_audit_log_file(ac, file);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_file_path, struct file *file)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "path");
	bpf_audit_log_path(ac, &file->f_path);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/inode_readlink")
int BPF_PROG(test_dentry, struct dentry *dentry)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "dentry");
	bpf_audit_log_dentry(ac, dentry);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_inode, struct file *file)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "inode");
	bpf_audit_log_inode(ac, file->f_inode);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/task_getpgid")
int BPF_PROG(test_task, struct task_struct *task)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "task");
	bpf_audit_log_task(ac, task);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/capable")
int BPF_PROG(test_cap, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "cap");
	bpf_audit_log_cap(ac, cap);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm/file_ioctl")
int BPF_PROG(test_ioctl_op, struct file *file, unsigned int cmd,
	     unsigned long arg)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "ioctl_op");
	bpf_audit_log_ioctl_op(ac, file, cmd);
	bpf_audit_log_end(ac);
	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(test_sleepable, struct file *file)
{
	struct bpf_audit_context *ac;

	ac = bpf_audit_log_start();
	if (!ac)
		return -ENOMEM;

	bpf_audit_log_cause(ac, "sleepable");
	bpf_audit_log_file(ac, file);
	bpf_audit_log_end(ac);
	return 0;
}

