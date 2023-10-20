// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/nsproxy.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/debugfs.h>
#include <net/sock.h>

#define BIND    0
#define CONNECT 1
#define SENDMSG 2

#define CONNECT_TIMEOUT_SEC 1

static char ip[256];
module_param_string(ip, ip, sizeof(ip), 0644);
MODULE_PARM_DESC(ip, "IPv4/IPv6/Unix address to use for socket operation");
static char port[7];
module_param_string(port, port, sizeof(port), 0644);
MODULE_PARM_DESC(port, "Port number to use for socket operation");
static uint af;
module_param(af, uint, 0644);
MODULE_PARM_DESC(af, "Address family (AF_INET, AF_INET6, or AF_UNIX)");
static int type;
module_param(type, int, 0644);
MODULE_PARM_DESC(type, "Socket type (SOCK_STREAM or SOCK_DGRAM)");
static uint op;
module_param(op, uint, 0644);
MODULE_PARM_DESC(op, "Socket operation (BIND=0, CONNECT=1, SENDMSG=2)");

static struct debugfs_blob_wrapper sock_name_blob;
static struct debugfs_blob_wrapper peer_name_blob;
static struct debugfs_blob_wrapper addr_blob;
static struct dentry *debugfs_dentry;
static struct sockaddr_storage sock_name;
static struct sockaddr_storage peer_name;
static struct sockaddr_storage addr;
static bool success;

static struct socket *sock = NULL;

static int do_kernel_bind(struct sockaddr *addr, int addrlen)
{
	int err;

	err = kernel_bind(sock, (struct sockaddr *)addr, addrlen);
	if (err) {
		pr_err("kernel_bind() returned %d\n", err);
		goto err;
	}

	err = kernel_getsockname(sock, (struct sockaddr *)&sock_name);
	if (err < 0) {
		pr_err("kernel_getsockname() returned %d\n", err);
		goto err;
	}

	if (type == SOCK_STREAM) {
		err = kernel_listen(sock, 128);
		if (err == -1) {
			pr_err("kernel_listen() returned %d\n", err);
			goto err;
		}
	}

	err = 0;
	goto out;
err:
	err = -1;
out:
	return err;
}

static int do_kernel_connect(struct sockaddr *addr, int addrlen)
{
	int err;

	/* Set timeout for call to kernel_connect() to prevent it from hanging,
	 * and consider the connection attempt failed if it returns
	 * -EINPROGRESS.
	 */
	sock->sk->sk_sndtimeo = CONNECT_TIMEOUT_SEC * HZ;

	err = kernel_connect(sock, addr, addrlen, 0);
	if (err) {
		pr_err("kernel_connect() returned %d\n", err);
		goto err;
	}

	err = kernel_getsockname(sock, (struct sockaddr *)&sock_name);
	if (err < 0) {
		pr_err("kernel_getsockname() returned %d\n", err);
		goto err;
	}

	err = kernel_getpeername(sock, (struct sockaddr *)&peer_name);
	if (err < 0) {
		pr_err("kernel_getpeername() returned %d\n", err);
		goto err;
	}

	err = 0;
	goto out;
err:
	err = -1;
out:
	return err;
}

static int do_kernel_sendmsg(struct sockaddr *addr, int addrlen)
{
	struct msghdr msg = {
		.msg_name	= addr,
		.msg_namelen	= addrlen,
	};
	struct kvec iov;
	int err;

	iov.iov_base = "abc";
	iov.iov_len  = sizeof("abc");

	err = kernel_sendmsg(sock, &msg, &iov, 1, sizeof("abc"));
	if (err < 0) {
		pr_err("kernel_sendmsg() returned %d\n", err);
		goto err;
	}

	/* kernel_sendmsg() and sock_sendmsg() are both used throughout the
	 * kernel. Neither of these functions should modify msg_name, so call
	 * both just to make sure.
	 */
	iov_iter_kvec(&msg.msg_iter, ITER_SOURCE, &iov, 1, sizeof("abc"));
	err = sock_sendmsg(sock, &msg);
	if (err < 0) {
		pr_err("sock_sendmsg() returned %d\n", err);
		goto err;
	}

	err = 0;
	goto out;
err:
	err = -1;
out:
	return err;
}

static int do_sock_op(int op, struct sockaddr *addr, int addrlen)
{
	switch (op) {
	case BIND:
		return do_kernel_bind(addr, addrlen);
	case CONNECT:
		return do_kernel_connect(addr, addrlen);
	case SENDMSG:
		return do_kernel_sendmsg(addr, addrlen);
	default:
		return -EINVAL;
	}
}

static int kernel_sock_addr_testmod_init(void)
{
	int addr_len = sizeof(struct sockaddr_storage);
	int proto;
	int err;

	debugfs_dentry = debugfs_create_dir("sock_addr_testmod", NULL);

	addr_blob.data = &addr;
	addr_blob.size = sizeof(addr);
	sock_name_blob.data = &sock_name;
	sock_name_blob.size = sizeof(sock_name);
	peer_name_blob.data = &peer_name;
	peer_name_blob.size = sizeof(peer_name);

	debugfs_create_blob("addr", 0444, debugfs_dentry, &addr_blob);
	debugfs_create_blob("sock_name", 0444, debugfs_dentry, &sock_name_blob);
	debugfs_create_blob("peer_name", 0444, debugfs_dentry, &peer_name_blob);
	debugfs_create_bool("success", 0444, debugfs_dentry, &success);

	switch (af) {
	case AF_INET:
	case AF_INET6:
		err = inet_pton_with_scope(&init_net, af, ip, port, &addr);
		if (err) {
			pr_err("inet_pton_with_scope() returned %d\n", err);
			goto err;
		}

		proto = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
		break;
	case AF_UNIX:
		memset(&addr, 0, sizeof(addr));
		((struct sockaddr_un *)&addr)->sun_family = AF_UNIX;
		((struct sockaddr_un *)&addr)->sun_path[0] = 0; // abstract
		strcpy(((struct sockaddr_un *)&addr)->sun_path + 1, ip);
		addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + 
			   strlen(ip);
		proto = PF_UNIX;
		pr_info("IP: %s\n", ip);
		pr_info("Unix socket address: %s\n", ((struct sockaddr_un *)&addr)->sun_path + 1);
		break;
	default:
		pr_err("invalid address family %d\n", af);
		goto err;
	}

	err = sock_create_kern(&init_net, af, type, proto, &sock);
	if (err) {
		pr_err("sock_create_kern() returned %d\n", err);
		goto err;
	}

	if (do_sock_op(op, (struct sockaddr *)&addr, addr_len))
		goto err;

	success = true;
	goto out;
err:
	success = false;
out:
	return 0;
}

static void kernel_sock_addr_testmod_exit(void)
{
	if (sock)
		sock_release(sock);

	debugfs_remove_recursive(debugfs_dentry);
}

module_init(kernel_sock_addr_testmod_init);
module_exit(kernel_sock_addr_testmod_exit);

MODULE_AUTHOR("Jordan Rife");
MODULE_DESCRIPTION("BPF socket address selftests module");
MODULE_LICENSE("Dual BSD/GPL");
