// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "audit_helpers.h"
#include "test_lsm_audit_kfuncs.skel.h"
#include "test_progs.h"

#ifndef AUDIT_BPF_LSM_ACCESS
#define AUDIT_BPF_LSM_ACCESS 1427
#endif

static inline struct sockaddr_in addr4(void)
{
	return (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_port = htons(1234),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
}

static inline struct sockaddr_in6 addr6(void)
{
	return (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = htons(1234),
		.sin6_addr = in6addr_loopback,
	};
}

static int bind_connect(const struct sockaddr *addr, int addrlen)
{
	int err;
	int sock;
	int opt = 1;
	socklen_t optlen = sizeof(opt);

	sock = socket(addr->sa_family, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(sock, "socket"))
		return 1;

	err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, optlen);
	if (!ASSERT_OK(err, "setsockopt"))
		goto done;

	err = bind(sock, addr, addrlen);
	if (!ASSERT_OK(err, "bind"))
		goto done;

	err = connect(sock, addr, addrlen);
	ASSERT_OK(err, "connect");

	err = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, &optlen);
	ASSERT_OK(err, "getsockopt");

done:
	close(sock);
	return err;
}

static void test_audit_log_sockaddr_src(struct audit_observer *obs,
					struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_in sin = addr4();
	struct sockaddr_in6 sin6 = addr6();
	struct bpf_link *link;

	link = bpf_program__attach_lsm(skel->progs.test_sockaddr_src);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"bind4\" saddr=127.0.0.1 src=1234 netif=lo",
			      1);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"bind6\" saddr=::1 src=1234 netif=lo", 1);

	if (bind_connect((const struct sockaddr *)&sin, sizeof(sin)))
		goto done;

	if (bind_connect((const struct sockaddr *)&sin6, sizeof(sin6)))
		goto done;

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

done:
	bpf_link__destroy(link);
}

static void test_audit_log_sockaddr_dest(struct audit_observer *obs,
					 struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_in sin = addr4();
	struct sockaddr_in6 sin6 = addr6();
	struct bpf_link *link;

	link = bpf_program__attach_lsm(skel->progs.test_sockaddr_dest);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"connect4\" daddr=127.0.0.1 dest=1234 netif=lo",
			      1);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"connect6\" daddr=::1 dest=1234 netif=lo",
			      1);

	if (bind_connect((const struct sockaddr *)&sin, sizeof(sin)))
		goto out;

	if (bind_connect((const struct sockaddr *)&sin6, sizeof(sin6)))
		goto out;

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_sock(struct audit_observer *obs,
				struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_in sin = addr4();
	struct sockaddr_in6 sin6 = addr6();
	struct bpf_link *link;

	link = bpf_program__attach_lsm(skel->progs.test_sock);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"sock4\" laddr=127.0.0.1 lport=1234 faddr=127.0.0.1 fport=1234 netif=lo",
			1);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"sock6\" laddr=::1 lport=1234 faddr=::1 fport=1234 netif=lo",
			1);

	if (bind_connect((const struct sockaddr *)&sin, sizeof(sin)))
		goto out;

	if (bind_connect((const struct sockaddr *)&sin6, sizeof(sin6)))
		goto out;

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_sock_unix(struct audit_observer *obs,
				     struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_un addr;
	struct bpf_link *link;
	char expected[256];
	char sun_path[108];
	int server_fd = -1;
	int opt = 1;
	socklen_t optlen = sizeof(opt);
	int err;

	snprintf(sun_path, sizeof(sun_path), "/root/tmp/bpf_audit_test_%d.sock",
		 getpid());

	/* Ensure directory exists */
	mkdir("/root/tmp", 0755);
	unlink(sun_path);

	link = bpf_program__attach_lsm(skel->progs.test_sock_unix);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	snprintf(expected, sizeof(expected), "cause=\"sock_unix\" path=\"%s\"",
		 sun_path);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS, expected, 1);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sun_path, sizeof(addr.sun_path) - 1);

	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(server_fd, "socket"))
		goto out;

	err = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (!ASSERT_OK(err, "bind"))
		goto out;

	err = getsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, &optlen);
	ASSERT_OK(err, "getsockopt");

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	if (server_fd >= 0)
		close(server_fd);
	unlink(sun_path);
	bpf_link__destroy(link);
}

static void test_audit_log_file(struct audit_observer *obs,
				struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	int err;
	int fd;

	link = bpf_program__attach_lsm(skel->progs.test_file);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"file\" path=\"/dev/null\" dev=\"devtmpfs\" ino=4",
			1);

	fd = open("/dev/null", O_RDONLY);
	close(fd);
	if (!ASSERT_OK_FD(fd, "open(/dev/null)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_path(struct audit_observer *obs,
				struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	int err;
	int fd;

	link = bpf_program__attach_lsm(skel->progs.test_file_path);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"path\" path=\"/dev/null\" dev=\"devtmpfs\" ino=4",
			      1);

	fd = open("/dev/null", O_RDONLY);
	close(fd);
	if (!ASSERT_OK_FD(fd, "open(/dev/null)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_dentry(struct audit_observer *obs,
				  struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	char expected[128];
	char buf[64];
	int err;

	link = bpf_program__attach_lsm(skel->progs.test_dentry);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	snprintf(expected, sizeof(expected),
		 "cause=\"dentry\" name=\"exe\" dev=");
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS, expected, 1);

	/* readlink triggers inode_readlink hook */
	err = readlink("/proc/self/exe", buf, sizeof(buf));
	if (!ASSERT_GT(err, 0, "readlink(/proc/self/exe)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_inode(struct audit_observer *obs,
				 struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	char expected[128];
	struct stat st;
	int err;
	int fd;

	if (!ASSERT_OK(stat("/dev/null", &st), "stat(/dev/null)"))
		return;

	link = bpf_program__attach_lsm(skel->progs.test_inode);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	snprintf(expected, sizeof(expected),
		 "cause=\"inode\" name=\"null\" dev=\"devtmpfs\" ino=%lu",
		 st.st_ino);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS, expected, 1);

	fd = open("/dev/null", O_RDONLY);
	close(fd);
	if (!ASSERT_OK_FD(fd, "open(/dev/null)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_task(struct audit_observer *obs,
				struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	char expected[128];
	pid_t pid;
	int err;

	pid = getpid();

	link = bpf_program__attach_lsm(skel->progs.test_task);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	snprintf(expected, sizeof(expected),
		 "cause=\"task\" opid=%d ocomm=\"test_progs\"", pid);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS, expected, 1);

	err = getpgid(pid);
	if (!ASSERT_GT(err, -1, "pid pgid match"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_cap(struct audit_observer *obs,
			       struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	int err;
	int fd;

	link = bpf_program__attach_lsm(skel->progs.test_cap);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"cap\" capability=", 1);

	fd = open("/proc/kallsyms", O_RDONLY);
	close(fd);
	if (!ASSERT_OK_FD(fd, "open(/proc/kallsyms)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_ioctl_op(struct audit_observer *obs,
				    struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	char expected[128];
	struct stat st;
	int err;
	int fd;

	if (!ASSERT_OK(stat("/dev/null", &st), "stat(/dev/null)"))
		return;

	link = bpf_program__attach_lsm(skel->progs.test_ioctl_op);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	snprintf(expected, sizeof(expected),
		 "cause=\"ioctl_op\" path=\"/dev/null\" dev=\"devtmpfs\" ino=%lu ioctlcmd=0x%x",
		st.st_ino, TCGETS);
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS, expected, 1);

	fd = open("/dev/null", O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open(/dev/null)"))
		goto out;

	/* ioctl will fail with ENOTTY but the LSM hook fires regardless */
	ioctl(fd, TCGETS, NULL);
	close(fd);

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void test_audit_log_sleepable(struct audit_observer *obs,
				     struct test_lsm_audit_kfuncs *skel)
{
	struct bpf_link *link;
	int err;
	int fd;

	link = bpf_program__attach_lsm(skel->progs.test_sleepable);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"sleepable\" path=\"/dev/null\" dev=\"devtmpfs\" ino=4",
		1);

	fd = open("/dev/null", O_RDONLY);
	close(fd);
	if (!ASSERT_OK_FD(fd, "open(/dev/null)"))
		goto out;

	err = audit_observer_wait(obs);
	ASSERT_OK(err, "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

out:
	bpf_link__destroy(link);
}

static void
test_audit_log_sockaddr_both_null(struct audit_observer *obs,
				  struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_in sin = addr4();
	struct bpf_link *link;

	link = bpf_program__attach_lsm(skel->progs.test_sockaddr_both_null);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	/* Should see cause but no saddr/daddr since both were NULL */
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"sockaddr_both_null\"", 1);

	bind_connect((const struct sockaddr *)&sin, sizeof(sin));

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

	bpf_link__destroy(link);
}

static void
test_audit_log_sockaddr_small_addrlen(struct audit_observer *obs,
				      struct test_lsm_audit_kfuncs *skel)
{
	struct sockaddr_in sin = addr4();
	struct bpf_link *link;

	link = bpf_program__attach_lsm(skel->progs.test_sockaddr_small_addrlen);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;

	audit_observer_reset(obs);

	/* Should see cause but no saddr since addrlen was too small */
	audit_observer_expect(obs, AUDIT_BPF_LSM_ACCESS,
			      "cause=\"sockaddr_small_addrlen\"", 1);

	bind_connect((const struct sockaddr *)&sin, sizeof(sin));

	ASSERT_OK(audit_observer_wait(obs), "audit_observer_wait");
	ASSERT_TRUE(audit_observer_check_satisfied(obs),
		    "all expectations met");

	bpf_link__destroy(link);
}

void test_lsm_audit_kfuncs(void)
{
	struct test_lsm_audit_kfuncs *skel = NULL;
	struct audit_observer obs;
	FILE *log = NULL;
	int audit_fd;

	audit_fd = audit_init();
	if (!ASSERT_GE(audit_fd, 0, "audit_init"))
		return;

	if (env.verbosity > VERBOSE_NONE)
		log = env.stdout_saved;

	audit_observer_init(&obs, audit_fd, log, 500);

	skel = test_lsm_audit_kfuncs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel load"))
		goto close_prog;

	if (test__start_subtest("net")) {
		test_audit_log_sockaddr_src(&obs, skel);
		test_audit_log_sockaddr_dest(&obs, skel);
		test_audit_log_sockaddr_both_null(&obs, skel);
		test_audit_log_sockaddr_small_addrlen(&obs, skel);
		test_audit_log_sock(&obs, skel);
		test_audit_log_sock_unix(&obs, skel);
	}

	if (test__start_subtest("file")) {
		test_audit_log_file(&obs, skel);
		test_audit_log_path(&obs, skel);
		test_audit_log_dentry(&obs, skel);
		test_audit_log_inode(&obs, skel);
	}

	if (test__start_subtest("task")) {
		test_audit_log_task(&obs, skel);
		test_audit_log_cap(&obs, skel);
	}

	if (test__start_subtest("ioctl"))
		test_audit_log_ioctl_op(&obs, skel);

	if (test__start_subtest("sleepable"))
		test_audit_log_sleepable(&obs, skel);

close_prog:
	test_lsm_audit_kfuncs__destroy(skel);
	audit_cleanup(audit_fd);
}
