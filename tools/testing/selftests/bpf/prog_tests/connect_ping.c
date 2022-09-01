// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2022 Google LLC.
 */

#define _GNU_SOURCE
#include <sys/mount.h>

#include <test_progs.h>
#include <cgroup_helpers.h>
#include <network_helpers.h>

#include "connect_ping.skel.h"

/* 2001:db8::1 */
#define BINDADDR_V6 { { { 0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1 } } }
const struct in6_addr bindaddr_v6 = BINDADDR_V6;

static bool write_sysctl(const char *sysctl, const char *value)
{
	int fd, err, len;

	fd = open(sysctl, O_WRONLY);
	if (!ASSERT_GE(fd, 0, "open-sysctl"))
		return false;

	len = strlen(value);
	err = write(fd, value, len);
	close(fd);
	if (!ASSERT_EQ(err, len, "write-sysctl"))
		return false;

	return true;
}

static void test_ipv4(int cgroup_fd)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t sa_len = sizeof(sa);
	struct connect_ping *obj;
	int sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (!ASSERT_GE(sock_fd, 0, "sock-create"))
		return;

	obj = connect_ping__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		goto close_sock;

	obj->bss->do_bind = 0;

	/* Attach connect v4 and connect v6 progs, connect a v4 ping socket to
	 * localhost, assert that only v4 is called, and called exactly once,
	 * and that the socket's bound address is original loopback address.
	 */
	obj->links.connect_v4_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v4_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v4_prog, "cg-attach-v4"))
		goto close_bpf_object;
	obj->links.connect_v6_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v6_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v6_prog, "cg-attach-v6"))
		goto close_bpf_object;

	if (!ASSERT_OK(connect(sock_fd, (struct sockaddr *)&sa, sa_len),
		       "connect"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations_v4, 1, "invocations_v4"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->invocations_v6, 0, "invocations_v6"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->has_error, 0, "has_error"))
		goto close_bpf_object;

	if (!ASSERT_OK(getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len),
		       "getsockname"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin_family, AF_INET, "sin_family"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin_addr.s_addr, htonl(INADDR_LOOPBACK), "sin_addr"))
		goto close_bpf_object;

close_bpf_object:
	connect_ping__destroy(obj);
close_sock:
	close(sock_fd);
}

static void test_ipv4_bind(int cgroup_fd)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t sa_len = sizeof(sa);
	struct connect_ping *obj;
	int sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (!ASSERT_GE(sock_fd, 0, "sock-create"))
		return;

	obj = connect_ping__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		goto close_sock;

	obj->bss->do_bind = 1;

	/* Attach connect v4 and connect v6 progs, connect a v4 ping socket to
	 * localhost, assert that only v4 is called, and called exactly once,
	 * and that the socket's bound address is address we explicitly bound.
	 */
	obj->links.connect_v4_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v4_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v4_prog, "cg-attach-v4"))
		goto close_bpf_object;
	obj->links.connect_v6_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v6_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v6_prog, "cg-attach-v6"))
		goto close_bpf_object;

	if (!ASSERT_OK(connect(sock_fd, (struct sockaddr *)&sa, sa_len),
		       "connect"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations_v4, 1, "invocations_v4"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->invocations_v6, 0, "invocations_v6"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->has_error, 0, "has_error"))
		goto close_bpf_object;

	if (!ASSERT_OK(getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len),
		       "getsockname"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin_family, AF_INET, "sin_family"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin_addr.s_addr, htonl(0x01010101), "sin_addr"))
		goto close_bpf_object;

close_bpf_object:
	connect_ping__destroy(obj);
close_sock:
	close(sock_fd);
}

static void test_ipv6(int cgroup_fd)
{
	struct sockaddr_in6 sa = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	socklen_t sa_len = sizeof(sa);
	struct connect_ping *obj;
	int sock_fd;

	sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	if (!ASSERT_GE(sock_fd, 0, "sock-create"))
		return;

	obj = connect_ping__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		goto close_sock;

	obj->bss->do_bind = 0;

	/* Attach connect v4 and connect v6 progs, connect a v6 ping socket to
	 * localhost, assert that only v6 is called, and called exactly once,
	 * and that the socket's bound address is original loopback address.
	 */
	obj->links.connect_v4_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v4_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v4_prog, "cg-attach-v4"))
		goto close_bpf_object;
	obj->links.connect_v6_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v6_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v6_prog, "cg-attach-v6"))
		goto close_bpf_object;

	if (!ASSERT_OK(connect(sock_fd, (struct sockaddr *)&sa, sa_len),
		       "connect"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations_v4, 0, "invocations_v4"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->invocations_v6, 1, "invocations_v6"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->has_error, 0, "has_error"))
		goto close_bpf_object;

	if (!ASSERT_OK(getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len),
		       "getsockname"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin6_family, AF_INET6, "sin6_family"))
		goto close_bpf_object;
	if (!ASSERT_EQ(memcmp(&sa.sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)),
		       0, "sin_addr"))
		goto close_bpf_object;

close_bpf_object:
	connect_ping__destroy(obj);
close_sock:
	close(sock_fd);
}

static void test_ipv6_bind(int cgroup_fd)
{
	struct sockaddr_in6 sa = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	socklen_t sa_len = sizeof(sa);
	struct connect_ping *obj;
	int sock_fd;

	sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	if (!ASSERT_GE(sock_fd, 0, "sock-create"))
		return;

	obj = connect_ping__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		goto close_sock;

	obj->bss->do_bind = 1;

	/* Attach connect v4 and connect v6 progs, connect a v6 ping socket to
	 * localhost, assert that only v6 is called, and called exactly once,
	 * and that the socket's bound address is address we explicitly bound.
	 */
	obj->links.connect_v4_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v4_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v4_prog, "cg-attach-v4"))
		goto close_bpf_object;
	obj->links.connect_v6_prog =
		bpf_program__attach_cgroup(obj->progs.connect_v6_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(obj->links.connect_v6_prog, "cg-attach-v6"))
		goto close_bpf_object;

	if (!ASSERT_OK(connect(sock_fd, (struct sockaddr *)&sa, sa_len),
		       "connect"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations_v4, 0, "invocations_v4"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->invocations_v6, 1, "invocations_v6"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->has_error, 0, "has_error"))
		goto close_bpf_object;

	if (!ASSERT_OK(getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len),
		       "getsockname"))
		goto close_bpf_object;
	if (!ASSERT_EQ(sa.sin6_family, AF_INET6, "sin6_family"))
		goto close_bpf_object;
	if (!ASSERT_EQ(memcmp(&sa.sin6_addr, &bindaddr_v6, sizeof(bindaddr_v6)),
		       0, "sin_addr"))
		goto close_bpf_object;

close_bpf_object:
	connect_ping__destroy(obj);
close_sock:
	close(sock_fd);
}

void test_connect_ping(void)
{
	int cgroup_fd;

	if (!ASSERT_OK(unshare(CLONE_NEWNET | CLONE_NEWNS), "unshare"))
		return;

	/* overmount sysfs, and making original sysfs private so overmount
	 * does not propagate to other mntns.
	 */
	if (!ASSERT_OK(mount("none", "/sys", NULL, MS_PRIVATE, NULL),
		       "remount-private-sys"))
		return;
	if (!ASSERT_OK(mount("sysfs", "/sys", "sysfs", 0, NULL),
		       "mount-sys"))
		return;
	if (!ASSERT_OK(mount("bpffs", "/sys/fs/bpf", "bpf", 0, NULL),
		       "mount-bpf"))
		goto clean_mount;

	if (!ASSERT_OK(system("ip link set dev lo up"), "lo-up"))
		goto clean_mount;
	if (!ASSERT_OK(system("ip addr add 1.1.1.1 dev lo"), "lo-addr-v4"))
		goto clean_mount;
	if (!ASSERT_OK(system("ip -6 addr add 2001:db8::1 dev lo"), "lo-addr-v6"))
		goto clean_mount;
	if (!write_sysctl("/proc/sys/net/ipv4/ping_group_range", "0 0"))
		goto clean_mount;

	cgroup_fd = test__join_cgroup("/connect_ping");
	if (!ASSERT_GE(cgroup_fd, 0, "cg-create"))
		goto clean_mount;

	if (test__start_subtest("ipv4"))
		test_ipv4(cgroup_fd);
	if (test__start_subtest("ipv4-bind"))
		test_ipv4_bind(cgroup_fd);

	if (test__start_subtest("ipv6"))
		test_ipv6(cgroup_fd);
	if (test__start_subtest("ipv6-bind"))
		test_ipv6_bind(cgroup_fd);

	close(cgroup_fd);

clean_mount:
	umount2("/sys", MNT_DETACH);
}
