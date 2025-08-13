// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <uapi/linux/filter.h>
#include <sys/utsname.h>
#include "socket_filter.skel.h"

static int duration;

void do_test(void)
{
	/* the filter below is the tcpdump filter:
	 * tcpdump "not ether host 3c37121a2b3c and not ether host 184ecbca2a3a \
	 * and not ether host 14130b4d3f47 and not ether host f0f61cf440b7 \
	 * and not ether host a84b4dedf471 and not ether host d022be17e1d7 \
	 * and not ether host 5c497967208b and not ether host 706655784d5b"
	 */
	struct sock_filter code[] = {
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x121a2b3c },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 60,  0, 0x00003c37 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0x121a2b3c },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 56,  0, 0x00003c37 },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0xcbca2a3a },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 52,  0, 0x0000184e },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0xcbca2a3a },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 48,  0, 0x0000184e },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x0b4d3f47 },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 44,  0, 0x00001413 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0x0b4d3f47 },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 40,  0, 0x00001413 },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x1cf440b7 },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 36,  0, 0x0000f0f6 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0x1cf440b7 },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 32,  0, 0x0000f0f6 },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x4dedf471 },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 28,  0, 0x0000a84b },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0x4dedf471 },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 24,  0, 0x0000a84b },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0xbe17e1d7 },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 20,  0, 0x0000d022 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0xbe17e1d7 },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15, 16,  0, 0x0000d022 },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x7967208b },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15, 12,  0, 0x00005c49 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  2, 0x7967208b },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15,  8,  0, 0x00005c49 },
		{ 0x20,  0,  0, 0x00000008 },
		{ 0x15,  0,  2, 0x55784d5b },
		{ 0x28,  0,  0, 0x00000006 },
		{ 0x15,  4,  0, 0x00007066 },
		{ 0x20,  0,  0, 0x00000002 },
		{ 0x15,  0,  3, 0x55784d5b },
		{ 0x28,  0,  0, 0x00000000 },
		{ 0x15,  0,  1, 0x00007066 },
		{ 0x06,  0,  0, 0x00000000 },
		{ 0x06,  0,  0, 0x00040000 },
	};
	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(code),
		.filter = code,
	};
	int ret, sock = 0;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (CHECK(sock < 0, "create socket", "errno %d\n", errno))
		return;

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	CHECK(ret < 0, "attach filter", "errno %d\n", errno);

	close(sock);
}

void test_socket_filter(void)
{
	struct socket_filter *skel;
	struct utsname uts;
	int err;

	err = uname(&uts);
	if (err < 0)
		return;

	skel = socket_filter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/* The filter JIT failed on armv6 */
	if (strncmp(uts.machine, "armv6", strlen("armv6")) == 0 &&
	    skel->kconfig->CONFIG_BPF_JIT_ALWAYS_ON)
		test__skip();
	else
		do_test();

	socket_filter__destroy(skel);
}
