// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#define SYS(cmd) ({ \
	if (!ASSERT_OK(system(cmd), (cmd))) \
		goto out; \
})

#define SYS_OUT(cmd) ({ \
	FILE *f = popen((cmd), "r"); \
	if (!ASSERT_OK_PTR(f, (cmd))) \
		goto out; \
	f; \
})

static bool expect_str(char *buf, size_t size, const char *str)
{
	if (size != strlen(str))
		return false;
	return !memcmp(buf, str, size);
}

void test_xdp_synproxy(void)
{
	int server_fd = -1, client_fd = -1, accept_fd = -1;
	struct nstoken *ns = NULL;
	FILE *ctrl_file = NULL;
	char buf[1024];
	size_t size;

	SYS("ip netns add synproxy");

	SYS("ip link add tmp0 type veth peer name tmp1");
	SYS("ip link set tmp1 netns synproxy");
	SYS("ip link set tmp0 up");
	SYS("ip addr replace 198.18.0.1/24 dev tmp0");

	// When checksum offload is enabled, the XDP program sees wrong
	// checksums and drops packets.
	SYS("ethtool -K tmp0 tx off");
	// Workaround required for veth.
	SYS("ip link set tmp0 xdp object xdp_dummy.o section xdp 2> /dev/null");

	ns = open_netns("synproxy");
	if (!ASSERT_OK_PTR(ns, "setns"))
		goto out;

	SYS("ip link set lo up");
	SYS("ip link set tmp1 up");
	SYS("ip addr replace 198.18.0.2/24 dev tmp1");
	SYS("sysctl -w net.ipv4.tcp_syncookies=2");
	SYS("sysctl -w net.ipv4.tcp_timestamps=1");
	SYS("sysctl -w net.netfilter.nf_conntrack_tcp_loose=0");
	SYS("iptables -t raw -I PREROUTING \
	    -i tmp1 -p tcp -m tcp --syn --dport 8080 -j CT --notrack");
	SYS("iptables -t filter -A INPUT \
	    -i tmp1 -p tcp -m tcp --dport 8080 -m state --state INVALID,UNTRACKED \
	    -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460");
	SYS("iptables -t filter -A INPUT \
	    -i tmp1 -m state --state INVALID -j DROP");

	ctrl_file = SYS_OUT("./xdp_synproxy --iface tmp1 --ports 8080 --single \
			    --mss4 1460 --mss6 1460 --wscale 7 --ttl 64");
	size = fread(buf, 1, sizeof(buf), ctrl_file);
	fclose(ctrl_file);
	if (!ASSERT_TRUE(expect_str(buf, size, "Total SYNACKs generated: 0\n"),
			 "initial SYNACKs"))
		goto out;

	server_fd = start_server(AF_INET, SOCK_STREAM, "198.18.0.2", 8080, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto out;

	close_netns(ns);
	ns = NULL;

	client_fd = connect_to_fd(server_fd, 10000);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto out;

	accept_fd = accept(server_fd, NULL, NULL);
	if (!ASSERT_GE(accept_fd, 0, "accept"))
		goto out;

	ns = open_netns("synproxy");
	if (!ASSERT_OK_PTR(ns, "setns"))
		goto out;

	ctrl_file = SYS_OUT("./xdp_synproxy --iface tmp1 --single");
	size = fread(buf, 1, sizeof(buf), ctrl_file);
	fclose(ctrl_file);
	if (!ASSERT_TRUE(expect_str(buf, size, "Total SYNACKs generated: 1\n"),
			 "SYNACKs after connection"))
		goto out;

out:
	if (accept_fd >= 0)
		close(accept_fd);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	if (ns)
		close_netns(ns);

	system("ip link del tmp0");
	system("ip netns del synproxy");
}
