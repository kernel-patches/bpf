// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/if_link.h>
#include <net/if.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "netlink_helpers.h"
#include "sk_assign_netkit.skel.h"

#define NS_HOST "sk_assign_host"
#define NS_POD "sk_assign_pod"
#define HOST_DEV "nk_host"
#define POD_DEV "nk0"
#define SERVICE_ADDR4 "198.18.0.99"
#define SERVICE_ADDR6 "2001:db8:99::99"
#define SERVICE_PORT 18080
#define PROXY_PORT 15001
#define TEST_DATA "test"
#define IO_TIMEOUT_MS 1000

struct iplink_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[512];
};

static int transparent_socket(int fd, void *opts)
{
	int one = 1;

	return setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
}

static int create_netkit(void)
{
	struct rtnl_handle rth = { .fd = -1 };
	struct rtattr *linkinfo, *data;
	struct iplink_req req = {};
	int err;

	err = rtnl_open(&rth, 0);
	if (err)
		return err;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	addattrstrz(&req.n, sizeof(req), IFLA_IFNAME, HOST_DEV);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattrstrz(&req.n, sizeof(req), IFLA_INFO_KIND, "netkit");
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, NETKIT_L2);
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);

	errno = 0;
	err = rtnl_talk(&rth, &req.n, NULL);
	if (err && errno)
		err = -errno;
	rtnl_close(&rth);
	return err;
}

static bool setup_netkit(int family, const char *dest)
{
	const char *host = family == AF_INET ? "10.88.0.1" : "fd88::1";
	const char *pod = family == AF_INET ? "10.88.0.2" : "fd88::2";
	const char *dad = family == AF_INET6 ? "nodad" : "";
	int prefix = family == AF_INET ? 24 : 64;

	SYS(fail, "ip link set %s netns %s", POD_DEV, NS_POD);
	SYS(fail, "ip link set %s up", HOST_DEV);
	SYS(fail, "ip -n %s link set %s up", NS_POD, POD_DEV);
	SYS(fail, "ip addr add %s/%d dev %s %s", host, prefix, HOST_DEV, dad);
	SYS(fail, "ip -n %s addr add %s/%d dev %s %s", NS_POD, pod, prefix,
	    POD_DEV, dad);
	SYS(fail, "ip -n %s route add default via %s", NS_POD, host);
	SYS(fail, "ip route add local %s dev lo", dest);
	return true;
fail:
	return false;
}

static void run_netkit(int family, int type)
{
	static const struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = transparent_socket,
	};
	const char *dest = family == AF_INET ? SERVICE_ADDR4 : SERVICE_ADDR6;
	int server = -1, client = -1, accepted = -1;
	struct netns_obj *host = NULL, *pod = NULL;
	struct sk_assign_netkit *skel = NULL;
	struct sockaddr_storage expected;
	unsigned int ifindex;
	struct nstoken *tok;
	socklen_t len;
	int err;

	host = netns_new(NS_HOST, true);
	if (!ASSERT_OK_PTR(host, "host_netns"))
		return;
	pod = netns_new(NS_POD, false);
	if (!ASSERT_OK_PTR(pod, "pod_netns"))
		goto cleanup;
	err = create_netkit();
	if (err == -EOPNOTSUPP || err == -ENODEV) {
		printf("%s:SKIP: CONFIG_NETKIT is unavailable\n", __func__);
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "create_netkit") || !setup_netkit(family, dest))
		goto cleanup;

	server = start_server_str(family, type, NULL, PROXY_PORT, &opts);
	if (!ASSERT_OK_FD(server, "start_server"))
		goto cleanup;
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->service_port = SERVICE_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	ifindex = if_nametoindex(HOST_DEV);
	skel->links.assign_proxy = bpf_program__attach_netkit(
		skel->progs.assign_proxy, ifindex, NULL);
	if (!ASSERT_OK_PTR(skel->links.assign_proxy, "attach_netkit"))
		goto cleanup;
	skel->links.egress_assign = bpf_program__attach_tcx(
		skel->progs.egress_assign, ifindex, NULL);
	if (!ASSERT_OK_PTR(skel->links.egress_assign, "attach_tcx_egress"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, SERVICE_PORT, &expected,
				     &len), "make_sockaddr"))
		goto cleanup;

	tok = open_netns(NS_POD);
	if (!ASSERT_OK_PTR(tok, "open_pod"))
		goto cleanup;
	client = connect_to_addr(type, &expected, len, NULL);
	close_netns(tok);
	if (!ASSERT_OK_FD(client, "connect_client"))
		goto cleanup;
	if (type == SOCK_DGRAM) {
		char buf[sizeof(TEST_DATA) - 1];

		if (!ASSERT_EQ(send(client, TEST_DATA, sizeof(buf), 0),
			       sizeof(buf), "send_client") ||
		    !ASSERT_EQ(recv(server, buf, sizeof(buf), 0),
			       sizeof(buf), "recv_server") ||
		    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "proxy_payload"))
			goto cleanup;
	} else {
		socklen_t actual_len = sizeof(struct sockaddr_storage);
		struct sockaddr_storage actual = {};

		accepted = accept(server, NULL, NULL);
		if (!ASSERT_OK_FD(accepted, "accept") ||
		    !ASSERT_OK(getsockname(accepted, (void *)&actual,
					   &actual_len), "getsockname") ||
		    !ASSERT_EQ(actual_len, len, "original_address_len") ||
		    !ASSERT_MEMEQ(&actual, &expected, len, "original_dst"))
			goto cleanup;
	}
	ASSERT_OK(skel->bss->proxy_err, "assign_and_clone");
	ASSERT_EQ(skel->data->egress_ret, -EOPNOTSUPP, "egress_rejected");
cleanup:
	sk_assign_netkit__destroy(skel);
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	netns_free(pod);
	netns_free(host);
}

void test_sk_assign_netkit(void)
{
	if (test__start_subtest("tcpv4"))
		run_netkit(AF_INET, SOCK_STREAM);
	if (test__start_subtest("tcpv6"))
		run_netkit(AF_INET6, SOCK_STREAM);
	if (test__start_subtest("udpv4"))
		run_netkit(AF_INET, SOCK_DGRAM);
	if (test__start_subtest("udpv6"))
		run_netkit(AF_INET6, SOCK_DGRAM);
}
