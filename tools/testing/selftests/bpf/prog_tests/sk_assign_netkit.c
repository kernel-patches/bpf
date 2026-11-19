// SPDX-License-Identifier: GPL-2.0
#include <net/if.h>
#include <netinet/tcp.h>
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include "netlink_helpers.h"
#include "network_helpers.h"
#include "sk_assign_netkit.skel.h"

#define NS_HOST "sk_assign_host"
#define NS_POD "sk_assign_pod"
#define HOST_DEV "nk_host"
#define POD_DEV "nk_pod"
#define DEST_PORT 18080
#define PROXY_PORT 15001
#define TEST_DATA "test"
#define TEST_ITERATIONS 8
#define IO_TIMEOUT_MS 1000
#define POLL_RETRIES 5000
#define POLL_INTERVAL_US 1000

struct netkit_request {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

static int create_netkit(void)
{
	struct rtattr *linkinfo, *data, *peer_info;
	struct rtnl_handle rth = { .fd = -1 };
	struct netkit_request req = {};
	int err;

	err = rtnl_open(&rth, 0);
	if (err)
		return err;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	addattrstrz(&req.n, sizeof(req), IFLA_IFNAME, HOST_DEV);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattrstrz(&req.n, sizeof(req), IFLA_INFO_KIND, "netkit");
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, NETKIT_L2);
	peer_info = addattr_nest(&req.n, sizeof(req), IFLA_NETKIT_PEER_INFO);
	req.n.nlmsg_len += sizeof(struct ifinfomsg);
	addattrstrz(&req.n, sizeof(req), IFLA_IFNAME, POD_DEV);
	addattr_nest_end(&req.n, peer_info);
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);
	rth.flags |= RTNL_HANDLE_F_SUPPRESS_NLERR;
	err = rtnl_talk(&rth, &req.n, NULL);
	if (err)
		err = -errno;
	rtnl_close(&rth);
	return err;
}

static int transparent_socket(int fd, void *opts)
{
	int family = *(int *)opts;
	int one = 1;

	if (family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)))
			return -1;
		return setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one,
				  sizeof(one));
	}
	return setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
}

static void check_timewait(struct sk_assign_netkit *skel, int family,
			   int accepted, int client)
{
	struct __sk_buff ctx = { .ifindex = if_nametoindex(HOST_DEV) };
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	struct sockaddr_storage local, peer;
	socklen_t len = sizeof(local);
	struct sockaddr_in6 *l6, *p6;
	struct sockaddr_in *l4, *p4;
	int i, fd;
	char buf;

	if (!ASSERT_OK(getsockname(accepted, (void *)&local, &len),
		       "timewait_local"))
		return;
	len = sizeof(peer);
	if (!ASSERT_OK(getpeername(accepted, (void *)&peer, &len),
		       "timewait_peer"))
		return;
	if (family == AF_INET) {
		l4 = (void *)&local;
		p4 = (void *)&peer;
		skel->bss->probe_tuple.ipv4.saddr = p4->sin_addr.s_addr;
		skel->bss->probe_tuple.ipv4.daddr = l4->sin_addr.s_addr;
		skel->bss->probe_tuple.ipv4.sport = p4->sin_port;
		skel->bss->probe_tuple.ipv4.dport = l4->sin_port;
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv4);
	} else {
		l6 = (void *)&local;
		p6 = (void *)&peer;
		memcpy(skel->bss->probe_tuple.ipv6.saddr, &p6->sin6_addr,
		       sizeof(p6->sin6_addr));
		memcpy(skel->bss->probe_tuple.ipv6.daddr, &l6->sin6_addr,
		       sizeof(l6->sin6_addr));
		skel->bss->probe_tuple.ipv6.sport = p6->sin6_port;
		skel->bss->probe_tuple.ipv6.dport = l6->sin6_port;
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv6);
	}
	if (!ASSERT_OK(shutdown(accepted, SHUT_WR), "server_shutdown") ||
	    !ASSERT_EQ(recv(client, &buf, 1, 0), 0, "client_eof") ||
	    !ASSERT_OK(shutdown(client, SHUT_WR), "client_shutdown") ||
	    !ASSERT_EQ(recv(accepted, &buf, 1, 0), 0, "server_eof"))
		return;
	fd = bpf_program__fd(skel->progs.probe_timewait);
	for (i = 0; i < POLL_RETRIES; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "probe_timewait"))
			return;
		if (skel->bss->probe_state == BPF_TCP_TIME_WAIT)
			break;
		usleep(POLL_INTERVAL_US);
	}
	ASSERT_EQ(skel->bss->probe_state, BPF_TCP_TIME_WAIT, "timewait_found");
	ASSERT_EQ(skel->bss->probe_result, -EOPNOTSUPP, "timewait_rejected");
}

static int enable_netns_ipv6(const char *name)
{
	struct nstoken *token;
	int err;

	token = open_netns(name);
	if (!token)
		return -1;
	err = write_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	if (!err)
		err = write_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6",
				   "0");
	close_netns(token);
	return err;
}

static void run_netkit(int family)
{
	const char *dest = family == AF_INET ? "198.18.0.99" : "2001:db8:99::99";
	struct network_helper_opts client_opts = { .timeout_ms = IO_TIMEOUT_MS };
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	int server = -1, client = -1, accepted = -1;
	struct netns_obj *host = NULL, *pod = NULL;
	struct sockaddr_storage expected, actual;
	struct sk_assign_netkit *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = transparent_socket,
		.cb_opts = &family,
	};
	char buf[sizeof(TEST_DATA) - 1];
	struct nstoken *pod_tok = NULL;
	struct bpf_link *link = NULL;
	socklen_t len, actual_len;
	int i, err;

	err = socket(family, SOCK_STREAM, 0);
	if (err < 0 && errno == EAFNOSUPPORT) {
		printf("SKIP: address family %d is unavailable\n", family);
		test__skip();
		return;
	}
	if (!ASSERT_GE(err, 0, "family_probe"))
		return;
	close(err);
	host = netns_new(NS_HOST, true);
	if (!ASSERT_NEQ(host, NULL, "host_netns"))
		goto cleanup;
	pod = netns_new(NS_POD, false);
	if (!ASSERT_NEQ(pod, NULL, "pod_netns"))
		goto cleanup;
	if (family == AF_INET6 &&
	    (!ASSERT_OK(enable_netns_ipv6(NS_HOST), "host_ipv6") ||
	     !ASSERT_OK(enable_netns_ipv6(NS_POD), "pod_ipv6")))
		goto cleanup;
	err = create_netkit();
	if (err == -EOPNOTSUPP) {
		printf("SKIP: netkit is unavailable\n");
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "create_netkit"))
		goto cleanup;
	SYS(cleanup, "ip link set %s netns %s", POD_DEV, NS_POD);
	SYS(cleanup, "ip link set %s up", HOST_DEV);
	SYS(cleanup, "ip -n %s link set %s up", NS_POD, POD_DEV);
	if (family == AF_INET) {
		SYS(cleanup, "ip addr add 10.88.0.1/24 dev %s", HOST_DEV);
		SYS(cleanup, "ip -n %s addr add 10.88.0.2/24 dev %s", NS_POD, POD_DEV);
		SYS(cleanup, "ip -n %s route add default via 10.88.0.1", NS_POD);
		SYS(cleanup, "ip route add local 198.18.0.99/32 dev lo");
		if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0"),
			       "rp_filter_all") ||
		    !ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/" HOST_DEV
				   "/rp_filter", "0"),
			       "rp_filter_host"))
			goto cleanup;
	} else {
		SYS(cleanup, "ip -6 addr add fd88::1/64 dev %s nodad", HOST_DEV);
		SYS(cleanup, "ip -n %s -6 addr add fd88::2/64 dev %s nodad", NS_POD, POD_DEV);
		SYS(cleanup, "ip -n %s -6 route add default via fd88::1", NS_POD);
		SYS(cleanup, "ip -6 route add local 2001:db8:99::99/128 dev lo");
	}

	server = start_server_str(family, SOCK_STREAM, bind_addr, PROXY_PORT, &opts);
	if (!ASSERT_GE(server, 0, "start_server"))
		goto cleanup;
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->dest_port = DEST_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	link = bpf_program__attach_netkit(skel->progs.assign_socket,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, DEST_PORT, &expected, &len),
		       "make_sockaddr"))
		goto cleanup;

	for (i = 0; i < TEST_ITERATIONS; i++) {
		pod_tok = open_netns(NS_POD);
		if (!ASSERT_NEQ(pod_tok, NULL, "open_pod"))
			goto cleanup;
		client = connect_to_addr(SOCK_STREAM, &expected, len, &client_opts);
		close_netns(pod_tok);
		pod_tok = NULL;
		if (!ASSERT_GE(client, 0, "connect_client"))
			goto cleanup;
		accepted = accept(server, NULL, NULL);
		if (!ASSERT_GE(accepted, 0, "accept"))
			goto cleanup;
		if (!ASSERT_OK(settimeo(accepted, IO_TIMEOUT_MS),
			       "accepted_timeout"))
			goto cleanup;
		memset(&actual, 0, sizeof(actual));
		actual_len = sizeof(actual);
		if (!ASSERT_OK(getsockname(accepted, (void *)&actual, &actual_len),
			       "getsockname"))
			goto cleanup;
		ASSERT_EQ(actual_len, len, "original_address_len");
		ASSERT_MEMEQ(&actual, &expected, len, "original_destination");
		if (!ASSERT_EQ(send(client, TEST_DATA, sizeof(buf), 0),
			       sizeof(buf), "send_client") ||
		    !ASSERT_EQ(recv(accepted, buf, sizeof(buf), MSG_WAITALL),
			       sizeof(buf), "recv_server") ||
		    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "server_data") ||
		    !ASSERT_EQ(send(accepted, buf, sizeof(buf), 0), sizeof(buf),
			       "send_server") ||
		    !ASSERT_EQ(recv(client, buf, sizeof(buf), MSG_WAITALL),
			       sizeof(buf), "recv_client") ||
		    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "client_data"))
			goto cleanup;
		if (i == TEST_ITERATIONS - 1)
			check_timewait(skel, family, accepted, client);
		close(accepted);
		accepted = -1;
		close(client);
		client = -1;
	}
	if (!ASSERT_OK(bpf_link__detach(link), "detach_netkit"))
		goto cleanup;
	ASSERT_GE(skel->bss->listener_assignments, TEST_ITERATIONS,
		  "listener_assignments");
	ASSERT_GT(skel->bss->established_assignments, 0, "established_assignments");
	ASSERT_GT(skel->bss->request_rejections, 0, "request_rejections");
	ASSERT_EQ(skel->bss->assign_errors, 0, "assign_errors");
cleanup:
	close_netns(pod_tok);
	bpf_link__destroy(link);
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	sk_assign_netkit__destroy(skel);
	netns_free(pod);
	netns_free(host);
}

void test_sk_assign_netkit(void)
{
	if (test__start_subtest("tcpv4"))
		run_netkit(AF_INET);
	if (test__start_subtest("tcpv6"))
		run_netkit(AF_INET6);
}
