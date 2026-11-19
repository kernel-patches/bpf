// SPDX-License-Identifier: GPL-2.0
#include <net/if.h>
#include <netinet/tcp.h>
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include <stdint.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include "netlink_helpers.h"
#include "network_helpers.h"
#include "unpriv_helpers.h"
#include "sk_assign_netkit.skel.h"
#include "sk_assign_lifetime.skel.h"

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
#define QUEUE_TIMEOUT_MS 5000
#define QUEUE_CLIENT_TIMEOUT_MS 10000

struct queue_request {
	struct nlmsghdr n;
	struct nfgenmsg g;
	char buf[512];
};

struct netkit_request {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

struct queue_worker {
	struct sk_assign_lifetime *skel;
	__u64 *measurement_done;
	__u64 *blocked_syns;
	pthread_t thread;
	bool wait_retransmit;
	int reference_errors;
	int error;
	int fd;
};

static int queue_config(int fd, int type, const void *data, int len)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct queue_request req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg)),
		.n.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.g.version = NFNETLINK_V0,
	};
	struct nlmsgerr *err;
	char reply[512];
	int ret;

	addattr_l(&req.n, sizeof(req), type, data, len);
	ret = sendto(fd, &req, req.n.nlmsg_len, 0, (void *)&addr, sizeof(addr));
	if (ret < 0)
		return -errno;
	ret = recv(fd, reply, sizeof(reply), 0);
	if (ret < 0)
		return -errno;
	if (ret < NLMSG_LENGTH(sizeof(*err)))
		return -EIO;
	if (((struct nlmsghdr *)reply)->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	err = NLMSG_DATA((struct nlmsghdr *)reply);
	return err->error;
}

static int queue_open(void)
{
	struct nfqnl_msg_config_cmd cmd = { .command = NFQNL_CFG_CMD_BIND };
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(UINT16_MAX),
		.copy_mode = NFQNL_COPY_PACKET,
	};
	int fd, err;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (fd < 0)
		return -errno;
	if (bind(fd, (void *)&addr, sizeof(addr)) ||
	    settimeo(fd, QUEUE_TIMEOUT_MS)) {
		err = -errno;
		goto out;
	}
	err = queue_config(fd, NFQA_CFG_CMD, &cmd, sizeof(cmd));
	if (err)
		goto out;
	err = queue_config(fd, NFQA_CFG_PARAMS, &params, sizeof(params));
	if (!err)
		return fd;
out:
	close(fd);
	return err;
}

static bool queue_tracing_target(struct bpf_program *prog, const char *name)
{
	int err;

	err = bpf_program__set_attach_target(prog, 0, name);
	if (err == -ESRCH || err == -ENOENT) {
		printf("SKIP: %s BTF is unavailable\n", name);
		test__skip();
		return false;
	}
	return ASSERT_OK(err, "tracing_target");
}

static void *queue_verdict(void *arg)
{
	struct nfqnl_msg_verdict_hdr verdict = { .verdict = htonl(NF_ACCEPT) };
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct queue_worker *worker = arg;
	struct nfqnl_msg_packet_hdr *hdr;
	struct queue_request req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg)),
		.n.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
		.n.nlmsg_flags = NLM_F_REQUEST,
		.g.version = NFNETLINK_V0,
	};
	char buf[UINT16_MAX + 1];
	__u32 errors, mark = 0;
	struct nlmsghdr *nlh;
	bool packet = false;
	struct rtattr *attr;
	int fd, ret, len, i;

	ret = recv(worker->fd, buf, sizeof(buf), 0);
	if (ret < 0) {
		worker->error = -errno;
		return NULL;
	}
	nlh = (void *)buf;
	if (!NLMSG_OK(nlh, ret) ||
	    nlh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
		worker->error = -EPROTO;
		return NULL;
	}
	len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	attr = (void *)((char *)NLMSG_DATA(nlh) +
		       NLMSG_ALIGN(sizeof(struct nfgenmsg)));
	for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type & NLA_TYPE_MASK) {
		case NFQA_PACKET_HDR:
			if (RTA_PAYLOAD(attr) < sizeof(*hdr))
				goto invalid;
			hdr = RTA_DATA(attr);
			verdict.id = hdr->packet_id;
			packet = true;
			break;
		case NFQA_MARK:
			if (RTA_PAYLOAD(attr) != sizeof(mark))
				goto invalid;
			memcpy(&mark, RTA_DATA(attr), sizeof(mark));
			mark = ntohl(mark);
			break;
		}
	}
	if (!packet || !mark)
		goto invalid;
	if (worker->wait_retransmit) {
		for (i = 0; i < POLL_RETRIES; i++) {
			if (__atomic_load_n(worker->blocked_syns, __ATOMIC_RELAXED))
				break;
			usleep(POLL_INTERVAL_US);
		}
		if (i == POLL_RETRIES)
			worker->error = -ETIMEDOUT;
	}
	fd = bpf_map__fd(worker->skel->maps.observed);
	ret = bpf_map_lookup_elem(fd, &mark, &errors);
	if (ret) {
		worker->error = -errno;
	} else {
		worker->reference_errors = errors;
		if (bpf_map_delete_elem(fd, &mark))
			worker->error = -errno;
	}
	__atomic_store_n(worker->measurement_done, 1, __ATOMIC_RELEASE);
	addattr_l(&req.n, sizeof(req), NFQA_VERDICT_HDR, &verdict, sizeof(verdict));
	ret = sendto(worker->fd, &req, req.n.nlmsg_len, 0,
		     (void *)&addr, sizeof(addr));
	if (ret < 0)
		worker->error = -errno;
	return NULL;
invalid:
	worker->error = -EPROTO;
	return NULL;
}

static bool setup_nfqueue(struct sk_assign_netkit *skel,
			  struct queue_worker *worker, int server, int family,
			  bool retransmit)
{
	const char *nft_family = family == AF_INET ? "ip" : "ip6";
	socklen_t cookie_len = sizeof(__u64);
	struct sk_assign_lifetime *lifetime;
	__u64 cookie;

	if (!kernel_config_has("CONFIG_LTO_NONE=y")) {
		printf("SKIP: queue tracing requires a confirmed non-LTO kernel\n");
		test__skip();
		return false;
	}
	if (!kernel_config_has("CONFIG_DYNAMIC_FTRACE=y")) {
		printf("SKIP: queue tracing requires dynamic ftrace\n");
		test__skip();
		return false;
	}
	if (kernel_config_disabled("CONFIG_NF_TABLES") ||
	    kernel_config_disabled("CONFIG_NFT_QUEUE") ||
	    kernel_config_disabled(family == AF_INET ? "CONFIG_NF_TABLES_IPV4" :
						    "CONFIG_NF_TABLES_IPV6")) {
		printf("SKIP: nftables queue or family support is disabled\n");
		test__skip();
		return false;
	}
	worker->fd = queue_open();
	if (worker->fd == -EPROTONOSUPPORT || worker->fd == -EOPNOTSUPP ||
	    worker->fd == -EINVAL) {
		printf("SKIP: NFQUEUE is unavailable\n");
		test__skip();
		return false;
	}
	if (!ASSERT_GE(worker->fd, 0, "queue_open"))
		return false;
	if (!ASSERT_OK(getsockopt(server, SOL_SOCKET, SO_COOKIE, &cookie,
				  &cookie_len), "listener_cookie"))
		return false;
	worker->skel = sk_assign_lifetime__open();
	lifetime = worker->skel;
	if (!ASSERT_OK_PTR(lifetime, "lifetime_open"))
		return false;
	lifetime->rodata->listener_cookie = cookie;
	bpf_program__set_autoload(lifetime->progs.release_enter, false);
	bpf_program__set_autoload(lifetime->progs.release_exit, false);
	bpf_program__set_autoload(lifetime->progs.release_put, false);
	if (!queue_tracing_target(lifetime->progs.queue_enter, "nf_queue") ||
	    !queue_tracing_target(lifetime->progs.queue_observe,
				  "nfqnl_enqueue_packet"))
		return false;
	if (!ASSERT_OK(sk_assign_lifetime__load(lifetime), "lifetime_load"))
		return false;
	if (!ASSERT_OK(sk_assign_lifetime__attach(lifetime), "lifetime_attach"))
		return false;
	worker->measurement_done = &skel->bss->measurement_done;
	worker->blocked_syns = &skel->bss->blocked_syns;
	worker->wait_retransmit = retransmit;
	SYS(out, "nft add table %s sk_assign", nft_family);
	SYS(out, "nft add chain %s sk_assign pre '%s'", nft_family,
	    "{ type filter hook prerouting priority 0; }");
	SYS(out, "nft add rule %s sk_assign pre meta mark 1 queue num 0",
	    nft_family);
	return ASSERT_OK(pthread_create(&worker->thread, NULL, queue_verdict,
				       worker), "queue_thread");
out:
	return false;
}

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

static void run_netkit(int family, bool nfqueue, bool retransmit)
{
	const char *dest = family == AF_INET ? "198.18.0.99" : "2001:db8:99::99";
	struct queue_worker worker = { .reference_errors = -1, .fd = -1 };
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	int server = -1, client = -1, accepted = -1;
	struct netns_obj *host = NULL, *pod = NULL;
	struct network_helper_opts client_opts = {
		.timeout_ms = IO_TIMEOUT_MS,
	};
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
	bool worker_started = false;
	socklen_t len, actual_len;
	int i, err;

	if (nfqueue && SYS_NOFAIL("nft -v")) {
		printf("Missing required nft tool\n");
		test__skip();
		return;
	}
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
	skel->rodata->measure_queue = nfqueue;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	link = bpf_program__attach_netkit(skel->progs.assign_socket,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, DEST_PORT, &expected, &len),
		       "make_sockaddr"))
		goto cleanup;

	if (nfqueue) {
		if (!setup_nfqueue(skel, &worker, server, family, retransmit))
			goto cleanup;
		worker_started = true;
		client_opts.timeout_ms = QUEUE_CLIENT_TIMEOUT_MS;
	}

	for (i = 0; i < (nfqueue ? 1 : TEST_ITERATIONS); i++) {
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
	ASSERT_GE(skel->bss->listener_assignments,
		  nfqueue ? 1 : TEST_ITERATIONS, "listener_assignments");
	ASSERT_GT(skel->bss->established_assignments, 0, "established_assignments");
	ASSERT_GT(skel->bss->request_rejections, 0, "request_rejections");
	ASSERT_EQ(skel->bss->assign_errors, 0, "assign_errors");
	if (retransmit)
		ASSERT_GT(skel->bss->blocked_syns, 0, "retransmitted_syn_blocked");
cleanup:
	if (worker_started) {
		ASSERT_OK(pthread_join(worker.thread, NULL), "queue_join");
		ASSERT_OK(worker.error, "queue_verdict");
		ASSERT_EQ(worker.reference_errors, 0, "queue_references");
		ASSERT_EQ(worker.skel->bss->queue_errors, 0, "queue_map_errors");
	}
	if (worker.fd >= 0)
		close(worker.fd);
	sk_assign_lifetime__destroy(worker.skel);
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
		run_netkit(AF_INET, false, false);
	if (test__start_subtest("tcpv6"))
		run_netkit(AF_INET6, false, false);
	if (test__start_subtest("tcpv4_nfqueue"))
		run_netkit(AF_INET, true, false);
	if (test__start_subtest("tcpv6_nfqueue"))
		run_netkit(AF_INET6, true, false);
	if (test__start_subtest("tcpv4_nfqueue_retransmit"))
		run_netkit(AF_INET, true, true);
	if (test__start_subtest("tcpv6_nfqueue_retransmit"))
		run_netkit(AF_INET6, true, true);
}
