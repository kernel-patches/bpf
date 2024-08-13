// SPDX-License-Identifier: GPL-2.0

#include "test_progs.h"
#include "network_helpers.h"
#include "cgroup_helpers.h"
#include "cgroup_ancestor.skel.h"

#define VETH_PREFIX "test_cgid_"
#define VETH_1 VETH_PREFIX "1"
#define VETH_2 VETH_PREFIX "2"
#define CGROUP_PATH "/skb_cgroup_test"
#define TEST_NS "cgroup_ancestor_ns"
#define NUM_CGROUP_LEVELS 4
#define WAIT_AUTO_IP_MAX_ATTEMPT 10
#define DST_ADDR "ff02::1"
#define DST_PORT 1234
#define MAX_ASSERT_NAME 32

struct test_data {
	struct cgroup_ancestor *skel;
	struct bpf_tc_hook qdisc;
	struct bpf_tc_opts tc_attach;
	struct nstoken *ns;
};

static int send_datagram(void)
{
	unsigned char buf[] = "some random test data";
	struct sockaddr_in6 addr = { .sin6_family = AF_INET6,
				     .sin6_port = htons(DST_PORT),
				     .sin6_scope_id = if_nametoindex(VETH_1) };
	int sock, n;

	if (!ASSERT_EQ(inet_pton(AF_INET6, DST_ADDR, &addr.sin6_addr), 1,
		       "inet_pton"))
		return -1;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_OK_FD(sock, "create socket"))
		return sock;

	n = sendto(sock, buf, sizeof(buf), 0, (const struct sockaddr *)&addr,
		   sizeof(addr));
	ASSERT_EQ(n, sizeof(buf), "send data");
	close(sock);

	return n  == sizeof(buf) ? 0 : n;
}

static int wait_local_ip(void)
{
	char *ping_cmd = ping_command(AF_INET6);
	int i, err;

	for (i = 0; i < WAIT_AUTO_IP_MAX_ATTEMPT; i++) {
		err = SYS_NOFAIL("%s -c 1 -W 1 %s%%%s", ping_cmd, DST_ADDR,
				 VETH_1);
		if (!err)
			break;
	}

	return err;
}

static int setup_network(struct test_data *t)
{
	int ret;

	SYS(fail, "ip netns add %s", TEST_NS);
	t->ns = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(t->ns, "open netns"))
		goto cleanup_ns;

	SYS(close_ns, "ip link add dev %s type veth peer name %s",
	    VETH_1, VETH_2);
	SYS(close_ns, "ip link set %s up", VETH_1);
	SYS(close_ns, "ip link set %s up", VETH_2);

	ret = wait_local_ip();
	if (!ASSERT_EQ(ret, 0, "wait local ip"))
		goto cleanup_interfaces;

	memset(&t->qdisc, 0, sizeof(t->qdisc));
	t->qdisc.sz = sizeof(t->qdisc);
	t->qdisc.attach_point = BPF_TC_EGRESS;
	t->qdisc.ifindex = if_nametoindex(VETH_1);
	if (!ASSERT_NEQ(t->qdisc.ifindex, 0, "if_nametoindex"))
		goto cleanup_interfaces;
	if (!ASSERT_OK(bpf_tc_hook_create(&t->qdisc), "qdisc add"))
		goto cleanup_interfaces;

	memset(&t->tc_attach, 0, sizeof(t->tc_attach));
	t->tc_attach.sz = sizeof(t->tc_attach);
	t->tc_attach.prog_fd = bpf_program__fd(t->skel->progs.log_cgroup_id);
	if (!ASSERT_OK(bpf_tc_attach(&t->qdisc, &t->tc_attach), "filter add"))
		goto cleanup_qdisc;

	return 0;

cleanup_qdisc:
	bpf_tc_hook_destroy(&t->qdisc);
cleanup_interfaces:
	SYS_NOFAIL("ip link del %s", VETH_1);
close_ns:
	close_netns(t->ns);
cleanup_ns:
	SYS_NOFAIL("ip netns del %s", TEST_NS);
fail:
	return 1;
}

static void cleanup_network(struct test_data *t)
{
	bpf_tc_detach(&t->qdisc, &t->tc_attach);
	bpf_tc_hook_destroy(&t->qdisc);
	/* Deleting first interface will also delete peer interface */
	SYS_NOFAIL("ip link del %s", VETH_1);
	close_netns(t->ns);
	SYS_NOFAIL("ip netns del %s", TEST_NS);
}

static void check_ancestors_ids(struct test_data *t)
{
	__u64 expected_ids[NUM_CGROUP_LEVELS];
	char assert_name[MAX_ASSERT_NAME];
	__u32 level;

	expected_ids[0] = get_cgroup_id("/.."); /* root cgroup */
	expected_ids[1] = get_cgroup_id("");
	expected_ids[2] = get_cgroup_id(CGROUP_PATH);
	expected_ids[3] = 0; /* non-existent cgroup */

	for (level = 0; level < NUM_CGROUP_LEVELS; level++) {
		snprintf(assert_name, MAX_ASSERT_NAME,
			 "ancestor id at level %d", level);
		ASSERT_EQ(t->skel->bss->cgroup_ids[level], expected_ids[level],
			  assert_name);
	}
}

void test_cgroup_ancestor(void)
{
	struct test_data t;
	int cgroup_fd;

	t.skel = cgroup_ancestor__open_and_load();
	if (!ASSERT_OK_PTR(t.skel, "open and load"))
		return;

	cgroup_fd = cgroup_setup_and_join(CGROUP_PATH);
	if (cgroup_fd < 0)
		goto cleanup_progs;

	if (setup_network(&t))
		goto cleanup_cgroups;

	if (send_datagram())
		goto cleanup_network;

	check_ancestors_ids(&t);

cleanup_network:
	cleanup_network(&t);
cleanup_cgroups:
	close(cgroup_fd);
	cleanup_cgroup_environment();
cleanup_progs:
	cgroup_ancestor__destroy(t.skel);
}
