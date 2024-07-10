// SPDX-License-Identifier: GPL-2.0
/**
 * Create 3 namespaces with 3 veth peers, and
 * forward packets in-between using native XDP
 *
 *                      XDP_TX
 * NS1(veth11)        NS2(veth22)        NS3(veth33)
 *      |                  |                  |
 *      |                  |                  |
 *   (veth1,            (veth2,            (veth3,
 *   id:111)            id:122)            id:133)
 *     ^ |                ^ |                ^ |
 *     | |  XDP_REDIRECT  | |  XDP_REDIRECT  | |
 *     | ------------------ ------------------ |
 *     -----------------------------------------
 *                    XDP_REDIRECT
 */

#define _GNU_SOURCE
#include <net/if.h>
#include "test_progs.h"
#include "network_helpers.h"
#include "xdp_dummy.skel.h"
#include "xdp_redirect_map.skel.h"
#include "xdp_tx.skel.h"

#define VETH_PAIRS_COUNT	3
#define NS_NAME_MAX_LEN		16
#define NS_SUFFIX_LEN		6
#define VETH_NAME_MAX_LEN	16
#define IP_SRC				"10.1.1.11"
#define IP_DST				"10.1.1.33"
#define IP_CMD_MAX_LEN		128

struct skeletons {
	struct xdp_dummy *xdp_dummy;
	struct xdp_tx *xdp_tx;
	struct xdp_redirect_map *xdp_redirect_maps;
};

struct veth_configuration {
	char local_veth[VETH_NAME_MAX_LEN]; /* Interface in main namespace */
	char remote_veth[VETH_NAME_MAX_LEN]; /* Peer interface in dedicated namespace*/
	char namespace[NS_NAME_MAX_LEN]; /* Namespace for the remote veth */
	char next_veth[VETH_NAME_MAX_LEN]; /* Local interface to redirect traffic to */
	char *remote_addr; /* IP address of the remote veth */
};

static struct veth_configuration config[VETH_PAIRS_COUNT] = {
	{
		.local_veth = "veth1",
		.remote_veth = "veth11",
		.next_veth = "veth2",
		.remote_addr = IP_SRC
	},
	{
		.local_veth = "veth2",
		.remote_veth = "veth22",
		.next_veth = "veth3",
		.remote_addr = NULL
	},
	{
		.local_veth = "veth3",
		.remote_veth = "veth33",
		.next_veth = "veth1",
		.remote_addr = IP_DST
	}
};

static int libbpf_debug_print(enum libbpf_print_level level,
			      const char *format, va_list args)
{
	if (level != LIBBPF_WARN)
		vprintf(format, args);
	return 0;
}

static void generate_random_ns_name(int index, char *out)
{
	int random, count, i;

	count = snprintf(out, NS_NAME_MAX_LEN, "ns%d-", index);
	for(i=0; i<NS_SUFFIX_LEN; i++) {
		random=rand() % 2;
		out[count++]= random ? 'a' + rand() % 26 : 'A' + rand() % 26;
	}
	out[count] = 0;
}

static int attach_programs_to_veth_pair(struct skeletons *skeletons, int index)
{
	struct bpf_program *local_prog, *remote_prog;
	struct nstoken *nstoken;
	struct bpf_link *link;
	int interface;

	switch(index) {
		case 0:
			local_prog = skeletons->xdp_redirect_maps->progs.xdp_redirect_map_0;
			remote_prog = skeletons->xdp_dummy->progs.xdp_dummy_prog;
			break;
		case 1:
			local_prog = skeletons->xdp_redirect_maps->progs.xdp_redirect_map_1;
			remote_prog = skeletons->xdp_tx->progs.xdp_tx;
			break;
		case 2:
			local_prog = skeletons->xdp_redirect_maps->progs.xdp_redirect_map_2;
			remote_prog = skeletons->xdp_dummy->progs.xdp_dummy_prog;
			break;
	}
	interface = if_nametoindex(config[index].local_veth);
	link = bpf_program__attach_xdp(local_prog, interface);
	if (!ASSERT_OK_PTR(link, "attach xdp program to local veth"))
		return -1;
	nstoken = open_netns(config[index].namespace);
	if (!ASSERT_OK_PTR(nstoken, "switch to remote veth namespace"))
		return -1;
	interface = if_nametoindex(config[index].remote_veth);
	link = bpf_program__attach_xdp(remote_prog, interface);
	close_netns(nstoken);
	if (!ASSERT_OK_PTR(link, "attach xdp program to remote veth"))
		return -1;

	return 0;
}

static int configure_network(struct skeletons *skeletons) {
	int interface_id;
	int map_fd;
	int err;
	int i=0;

	/* First create and configure all interfaces */
	for(i=0; i<VETH_PAIRS_COUNT; i++) {
		generate_random_ns_name(i+1, config[i].namespace);

		SYS(fail, "ip netns add %s", config[i].namespace);
		SYS(fail, "ip link add %s type veth peer name %s netns %s",
				config[i].local_veth,
				config[i].remote_veth,
				config[i].namespace);
		SYS(fail, "ip link set dev %s up", config[i].local_veth);
		if (config[i].remote_addr)
			SYS(fail, "ip -n %s addr add %s/24 dev %s",
					   config[i].namespace, config[i].remote_addr, config[i].remote_veth);
		SYS(fail, "ip -n %s link set dev %s up",
				   config[i].namespace, config[i].remote_veth);
	}

	/* Then configure the redirect map and attach programs to interfaces */
	map_fd = bpf_map__fd(skeletons->xdp_redirect_maps->maps.tx_port);
	if (!ASSERT_GE(map_fd, 0, "open redirect map"))
		goto fail;
	for (i=0; i<VETH_PAIRS_COUNT; i++) {
		interface_id = if_nametoindex(config[i].next_veth);
		err = bpf_map_update_elem(map_fd, &i, &interface_id, BPF_ANY);
		if (!ASSERT_OK(err, "configure interface redirection through map"))
			goto fail;
		if(attach_programs_to_veth_pair(skeletons, i))
			goto fail;
	}

	return 0;

fail:
	return -1;
}

static void cleanup_network()
{
	char cmd[IP_CMD_MAX_LEN];
	int i;

	/* Deleting namespaces is enough to automatically remove veth pairs as well
	 */
	for(i=0; i<VETH_PAIRS_COUNT; i++) {
		if(config[i].namespace[0] == 0)
			continue;
		snprintf(cmd, IP_CMD_MAX_LEN, "ip netns del %s", config[i].namespace);
		system(cmd);
	}
}

static int check_ping(struct skeletons *skeletons)
{
	char cmd[IP_CMD_MAX_LEN];

	/* Test: if all interfaces are properly configured, we must be able to ping
	 * veth33 from veth11
	 */
	snprintf(cmd, IP_CMD_MAX_LEN,
			 "ip netns exec %s ping -c 1 -W 1 %s > /dev/null",
			 config[0].namespace, IP_DST);
	return system(cmd);
}

static void stop_handler(int signal)
{
	/* Make sure to remove any veth or namespace if we have to stop the test
	 * early
	 */
	cleanup_network();
	exit(1);
}

void test_xdp_veth_redirect()
{
	struct skeletons skeletons = {};
	libbpf_print_fn_t old_print_fn;

	signal(SIGTERM, stop_handler);
	signal(SIGSTOP, stop_handler);

	old_print_fn = libbpf_set_print(libbpf_debug_print);

	skeletons.xdp_dummy = xdp_dummy__open_and_load();
	if (!ASSERT_OK_PTR(skeletons.xdp_dummy, "xdp_dummy__open_and_load"))
		goto out;

	skeletons.xdp_tx = xdp_tx__open_and_load();
	if (!ASSERT_OK_PTR(skeletons.xdp_tx, "xdp_tx__open_and_load"))
		goto out;

	skeletons.xdp_redirect_maps = xdp_redirect_map__open_and_load();
	if (!ASSERT_OK_PTR(skeletons.xdp_redirect_maps, "xdp_redirect_map__open_and_load"))
		goto out;

	if(configure_network(&skeletons))
		goto out;

	ASSERT_OK(check_ping(&skeletons), "ping");

out:
	cleanup_network();
	xdp_dummy__destroy(skeletons.xdp_dummy);
	xdp_tx__destroy(skeletons.xdp_tx);
	xdp_redirect_map__destroy(skeletons.xdp_redirect_maps);
	libbpf_set_print(old_print_fn);
}
