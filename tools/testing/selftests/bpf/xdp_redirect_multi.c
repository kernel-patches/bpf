// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_IFACE_NUM 32

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int ifaces[MAX_IFACE_NUM] = {};

static void int_exit(int sig)
{
	__u32 prog_id = 0;
	int i;

	for (i = 0; ifaces[i] > 0; i++) {
		if (bpf_get_link_xdp_id(ifaces[i], &prog_id, xdp_flags)) {
			printf("bpf_get_link_xdp_id failed\n");
			exit(1);
		}
		if (prog_id)
			bpf_set_link_xdp_fd(ifaces[i], -1, xdp_flags);
	}

	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] <IFNAME|IFINDEX> <IFNAME|IFINDEX> ...\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n"
		"    -F    force loading prog\n",
		prog);
}

int main(int argc, char **argv)
{
	int prog_fd, group_all, group_v4, group_v6, exclude;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};
	int i, ret, opt, ifindex;
	char ifname[IF_NAMESIZE];
	struct bpf_object *obj;
	char filename[256];

	while ((opt = getopt(argc, argv, "SNF")) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		printf("usage: %s <IFNAME|IFINDEX> <IFNAME|IFINDEX> ...\n", argv[0]);
		return 1;
	}

	printf("Get interfaces");
	for (i = 0; i < MAX_IFACE_NUM && argv[optind + i]; i++) {
		ifaces[i] = if_nametoindex(argv[optind + i]);
		if (!ifaces[i])
			ifaces[i] = strtoul(argv[optind + i], NULL, 0);
		if (!if_indextoname(ifaces[i], ifname)) {
			perror("Invalid interface name or i");
			return 1;
		}
		printf(" %d", ifaces[i]);
	}
	printf("\n");

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	group_all = bpf_object__find_map_fd_by_name(obj, "forward_map_all");
	group_v4 = bpf_object__find_map_fd_by_name(obj, "forward_map_v4");
	group_v6 = bpf_object__find_map_fd_by_name(obj, "forward_map_v6");
	exclude = bpf_object__find_map_fd_by_name(obj, "exclude_map");

	if (group_all < 0 || group_v4 < 0 || group_v6 < 0 || exclude < 0) {
		printf("bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	/* Init forward multicast groups and exclude group */
	for (i = 0; ifaces[i] > 0; i++) {
		ifindex = ifaces[i];

		/* Add all the interfaces to group all */
		ret = bpf_map_update_elem(group_all, &ifindex, &ifindex, 0);
		if (ret) {
			perror("bpf_map_update_elem");
			goto err_out;
		}

		/* For testing: remove the 1st interfaces from group v6 */
		if (i != 0) {
			ret = bpf_map_update_elem(group_v6, &ifindex, &ifindex, 0);
			if (ret) {
				perror("bpf_map_update_elem");
				goto err_out;
			}
		}

		/* For testing: remove the 2nd interfaces from group v4 */
		if (i != 1) {
			ret = bpf_map_update_elem(group_v4, &ifindex, &ifindex, 0);
			if (ret) {
				perror("bpf_map_update_elem");
				goto err_out;
			}
		}

		/* For testing: add the 3rd interfaces to exclude map */
		if (i == 2) {
			ret = bpf_map_update_elem(exclude, &ifindex, &ifindex, 0);
			if (ret) {
				perror("bpf_map_update_elem");
				goto err_out;
			}
		}

		/* bind prog_fd to each interface */
		ret = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
		if (ret) {
			printf("Set xdp fd failed on %d\n", ifindex);
			goto err_out;
		}

	}

	/* sleep some time for testing */
	sleep(999);

	return 0;

err_out:
	return 1;
}
