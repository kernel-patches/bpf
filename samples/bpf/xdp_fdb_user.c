// SPDX-License-Identifier: GPL-2.0-only

static const char *__doc__ =
"XDP fdb lookup tool, using BPF_MAP_TYPE_DEVMAP\n"
"Usage: xdp_fdb <IFINDEX_0> <IFINDEX_1> ... <IFINDEX_n>\n";

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include "xdp_fdb.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_MAP_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI |
		  SAMPLE_REDIRECT_MAP_CNT;

DEFINE_SAMPLE_INIT(xdp_fdb);

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "force", no_argument, NULL, 'F' },
	{ "interval", required_argument, NULL, 'i' },
	{ "verbose", no_argument, NULL, 'v' },
	{}
};

#define IFINDEX_LIST_SZ	32
static int ifindex_list[IFINDEX_LIST_SZ];
static int ifindex_num;

int main(int argc, char **argv)
{
	int i, opt, ret = EXIT_FAIL_OPTION;
	bool error = true, force = false;
	unsigned long interval = 2;
	struct xdp_fdb *skel;

	while ((opt = getopt_long(argc, argv, "hFi:v",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'F':
			force = true;
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			sample_switch_mode();
			break;
		case 'h':
			error = false;
		default:
			sample_usage(argv, long_options, __doc__, mask, error);
			return ret;
		}
	}

	if (argc <= optind + 1) {
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	for (i = optind; i < argc && i < IFINDEX_LIST_SZ; i++) {
		int index;

		index = if_nametoindex(argv[i]);

		if (!index)
			index = strtoul(argv[i], NULL, 0);
		if (index)
			ifindex_list[ifindex_num++] = index;
	}

	if (!ifindex_num) {
		fprintf(stderr, "Bad interface index or name\n");
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	skel = xdp_fdb__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_fdb__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = xdp_fdb__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_fdb__load: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_init(skel, mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}

	for (i = 0; i < ifindex_num; i++) {
		if (sample_install_xdp(skel->progs.xdp_fdb_lookup,
				       ifindex_list[i], false, force) < 0) {
			ret = EXIT_FAIL_XDP;
			goto end_destroy;
		}

		if (bpf_map_update_elem(bpf_map__fd(skel->maps.br_ports),
					&ifindex_list[i],
					&ifindex_list[i], 0) < 0) {
			fprintf(stderr, "Failed to update devmap value: %s\n",
				strerror(errno));
			ret = EXIT_FAIL_BPF;
			goto end_destroy;
		}
	}

	ret = sample_run(interval, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}
	ret = EXIT_OK;

end_destroy:
	xdp_fdb__destroy(skel);
end:
	sample_exit(ret);
}
