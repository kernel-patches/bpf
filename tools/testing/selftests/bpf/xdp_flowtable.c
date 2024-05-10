// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <argp.h>

#include "xdp_flowtable.skel.h"

#define MAX_ITERATION	10

static volatile bool exiting, verbosity;
static char ifname[IF_NAMESIZE];
static int ifindex = -ENODEV;
const char *argp_program_version = "xdp-flowtable 0.0";
const char argp_program_doc[] =
"XDP flowtable application.\n"
"\n"
"USAGE: ./xdp-flowtable [-v] <iface-name>\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbosity)
		return 0;
	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbosity = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "Invalid device name: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}

		ifindex = if_nametoindex(arg);
		if (!ifindex)
			ifindex = strtoul(arg, NULL, 0);
		if (!ifindex || !if_indextoname(ifindex, ifname)) {
			fprintf(stderr,
				"Bad interface index or name (%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

int main(int argc, char **argv)
{
	unsigned int count = 0, key = 0;
	struct xdp_flowtable *skel;
	int i, err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Load and verify BPF application */
	skel = xdp_flowtable__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -EINVAL;
	}

	/* Load & verify BPF programs */
	err = xdp_flowtable__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach the XDP program */
	err = xdp_flowtable__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	err = bpf_xdp_attach(ifindex,
			     bpf_program__fd(skel->progs.xdp_flowtable_do_lookup),
			     XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		fprintf(stderr, "Failed attaching XDP program to device %s\n",
			ifname);
		goto cleanup;
	}

	/* Collect stats */
	for (i = 0; i < MAX_ITERATION && !exiting; i++)
		sleep(1);

	/* Check results */
	err = bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key),
				   &count, sizeof(count), 0);
	if (!err && !count)
		err = -EINVAL;

	bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
cleanup:
	xdp_flowtable__destroy(skel);

	return err;
}
