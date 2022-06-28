// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022, Intel Corporation. */

#define _GNU_SOURCE	/* asprintf() */

#include <bpf/bpf.h>
#include <getopt.h>
#include <net/if.h>
#include <uapi/linux/if_link.h>

#include "test_xdp_meta.skel.h"

struct test_meta_op_opts {
	struct test_xdp_meta	*skel;
	const char		*cmd;
	char			*path;
	__u32			ifindex;
	__u32			flags;
	__u64			btf_id;
	__u32			meta_thresh;
};

struct test_meta_opt_desc {
	const char		*arg;
	const char		*help;
};

#define OPT(n, a, s) {				\
	.name			= #n,		\
	.has_arg		= (a),		\
	.val			= #s[0],	\
}

#define DESC(a, h) {				\
	.arg			= (a),		\
	.help			= (h),		\
}

static const struct option test_meta_opts[] = {
	OPT(dev,		required_argument,	d),
	OPT(fs,			required_argument,	f),
	OPT(help,		no_argument,		h),
	OPT(meta-thresh,	optional_argument,	M),
	OPT(mode,		required_argument,	m),
	{ /* Sentinel */ },
};

static const struct test_meta_opt_desc test_meta_descs[] = {
	DESC("= < IFNAME | IFINDEX >", "target interface name or index"),
	DESC("= < MOUNTPOINT >", "BPF FS mountpoint"),
	DESC(NULL, "display this text and exit"),
	DESC("= [ THRESH ]", "enable Generic metadata generation (frame size)"),
	DESC("= < skb | drv | hw >", "force particular XDP mode"),
};

static void test_meta_usage(char *argv[], bool err)
{
	FILE *out = err ? stderr : stdout;
	__u32 i = 0;

	fprintf(out,
		"Usage:\n\t%s COMMAND < -d | --dev= >  < IFNAME | IFINDEX > [ OPTIONS ]\n\n",
		argv[0]);
	fprintf(out, "OPTIONS:\n");

	for (const struct option *opt = test_meta_opts; opt->name; opt++) {
		fprintf(out, "\t-%c, --%s", opt->val, opt->name);
		fprintf(out, "%s\t", test_meta_descs[i].arg ? : "\t\t");
		fprintf(out, "%s\n", test_meta_descs[i++].help);
	}
}

static int test_meta_link_attach(const struct test_meta_op_opts *opts)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, la_opts,
		    .flags		= opts->flags,
		    .btf_id		= opts->btf_id,
		    .meta_thresh	= opts->meta_thresh);
	struct bpf_link *link;
	int ret;

	link = bpf_program__attach_xdp_opts(opts->skel->progs.ing_hints,
					    opts->ifindex, &la_opts);
	ret = libbpf_get_error(link);
	if (ret) {
		fprintf(stderr, "Failed to attach XDP program: %s (%d)\n",
			strerror(-ret), ret);
		return ret;
	}

	opts->skel->links.ing_hints = link;

	ret = bpf_link__pin(link, opts->path);
	if (ret)
		fprintf(stderr, "Failed to pin XDP link at %s: %s (%d)\n",
			opts->path, strerror(-ret), ret);

	bpf_link__disconnect(link);

	return ret;
}

static int test_meta_link_update(const struct test_meta_op_opts *opts)
{
	LIBBPF_OPTS(bpf_link_update_opts, lu_opts,
		    .xdp.new_btf_id		= opts->btf_id,
		    .xdp.new_meta_thresh	= opts->meta_thresh);
	struct bpf_link *link;
	int ret;

	link = bpf_link__open(opts->path);
	ret = libbpf_get_error(link);
	if (ret) {
		fprintf(stderr, "Failed to open XDP link at %s: %s (%d)\n",
			opts->path, strerror(-ret), ret);
		return ret;
	}

	opts->skel->links.ing_hints = link;

	ret = bpf_link_update(bpf_link__fd(link),
			      bpf_program__fd(opts->skel->progs.ing_hints),
			      &lu_opts);
	if (ret)
		fprintf(stderr, "Failed to update XDP link: %s (%d)\n",
			strerror(-ret), ret);

	return ret;
}

static int test_meta_link_detach(const struct test_meta_op_opts *opts)
{
	struct bpf_link *link;
	int ret;

	link = bpf_link__open(opts->path);
	ret = libbpf_get_error(link);
	if (ret) {
		fprintf(stderr, "Failed to open XDP link at %s: %s (%d)\n",
			opts->path, strerror(-ret), ret);
		return ret;
	}

	opts->skel->links.ing_hints = link;

	ret = bpf_link__unpin(link);
	if (ret) {
		fprintf(stderr, "Failed to unpin XDP link: %s (%d)\n",
			strerror(-ret), ret);
		return ret;
	}

	ret = bpf_link__detach(link);
	if (ret)
		fprintf(stderr, "Failed to detach XDP link: %s (%d)\n",
			strerror(-ret), ret);

	return ret;
}

static int test_meta_parse_args(struct test_meta_op_opts *opts, int argc,
				char *argv[])
{
	int opt, longidx, ret;

	while (1) {
		opt = getopt_long(argc, argv, "d:f:hM::m:", test_meta_opts,
				  &longidx);
		if (opt < 0)
			break;

		switch (opt) {
		case 'd':
			opts->ifindex = if_nametoindex(optarg);
			if (!opts->ifindex)
				opts->ifindex = strtoul(optarg, NULL, 0);

			break;
		case 'f':
			opts->path = optarg;
			break;
		case 'h':
			test_meta_usage(argv, false);
			return 0;
		case 'M':
			ret = libbpf_get_type_btf_id("struct xdp_meta_generic",
						     &opts->btf_id);
			if (ret) {
				fprintf(stderr,
					"Failed to get BTF ID: %s (%d)\n",
					strerror(-ret), ret);
				return ret;
			}

			/* Allow both `-M64` and `-M 64` */
			if (!optarg && optind < argc && argv[optind] &&
			    *argv[optind] >= '0' && *argv[optind] <= '9')
				optarg = argv[optind];

			opts->meta_thresh = strtoul(optarg ? : "1", NULL, 0);
			break;
		case 'm':
			if (!strcmp(optarg, "skb"))
				opts->flags = XDP_FLAGS_SKB_MODE;
			else if (!strcmp(optarg, "drv"))
				opts->flags = XDP_FLAGS_DRV_MODE;
			else if (!strcmp(optarg, "hw"))
				opts->flags = XDP_FLAGS_HW_MODE;

			if (opts->flags)
				break;

			/* fallthrough */
		default:
			test_meta_usage(argv, true);
			return -EINVAL;
		}
	}

	if (optind >= argc || !argv[optind]) {
		fprintf(stderr, "Command is required\n");
		test_meta_usage(argv, true);

		return -EINVAL;
	}

	opts->cmd = argv[optind];

	return 0;
}

int main(int argc, char *argv[])
{
	struct test_meta_op_opts opts = { };
	int ret;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (argc < 3) {
		test_meta_usage(argv, true);
		return -EINVAL;
	}

	ret = test_meta_parse_args(&opts, argc, argv);
	if (ret)
		return ret;

	if (!opts.ifindex) {
		fprintf(stderr, "Invalid or missing device argument\n");
		test_meta_usage(argv, true);

		return -EINVAL;
	}

	opts.skel = test_xdp_meta__open_and_load();
	ret = libbpf_get_error(opts.skel);
	if (ret) {
		fprintf(stderr, "Failed to load test_xdp_meta skeleton: %s (%d)\n",
			strerror(-ret), ret);
		return ret;
	}

	ret = asprintf(&opts.path, "%s/xdp/%s-%u", opts.path ? : "/sys/fs/bpf",
		       opts.skel->skeleton->name, opts.ifindex);
	ret = ret < 0 ? -errno : 0;
	if (ret) {
		fprintf(stderr, "Failed to allocate path string: %s (%d)\n",
			strerror(-ret), ret);
		goto meta_destroy;
	}

	if (!strcmp(opts.cmd, "attach")) {
		ret = test_meta_link_attach(&opts);
	} else if (!strcmp(opts.cmd, "update")) {
		ret = test_meta_link_update(&opts);
	} else if (!strcmp(opts.cmd, "detach")) {
		ret = test_meta_link_detach(&opts);
	} else {
		fprintf(stderr, "Invalid command '%s'\n", opts.cmd);
		test_meta_usage(argv, true);

		ret = -EINVAL;
	}

	if (ret)
		fprintf(stderr, "Failed to execute command '%s': %s (%d)\n",
			opts.cmd, strerror(-ret), ret);

	free(opts.path);
meta_destroy:
	test_xdp_meta__destroy(opts.skel);

	return ret;
}
