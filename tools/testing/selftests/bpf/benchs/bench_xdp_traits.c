// SPDX-License-Identifier: GPL-2.0

#include <argp.h>
#include "bench.h"
#include "bench_xdp_traits.skel.h"

static struct trait_ctx {
	struct bench_xdp_traits *skel;
	int pfd;
} ctx;

static struct trait_args {
	u32 trait_len;
} args = {
	.trait_len = 2,
};

enum {
	ARG_TRAIT_LEN = 6000,
};

static const struct argp_option opts[] = {
	{ "trait-len", ARG_TRAIT_LEN, "TRAIT_LEN", 0,
	  "Set the length of the trait set/get" },
	{},
};

static error_t trait_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_TRAIT_LEN:
		args.trait_len = strtoul(arg, NULL, 10);
		if (args.trait_len != 2 && args.trait_len != 4 && args.trait_len != 8) {
			fprintf(stderr, "Invalid trait length\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_trait_argp = {
	.options = opts,
	.parser = trait_parse_arg,
};

static void trait_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "bpf trait benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void trait_setup(void)
{
	int err, i, key;
	union bpf_attr attr;

	/* Register all keys so we can use them all. */
	bzero(&attr, sizeof(attr));
	for (i = 0; i < 64; i++) {
		key = syscall(__NR_bpf, BPF_REGISTER_TRAIT, &attr, sizeof(attr));
		if (key < 0) {
			fprintf(stderr, "couldn't register trait: %d\n", key);
			exit(1);
		}
	}

	setup_libbpf();

	ctx.skel = bench_xdp_traits__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	ctx.skel->bss->trait_len = args.trait_len;

	err = bench_xdp_traits__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		bench_xdp_traits__destroy(ctx.skel);
		exit(1);
	}
}

static void trait_cleanup(void)
{
	int err, i;
	union bpf_attr attr;

	/* Unregister all keys so we can run again. */
	bzero(&attr, sizeof(attr));
	for (i = 0; i < 64; i++) {
		attr.unregister_trait.trait = i;
		err = syscall(__NR_bpf, BPF_UNREGISTER_TRAIT, &attr, sizeof(attr));
		if (err < 0) {
			fprintf(stderr, "couldn't unregister trait %d: %d\n", i, err);
			exit(1);
		}
	}
}

static void trait_get_setup(void)
{
	trait_setup();
	ctx.pfd = bpf_program__fd(ctx.skel->progs.trait_get);
}

static void trait_set_setup(void)
{
	trait_setup();
	ctx.pfd = bpf_program__fd(ctx.skel->progs.trait_set);
}

static void trait_move_setup(void)
{
	trait_setup();
	ctx.pfd = bpf_program__fd(ctx.skel->progs.trait_move);
}

static void trait_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

static void *trait_producer(void *unused)
{
	static char in[14];
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = in,
		.data_size_in = sizeof(in),
		.repeat = 256, // max
	);

	while (true) {
		err = bpf_prog_test_run_opts(ctx.pfd, &opts);
		if (err != 0) {
			fprintf(stderr, "failed to prog_run: %d\n", err);
			return NULL;
		}
		if (opts.retval != 0) {
			fprintf(stderr, "prog didn't return 0: %d\n", opts.retval);
			return NULL;
		}
	}

	return NULL;
}

const struct bench bench_xdp_trait_get = {
	.name = "xdp-trait-get",
	.argp = &bench_trait_argp,
	.validate = trait_validate,
	.setup = trait_get_setup,
	.producer_thread = trait_producer,
	.measure = trait_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
	.cleanup = trait_cleanup,
};

const struct bench bench_xdp_trait_set = {
	.name = "xdp-trait-set",
	.argp = &bench_trait_argp,
	.validate = trait_validate,
	.setup = trait_set_setup,
	.producer_thread = trait_producer,
	.measure = trait_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
	.cleanup = trait_cleanup,
};

const struct bench bench_xdp_trait_move = {
	.name = "xdp-trait-move",
	.argp = &bench_trait_argp,
	.validate = trait_validate,
	.setup = trait_move_setup,
	.producer_thread = trait_producer,
	.measure = trait_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
	.cleanup = trait_cleanup,
};
