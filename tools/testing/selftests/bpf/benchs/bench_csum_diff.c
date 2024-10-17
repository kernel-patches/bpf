// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates */
#include <argp.h>
#include "bench.h"
#include "csum_diff_bench.skel.h"

static struct csum_diff_ctx {
	struct csum_diff_bench *skel;
	int pfd;
} ctx;

static struct csum_diff_args {
	u32 buff_len;
} args = {
	.buff_len = 32,
};

enum {
	ARG_BUFF_LEN = 5000,
};

static const struct argp_option opts[] = {
	{ "buff-len", ARG_BUFF_LEN, "BUFF_LEN", 0,
	  "Set the length of the buffer" },
	{},
};

static error_t csum_diff_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_BUFF_LEN:
		args.buff_len = strtoul(arg, NULL, 10);
		if (!args.buff_len ||
		    args.buff_len >= sizeof(ctx.skel->rodata->buff)) {
			fprintf(stderr, "Invalid buff len (limit %zu)\n",
				sizeof(ctx.skel->rodata->buff));
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_csum_diff_argp = {
	.options = opts,
	.parser = csum_diff_parse_arg,
};

static void csum_diff_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "csum_diff benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void csum_diff_setup(void)
{
	int err;
	char *buff;
	size_t i, sz;

	sz = sizeof(ctx.skel->rodata->buff);

	setup_libbpf();

	ctx.skel = csum_diff_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	srandom(time(NULL));
	buff = ctx.skel->rodata->buff;

	/*
	 * Set first 8 bytes of buffer to 0xdeadbeefdeadbeef, this is later used to verify the
	 * correctness of the helper by comparing the checksum result for 0xdeadbeefdeadbeef that
	 * should be 0x3b3b
	 */

	*(u64 *)buff = 0xdeadbeefdeadbeef;

	for (i = 8; i < sz; i++)
		buff[i] = '1' + random() % 9;

	ctx.skel->rodata->buff_len = args.buff_len;

	err = csum_diff_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		csum_diff_bench__destroy(ctx.skel);
		exit(1);
	}
}

static void csum_diff_helper_setup(void)
{
	u8 tmp_out[64 << 2] = {};
	u8 tmp_in[64] = {};
	int err, saved_errno;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = tmp_in,
		.data_size_in = sizeof(tmp_in),
		.data_out = tmp_out,
		.data_size_out = sizeof(tmp_out),
		.repeat = 1,
	);
	csum_diff_setup();
	ctx.pfd = bpf_program__fd(ctx.skel->progs.compute_checksum);

	err = bpf_prog_test_run_opts(ctx.pfd, &topts);
	saved_errno = errno;

	if (err) {
		fprintf(stderr, "failed to run setup prog: err %d, result %d, serror %d\n",
			err, ctx.skel->bss->result, saved_errno);
		csum_diff_bench__destroy(ctx.skel);
		exit(1);
	}

	/* Sanity check for correctness of helper */
	if (args.buff_len == 8 && ctx.skel->bss->result != 0x3b3b) {
		fprintf(stderr, "csum_diff helper broken: buff: %lx, result: %x, expected: %x\n",
			*(u64 *)ctx.skel->rodata->buff, ctx.skel->bss->result, 0x3b3b);
	}
}

static void *csum_diff_producer(void *unused)
{
	u8 tmp_out[64 << 2] = {};
	u8 tmp_in[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = tmp_in,
		.data_size_in = sizeof(tmp_in),
		.data_out = tmp_out,
		.data_size_out = sizeof(tmp_out),
		.repeat = 64,
	);
        while (true)
                (void)bpf_prog_test_run_opts(ctx.pfd, &topts);
        return NULL;
}

static void csum_diff_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

const struct bench bench_csum_diff = {
	.name = "csum-diff-helper",
	.argp = &bench_csum_diff_argp,
	.validate = csum_diff_validate,
	.setup = csum_diff_helper_setup,
	.producer_thread = csum_diff_producer,
	.measure = csum_diff_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
