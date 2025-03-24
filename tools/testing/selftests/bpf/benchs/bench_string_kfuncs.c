// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Red Hat, Inc. */
#include <argp.h>
#include "bench.h"
#include "string_kfuncs_bench.skel.h"

static struct string_kfuncs_ctx {
	struct string_kfuncs_bench *skel;
} ctx;

static struct string_kfuncs_args {
	u32 str_len;
} args = {
	.str_len = 32,
};

enum {
	ARG_STR_LEN = 5000,
};

static const struct argp_option opts[] = {
	{ "str-len", ARG_STR_LEN, "STR_LEN", 0, "Set the length of string(s)" },
	{},
};

static error_t string_kfuncs_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_STR_LEN:
		args.str_len = strtoul(arg, NULL, 10);
		if (!args.str_len ||
		    args.str_len >= sizeof(ctx.skel->bss->str)) {
			fprintf(stderr, "Invalid str len (limit %zu)\n",
				sizeof(ctx.skel->bss->str) - 1);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_string_kfuncs_argp = {
	.options = opts,
	.parser = string_kfuncs_parse_arg,
};

static void string_kfuncs_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "string_kfuncs benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void string_kfuncs_setup(void)
{
	int err;
	char *str;
	size_t i, sz, quarter;

	sz = sizeof(ctx.skel->bss->str);
	if (!sz) {
		fprintf(stderr, "invalid string size (%zu)\n", sz);
		exit(1);
	}

	setup_libbpf();

	ctx.skel = string_kfuncs_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	/* Fill str with random digits 1-9 */
	srandom(time(NULL));
	str = ctx.skel->bss->str;
	for (i = 0; i < args.str_len - 1; i++)
		str[i] = '1' + random() % 9;

	/* For strchr and variants - set the last character to '0' */
	str[args.str_len - 1] = '0';
	str[args.str_len] = '\0';

	/* For strstr and variants - copy the last quarter of str to substr */
	quarter = args.str_len / 4;
	memcpy(ctx.skel->bss->substr, str + args.str_len - quarter, quarter + 1);

	ctx.skel->rodata->str_len = args.str_len;

	err = string_kfuncs_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		string_kfuncs_bench__destroy(ctx.skel);
		exit(1);
	}
}

static void string_kfuncs_attach_prog(struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void string_kfuncs_strlen_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strlen_bench);
}

static void string_kfuncs_strnlen_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strnlen_bench);
}

static void string_kfuncs_strchr_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strchr_bench);
}

static void string_kfuncs_strnchr_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strnchr_bench);
}

static void string_kfuncs_strchrnul_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strchrnul_bench);
}

static void string_kfuncs_strnchrnul_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strnchrnul_bench);
}

static void string_kfuncs_strstr_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strstr_bench);
}

static void string_kfuncs_strnstr_setup(void)
{
	string_kfuncs_setup();
	string_kfuncs_attach_prog(ctx.skel->progs.strnstr_bench);
}

static void *string_kfuncs_producer(void *ctx)
{
	while (true)
		(void)syscall(__NR_getpgid);
	return NULL;
}

static void string_kfuncs_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

const struct bench bench_string_kfuncs_strlen = {
	.name = "string-kfuncs-strlen",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strlen_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strnlen = {
	.name = "string-kfuncs-strnlen",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strnlen_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strchr = {
	.name = "string-kfuncs-strchr",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strchr_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strnchr = {
	.name = "string-kfuncs-strnchr",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strnchr_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strchrnul = {
	.name = "string-kfuncs-strchrnul",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strchrnul_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strnchrnul = {
	.name = "string-kfuncs-strnchrnul",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strnchrnul_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strstr = {
	.name = "string-kfuncs-strstr",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strstr_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_string_kfuncs_strnstr = {
	.name = "string-kfuncs-strnstr",
	.argp = &bench_string_kfuncs_argp,
	.validate = string_kfuncs_validate,
	.setup = string_kfuncs_strnstr_setup,
	.producer_thread = string_kfuncs_producer,
	.measure = string_kfuncs_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
