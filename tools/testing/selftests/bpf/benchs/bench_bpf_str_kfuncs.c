// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "bench.h"
#include "bpf_str_kfuncs_bench.skel.h"

#define STR_BENCH_CAP		2048
#define STR_BENCH_SCENARIOS	4
#define STR_BENCH_REPEAT	100000
#define STR_BENCH_TRIALS	9
#define STR_BENCH_WARMUP	1000

enum benchmark_kind {
	BENCH_SCAN,
	BENCH_COMPARISON,
	BENCH_SPAN,
	BENCH_SUBSTRING,
	BENCH_COUNT,
};

struct scenario {
	const char *name;
	unsigned char payload[STR_BENCH_CAP];
	size_t length;
	int position;
	__u32 want;
};

struct sample {
	double ns_per_op;
};

struct benchmark {
	const char *name;
	const char *kfunc;
	struct bpf_program *prog;
	struct bpf_str_kfuncs_bench *skel;
	enum benchmark_kind kind;
};

struct scenario_spec {
	const char *name;
	size_t length;
	int position;
};

static const struct scenario_spec scenario_specs[STR_BENCH_SCENARIOS] = {
	{ "first",  64,   0    },
	{ "middle", 512,  240  },
	{ "late",   1536, 1200 },
	{ "absent", 2048, -1   },
};

static const char substring_needle[] = "Host: benchmark.example.com";
static const unsigned char dummy_packet[64];

static void make_scenario(enum benchmark_kind kind, struct scenario *scenario,
			  const struct scenario_spec *spec)
{
	scenario->name = spec->name;
	scenario->length = spec->length;
	scenario->position = spec->position;

	switch (kind) {
	case BENCH_SCAN:
		memset(scenario->payload, 'x', scenario->length);
		if (spec->position >= 0)
			scenario->payload[spec->position] = 'H';
		scenario->want = spec->position < 0 ? (__u32)-ENOENT : spec->position;
		break;
	case BENCH_COMPARISON:
		scenario->name = spec->position < 0 ? "equal" : spec->name;
		memset(scenario->payload, 'a', scenario->length);
		scenario->want = spec->position < 0 ? 0 : (__u32)-1;
		break;
	case BENCH_SPAN:
		memset(scenario->payload, 'a', scenario->length);
		if (spec->position >= 0)
			scenario->payload[spec->position] = ':';
		scenario->want = spec->position < 0 ? scenario->length : spec->position;
		break;
	case BENCH_SUBSTRING:
		memset(scenario->payload, 'x', scenario->length);
		if (spec->position >= 0)
			memcpy(scenario->payload + spec->position, substring_needle,
			       sizeof(substring_needle) - 1);
		scenario->want = spec->position < 0 ? (__u32)-ENOENT : spec->position;
		break;
	case BENCH_COUNT:
		break;
	}
}

static void prepare_program_input(const struct benchmark *benchmark,
				  const struct scenario *scenario)
{
	unsigned char *lhs = (unsigned char *)benchmark->skel->data->buffers.lhs.words;
	unsigned char *rhs = (unsigned char *)benchmark->skel->data->buffers.rhs.words;

	memcpy(lhs, scenario->payload, scenario->length);
	lhs[scenario->length] = '\0';

	if (benchmark->kind == BENCH_COMPARISON) {
		memcpy(rhs, scenario->payload, scenario->length);
		if (scenario->position >= 0)
			rhs[scenario->position] = 'b';
		rhs[scenario->length] = '\0';
	}

	benchmark->skel->data->payload_length = scenario->length;
}

static void run_program(const struct benchmark *benchmark, const struct scenario *scenario,
			int repeat, struct sample *sample)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err;

	topts.data_in = dummy_packet;
	topts.data_size_in = sizeof(dummy_packet);
	topts.repeat = repeat;
	err = bpf_prog_test_run_opts(bpf_program__fd(benchmark->prog), &topts);
	if (err || topts.retval != scenario->want) {
		fprintf(stderr, "%s/%s failed: err=%d retval=%u want=%u\n",
			benchmark->name, scenario->name, err, topts.retval, scenario->want);
		exit(1);
	}
	if (sample)
		sample->ns_per_op = topts.duration;
}

static int compare_samples(const void *a, const void *b)
{
	const struct sample *sa = a;
	const struct sample *sb = b;

	if (sa->ns_per_op < sb->ns_per_op)
		return -1;
	if (sa->ns_per_op > sb->ns_per_op)
		return 1;
	return 0;
}

static void benchmark_scenario(const struct benchmark *benchmark, const struct scenario *scenario)
{
	struct sample samples[STR_BENCH_TRIALS];
	int i;

	prepare_program_input(benchmark, scenario);
	run_program(benchmark, scenario, STR_BENCH_WARMUP, NULL);
	for (i = 0; i < STR_BENCH_TRIALS; i++)
		run_program(benchmark, scenario, STR_BENCH_REPEAT, &samples[i]);

	qsort(samples, STR_BENCH_TRIALS, sizeof(*samples), compare_samples);
	printf("%-9s %5zu %13.1f\n", scenario->name, scenario->length,
	       samples[STR_BENCH_TRIALS / 2].ns_per_op);
}

static void str_kfuncs_run(void)
{
	struct benchmark benchmarks[BENCH_COUNT];
	struct bpf_str_kfuncs_bench *skel;
	struct scenario scenario;
	struct utsname uts = {};
	int i, j;

	setup_libbpf();
	skel = bpf_str_kfuncs_bench__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		exit(1);
	}

	benchmarks[BENCH_SCAN] = (struct benchmark) {
		.name = "scan",
		.kfunc = "bpf_strnchr",
		.prog = skel->progs.scan_kfunc,
		.skel = skel,
		.kind = BENCH_SCAN,
	};
	benchmarks[BENCH_COMPARISON] = (struct benchmark) {
		.name = "comparison",
		.kfunc = "bpf_strcmp",
		.prog = skel->progs.compare_kfunc,
		.skel = skel,
		.kind = BENCH_COMPARISON,
	};
	benchmarks[BENCH_SPAN] = (struct benchmark) {
		.name = "span",
		.kfunc = "bpf_strcspn",
		.prog = skel->progs.span_kfunc,
		.skel = skel,
		.kind = BENCH_SPAN,
	};
	benchmarks[BENCH_SUBSTRING] = (struct benchmark) {
		.name = "substring",
		.kfunc = "bpf_strnstr",
		.prog = skel->progs.substring_kfunc,
		.skel = skel,
		.kind = BENCH_SUBSTRING,
	};

	uname(&uts);
	printf("BPF string kfunc benchmark\n");
	printf("kernel=%s arch=%s repeat=%d trials=%d warmup=%d\n",
	       uts.release, uts.machine, STR_BENCH_REPEAT, STR_BENCH_TRIALS, STR_BENCH_WARMUP);

	for (i = 0; i < BENCH_COUNT; i++) {
		printf("\n%s (%s)\n", benchmarks[i].name, benchmarks[i].kfunc);
		printf("%-9s %5s %13s\n", "Scenario", "Bytes", "Kfunc ns/op");

		for (j = 0; j < STR_BENCH_SCENARIOS; j++) {
			make_scenario(benchmarks[i].kind, &scenario, &scenario_specs[j]);
			benchmark_scenario(&benchmarks[i], &scenario);
		}
	}

	bpf_str_kfuncs_bench__destroy(skel);
}

const struct bench bench_bpf_str_kfuncs = {
	.name = "bpf-str-kfuncs",
	.run = str_kfuncs_run,
};
