// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "bench.h"
#include "testing_helpers.h"
#include "tracing_multi_attach_progs.skel.h"
#include "bpf/libbpf_internal.h"

#define TARGET_CNT 1000

static struct ctx {
	struct tracing_multi_attach_progs *targets[TARGET_CNT];
	struct tracing_multi_attach_progs *fentries[TARGET_CNT];
	struct tracing_multi_attach_progs *fentry_multi;
	int target_fds[TARGET_CNT];
	__u32 target_btf_ids[TARGET_CNT];
	int fentry_prog_fds[TARGET_CNT];
	int fentry_multi_prog_fd;
} ctx;

static void prepare(void)
{
	int err, i;

	setup_libbpf();

	for (i = 0; i < TARGET_CNT; i++) {
		struct tracing_multi_attach_progs *target;
		int btf_id, fd, obj_token_fd;

		target = tracing_multi_attach_progs__open();
		if (!target) {
			fprintf(stderr, "failed to open target program %d\n", i);
			exit(1);
		}

		bpf_program__set_autoload(target->progs.dummy_fentry, false);
		bpf_program__set_autoload(target->progs.dummy_fentry_multi, false);
		err = tracing_multi_attach_progs__load(target);
		if (err) {
			fprintf(stderr, "failed to load target program %d: %s\n",
				i, strerror(-err));
			exit(1);
		}

		fd = bpf_program__fd(target->progs.target);
		obj_token_fd = bpf_object__token_fd(target->obj);
		obj_token_fd = obj_token_fd < 0 ? 0 : obj_token_fd;
		btf_id = libbpf_find_prog_btf_id("target", fd, obj_token_fd);
		if (btf_id <= 0) {
			fprintf(stderr, "failed to find target BTF ID: %s\n",
				strerror(-btf_id));
			exit(1);
		}

		ctx.targets[i] = target;
		ctx.target_fds[i] = fd;
		ctx.target_btf_ids[i] = btf_id;
	}
}

static long create_and_attach_fentry(void)
{
	int link_fds[TARGET_CNT];
	long start_ns, end_ns;
	int err, i, j;

	start_ns = get_time_ns();

	/* An ordinary fentry program is bound to one target when it is loaded. */
	for (i = 0; i < TARGET_CNT; i++) {
		struct tracing_multi_attach_progs *fentry;

		fentry = tracing_multi_attach_progs__open();
		if (!fentry) {
			fprintf(stderr, "failed to open fentry program %d\n", i);
			exit(1);
		}

		bpf_program__set_autoload(fentry->progs.target, false);
		bpf_program__set_autoload(fentry->progs.dummy_fentry_multi, false);
		err = bpf_program__set_attach_target(fentry->progs.dummy_fentry, ctx.target_fds[i],
						     "target");
		err = err ?: tracing_multi_attach_progs__load(fentry);
		if (err) {
			fprintf(stderr, "failed to load fentry program %d: %s\n",
				i, strerror(-err));
			exit(1);
		}

		ctx.fentries[i] = fentry;
		ctx.fentry_prog_fds[i] = bpf_program__fd(fentry->progs.dummy_fentry);
	}

	for (i = 0; i < TARGET_CNT; i++) {
		link_fds[i] = bpf_link_create(ctx.fentry_prog_fds[i], 0, BPF_TRACE_FENTRY, NULL);
		if (link_fds[i] < 0) {
			err = errno;
			for (j = 0; j < i; j++)
				close(link_fds[j]);
			fprintf(stderr, "failed to create fentry link %d: %s\n",
				i, strerror(err));
			exit(1);
		}
	}
	end_ns = get_time_ns();

	for (i = 0; i < TARGET_CNT; i++)
		close(link_fds[i]);

	return end_ns - start_ns;
}

static long create_and_attach_fentry_multi(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	long start_ns, end_ns;
	int err, link_fd;

	opts.tracing_multi.ids = ctx.target_btf_ids;
	opts.tracing_multi.fds = ctx.target_fds;
	opts.tracing_multi.cnt = TARGET_CNT;

	start_ns = get_time_ns();

	ctx.fentry_multi = tracing_multi_attach_progs__open();
	if (!ctx.fentry_multi) {
		fprintf(stderr, "failed to open fentry.multi program\n");
		exit(1);
	}

	bpf_program__set_autoload(ctx.fentry_multi->progs.target, false);
	bpf_program__set_autoload(ctx.fentry_multi->progs.dummy_fentry, false);
	err = tracing_multi_attach_progs__load(ctx.fentry_multi);
	if (err) {
		fprintf(stderr, "failed to load fentry.multi program: %s\n",
			strerror(-err));
		exit(1);
	}

	ctx.fentry_multi_prog_fd = bpf_program__fd(ctx.fentry_multi->progs.dummy_fentry_multi);
	link_fd = bpf_link_create(ctx.fentry_multi_prog_fd, 0, BPF_TRACE_FENTRY_MULTI, &opts);
	end_ns = get_time_ns();
	if (link_fd < 0) {
		err = errno;
		fprintf(stderr, "failed to create fentry.multi link: %s\n",
			strerror(err));
		exit(1);
	}

	close(link_fd);
	return end_ns - start_ns;
}

static void cleanup(void)
{
	int i;

	tracing_multi_attach_progs__destroy(ctx.fentry_multi);
	for (i = 0; i < TARGET_CNT; i++) {
		tracing_multi_attach_progs__destroy(ctx.fentries[i]);
		tracing_multi_attach_progs__destroy(ctx.targets[i]);
	}
}

static void setup(void)
{
	double fentry_multi_ms, fentry_ms;
	long fentry_multi_ns, fentry_ns;

	prepare();
	fentry_ns = create_and_attach_fentry();
	fentry_multi_ns = create_and_attach_fentry_multi();
	fentry_ms = fentry_ns / 1000000.0;
	fentry_multi_ms = fentry_multi_ns / 1000000.0;

	printf("%s: prepared %d identical BPF program targets\n",
	       bench->name, TARGET_CNT);
	printf("%s: fentry created and attached %d programs/links in %-.3lfms\n",
	       bench->name, TARGET_CNT, fentry_ms);
	printf("%s: fentry.multi created one program and attached one %d-target link in %-.3lfms\n",
	       bench->name, TARGET_CNT, fentry_multi_ms);
	printf("%s: fentry.multi creation/attachment speedup is %-.2lfx\n",
	       bench->name, fentry_ms / fentry_multi_ms);

	cleanup();
	exit(0);
}

const struct bench bench_tracing_multi_attach_progs = {
	.name = "tracing-multi-attach-progs",
	.setup = setup,
};
