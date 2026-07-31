// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <search.h>
#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>
#include "bench.h"
#include "testing_helpers.h"
#include "trace_helpers.h"
#include "tracing_multi_bench.skel.h"
#include "bpf/libbpf_internal.h"

static int compare(const void *ppa, const void *ppb)
{
	const char *pa = *(const char **)ppa;
	const char *pb = *(const char **)ppb;

	return strcmp(pa, pb);
}

static void tdestroy_free_nop(void *ptr)
{
}

static void tracing_multi_attach_setup(void)
{
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	struct tracing_multi_bench *skel = NULL;
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;
	size_t i, cap = 0, cnt = 0;
	struct ksyms *ksyms = NULL;
	void *root = NULL;
	void *dups = NULL;
	__u32 *ids = NULL;
	__u32 nr, type_id;
	struct btf *btf;
	int err;

	setup_libbpf();

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err) {
		btf = NULL;
		fprintf(stderr, "failed to load vmlinux BTF: %s\n", strerror(-err));
		goto cleanup;
	}

	skel = tracing_multi_bench__open_and_load();
	err = libbpf_get_error(skel);
	if (!skel) {
		fprintf(stderr, "failed to open and load skeleton: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_get_ksyms(&ksyms, true);
	if (err) {
		fprintf(stderr, "failed to get kernel symbols: %s\n", strerror(-err));
		goto cleanup;
	}

	/* Get all ftrace 'safe' symbols.. */
	for (i = 0; i < ksyms->filtered_cnt; i++) {
		if (!tsearch(&ksyms->filtered_syms[i], &root, compare)) {
			err = -ENOMEM;
			fprintf(stderr, "failed to index ftrace symbols\n");
			goto cleanup;
		}
	}

	/*
	 * Collect names that are not unique in kallsyms. The kernel resolves a
	 * tracing-multi BTF id to an address with kallsyms_lookup_name(), which
	 * returns the first symbol of that name. For a duplicate name that may
	 * be a different (non-ftrace-able) instance than the ftrace-able one in
	 * available_filter_functions, so attaching to it by BTF id fails with
	 * -ENOENT (e.g. t_start/t_next/t_stop). ksyms->syms is sorted by name,
	 * so equal names are adjacent.
	 */
	for (i = 1; i < ksyms->sym_cnt; i++) {
		if (strcmp(ksyms->syms[i].name, ksyms->syms[i - 1].name))
			continue;
		if (!tsearch(&ksyms->syms[i].name, &dups, compare)) {
			err = -ENOMEM;
			fprintf(stderr, "failed to index duplicate kernel symbols\n");
			goto cleanup;
		}
	}

	/* ..and filter them through BTF and btf_type_is_traceable_func. */
	nr = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr; type_id++) {
		const struct btf_type *type;
		const char *str;

		type = btf__type_by_id(btf, type_id);
		if (!type)
			break;

		if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str)
			break;

		if (!tfind(&str, &root, compare))
			continue;

		/* Skip names that are not unique in kallsyms, see above. */
		if (tfind(&str, &dups, compare))
			continue;

		if (!btf_type_is_traceable_func(btf, type))
			continue;

		err = libbpf_ensure_mem((void **)&ids, &cap, sizeof(*ids), cnt + 1);
		if (err) {
			fprintf(stderr, "failed to allocate BTF ID array: %s\n",
				strerror(-err));
			goto cleanup;
		}

		ids[cnt++] = type_id;
	}

	opts.ids = ids;
	opts.cnt = cnt;

	attach_start_ns = get_time_ns();
	link = bpf_program__attach_tracing_multi(skel->progs.bench, NULL, &opts);
	attach_end_ns = get_time_ns();

	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach tracing multi link: %s\n",
			strerror(-err));
		goto cleanup;
	}

	detach_start_ns = get_time_ns();
	err = bpf_link__destroy(link);
	detach_end_ns = get_time_ns();
	link = NULL;
	if (err) {
		fprintf(stderr, "failed to detach tracing multi link: %s\n",
			strerror(-err));
		goto cleanup;
	}

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: found %zu functions\n", bench->name, cnt);
	printf("%s: attached in %7.3lfs\n", bench->name, attach_delta);
	printf("%s: detached in %7.3lfs\n", bench->name, detach_delta);

cleanup:
	bpf_link__destroy(link);
	tracing_multi_bench__destroy(skel);
	tdestroy(root, tdestroy_free_nop);
	tdestroy(dups, tdestroy_free_nop);
	free_kallsyms_local(ksyms);
	free(ids);
	btf__free(btf);

	exit(err ? 1 : 0);
}

const struct bench bench_tracing_multi_attach = {
	.name = "tracing-multi-attach",
	.setup = tracing_multi_attach_setup,
};
