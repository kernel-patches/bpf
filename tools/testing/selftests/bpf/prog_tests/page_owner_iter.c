// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include <test_progs.h>
#include "bpf_iter_page_owner.skel.h"

#define DEBUGFS_PAGE_OWNER	"/sys/kernel/debug/page_owner"

static bool page_owner_available(void)
{
	return access(DEBUGFS_PAGE_OWNER, R_OK) == 0;
}

/* Count link_fd output lines; -1 on error. */
static long iter_record_count(int link_fd)
{
	char *line = NULL;
	size_t len = 0;
	long count = 0;
	int iter_fd, err;
	FILE *f;

	iter_fd = bpf_iter_create(link_fd);
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		return -1;

	f = fdopen(iter_fd, "r");
	if (!f) {
		close(iter_fd);
		return -1;
	}
	while (getline(&line, &len, f) > 0)
		count++;
	err = ferror(f);
	free(line);
	fclose(f);
	return err ? -1 : count;
}

/* Validate bpf_page_owner_get_memcg_info() results from the open-coded run. */
static void check_memcg_skel(struct bpf_iter_page_owner *skel)
{
	fprintf(stderr,
		"memcg: seen=%u charged=%u online=%u nodata=%u notsup=%u bad=%u first='%s' name='%s' flags=%u\n",
		skel->bss->memcg_seen, skel->bss->memcg_charged,
		skel->bss->memcg_online, skel->bss->memcg_nodata,
		skel->bss->memcg_notsup, skel->bss->memcg_bad,
		skel->bss->memcg_first_path, skel->bss->memcg_first_name,
		skel->bss->memcg_first_flags);

	if (!ASSERT_GT(skel->bss->memcg_seen, 0, "memcg_seen_gt_0"))
		return;

	/* all -EOPNOTSUPP: CONFIG_MEMCG is off */
	if (skel->bss->memcg_notsup == skel->bss->memcg_seen) {
		ASSERT_EQ(skel->bss->memcg_bad, 0, "memcg_stub_invariants");
		return;
	}

	if (!ASSERT_EQ(skel->bss->memcg_bad, 0, "memcg_kfunc_invariants"))
		return;

	/* Every call is either charged or nodata */
	if (!ASSERT_EQ(skel->bss->memcg_charged + skel->bss->memcg_nodata,
		       skel->bss->memcg_seen, "memcg_ret_classified"))
		return;

	if (!skel->bss->memcg_first_saved)
		return;

	if (!ASSERT_EQ(skel->bss->memcg_first_path[0], '/',
		       "memcg_first_path_abs"))
		return;

	if (skel->bss->memcg_first_name[0])
		ASSERT_OK_PTR(strstr(skel->bss->memcg_first_path,
				    skel->bss->memcg_first_name),
			      "memcg_name_in_path");
}

void serial_test_page_owner_iter(void)
{
	struct bpf_iter_page_owner *skel = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	long iter_count, unfiltered_count, oc_diff, pid;
	unsigned int printed_before;
	int link_fd, prog_fd;

	if (!page_owner_available()) {
		test__skip();
		return;
	}

	skel = bpf_iter_page_owner__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_page_owner__open_and_load"))
		return;

	/* --- seq file iterator: unfiltered run --- */
	skel->bss->filter_en = 0;

	if (!ASSERT_OK(bpf_iter_page_owner__attach(skel), "skel_attach"))
		goto destroy;

	link_fd = bpf_link__fd(skel->links.dump_page_owner);
	iter_count = iter_record_count(link_fd);
	if (iter_count < 0)
		goto destroy;
	unfiltered_count = iter_count;

	fprintf(stderr, "iter_count=%ld printed_lines=%u total_seen=%u\n",
		iter_count, skel->bss->printed_lines, skel->bss->total_seen);

	ASSERT_GT(iter_count, 0, "unfiltered_lines_gt_0");

	ASSERT_EQ((long)skel->bss->printed_lines, iter_count,
		  "lines_match_printed");

	/* unfiltered: every visited page is printed, so the two must match */
	ASSERT_EQ(skel->bss->total_seen, skel->bss->printed_lines,
		  "unfiltered_all_printed");

	/* --- seq file iterator: pid-filtered run --- */
	pid = getpid();
	skel->bss->filter_en = 1;
	skel->bss->filter_pid = (pid_t)pid;

	/* printed_lines is cumulative across runs: compare the delta */
	printed_before = skel->bss->printed_lines;
	iter_count = iter_record_count(link_fd);
	if (iter_count < 0)
		goto destroy;

	fprintf(stderr,
		"pid=%ld iter_count=%ld printed_delta=%u\n",
		pid, iter_count, skel->bss->printed_lines - printed_before);

	ASSERT_GT(iter_count, 0, "filtered_lines_gt_0");
	ASSERT_EQ(skel->bss->printed_lines - printed_before, iter_count,
		  "filtered_printed_match");

	/* --- open-coded iterator parity --- */
	prog_fd = bpf_program__fd(skel->progs.scan_open_coded);

	ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts), "prog_test_run");
	fprintf(stderr,
		"open_coded_seen=%u nid_seen=%u first_nid=%d "
		"stack_bytes=%u stack=[\n%s]\n",
		skel->bss->open_coded_seen, skel->bss->nid_seen,
		skel->data->first_nid, skel->bss->stack_bytes,
		skel->bss->stack_text);

	/* same eligibility as the seq path: counts must be close */
	ASSERT_GT(skel->bss->open_coded_seen, 0, "oc_seen_gt_0");
	oc_diff = (long)skel->bss->open_coded_seen - unfiltered_count;
	if (oc_diff < 0)
		oc_diff = -oc_diff;
	ASSERT_LE(oc_diff, unfiltered_count / 100 + 64,
		  "oc_seen_close_to_iter");

	/* the nid kfunc returned a valid node for every page */
	ASSERT_EQ(skel->bss->nid_seen, skel->bss->open_coded_seen,
		  "nid_valid_all");
	ASSERT_GE(skel->data->first_nid, 0, "first_nid_valid");

	ASSERT_GT(skel->bss->stack_bytes, 0, "stack_snprint_ok");
	ASSERT_OK_PTR(strstr(skel->bss->stack_text, "+0x"), "stack_frames");
	ASSERT_OK_PTR(strchr(skel->bss->stack_text, '\n'), "stack_lines");

	check_memcg_skel(skel);

destroy:
	bpf_iter_page_owner__destroy(skel);
}
