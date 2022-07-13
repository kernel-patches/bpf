// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "pifo_map.skel.h"

static int run_prog(int prog_fd, __u32 exp_retval)
{
	struct xdp_md ctx_in = {};
	char data[10] = {};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = data,
			    .data_size_in = sizeof(data),
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = 1,
		);
	int err;

	ctx_in.data_end = sizeof(data);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run(valid)"))
		return -1;
	if (!ASSERT_EQ(opts.retval, exp_retval, "prog retval"))
		return -1;

	return 0;
}

static void check_map_counts(int map_fd, int start, int interval, int num, int exp_val)
{
	__u32 val, key, next_key, *kptr = NULL;
	int i, err;

	for (i = 0; i < num; i++) {
		err = bpf_map_get_next_key(map_fd, kptr, &next_key);
		if (!ASSERT_OK(err, "bpf_map_get_next_key()"))
			return;

		key = next_key;
		kptr = &key;

		if (!ASSERT_EQ(key, start + i * interval, "expected key"))
			break;
		err = bpf_map_lookup_elem(map_fd, &key, &val);
		if (!ASSERT_OK(err, "bpf_map_lookup_elem()"))
			break;
		if (!ASSERT_EQ(val, exp_val, "map value"))
			break;
	}
}

static void run_enqueue_fail(struct pifo_map *skel, int start, int interval, __u32 exp_retval)
{
	int enqueue_fd;

	skel->bss->start = start;
	skel->data->interval = interval;

	enqueue_fd = bpf_program__fd(skel->progs.pifo_enqueue);

	if (run_prog(enqueue_fd, exp_retval))
		return;
}

static void run_test(struct pifo_map *skel, int start, int interval)
{
	int enqueue_fd, dequeue_fd;

	skel->bss->start = start;
	skel->data->interval = interval;

	enqueue_fd = bpf_program__fd(skel->progs.pifo_enqueue);
	dequeue_fd = bpf_program__fd(skel->progs.pifo_dequeue);

	if (run_prog(enqueue_fd, 0))
		return;
	check_map_counts(bpf_map__fd(skel->maps.pifo_map),
			 skel->bss->start, skel->data->interval,
			 skel->rodata->num_entries, 1);
	run_prog(dequeue_fd, 0);
}

void test_pifo_map(void)
{
	struct pifo_map *skel = NULL;
	int err;

	skel = pifo_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	run_test(skel, 0, 1);
	run_test(skel, 0, 10);
	run_test(skel, 0, 100);

	/* do a series of runs that keep advancing the priority, to check that
	 * we can keep rorating the two internal maps
	 */
	run_test(skel, 0, 125);
	run_test(skel, 1250, 1);
	run_test(skel, 1250, 125);

	/* after rotating, starting enqueue at prio 0 will now fail */
	run_enqueue_fail(skel, 0, 1, -ERANGE);

	run_test(skel, 2500, 125);
	run_test(skel, 3750, 125);
	run_test(skel, 5000, 125);

	pifo_map__destroy(skel);

	/* reopen but change rodata */
	skel = pifo_map__open();
	if (!ASSERT_OK_PTR(skel, "open skel"))
		return;

	skel->rodata->num_entries = 12;
	err = pifo_map__load(skel);
	if (!ASSERT_OK(err, "load skel"))
		goto out;

	/* fails because the map is too small */
	run_enqueue_fail(skel, 0, 1, -EOVERFLOW);
out:
	pifo_map__destroy(skel);
}
