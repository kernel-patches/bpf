// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "map_kptr.skel.h"
#include "map_kptr_fail.skel.h"

static void test_map_kptr_success(bool test_run)
{
	LIBBPF_OPTS(bpf_test_run_opts, lopts);
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int key = 0, ret, cpu;
	struct map_kptr *skel;
	struct bpf_link *link;
	char buf[16], *pbuf;

	skel = map_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "map_kptr__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref1), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref1 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref1 retval");
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref2), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref2 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref2 retval");

	link = bpf_program__attach(skel->progs.test_ls_map_kptr_ref1);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach ref1"))
		goto exit;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_ls_map_kptr_ref1), &lopts);
	ASSERT_OK(ret, "test_ls_map_kptr_ref1 refcount");
	ASSERT_EQ((lopts.retval << 16) >> 16, 9000, "test_ls_map_kptr_ref1 retval");
	if (!ASSERT_OK(bpf_link__destroy(link), "bpf_link__destroy"))
		goto exit;

	link = bpf_program__attach(skel->progs.test_ls_map_kptr_ref2);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach ref2"))
		goto exit;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_ls_map_kptr_ref2), &lopts);
	ASSERT_OK(ret, "test_ls_map_kptr_ref2 refcount");
	ASSERT_EQ((lopts.retval << 16) >> 16, 9000, "test_ls_map_kptr_ref2 retval");
	if (!ASSERT_OK(bpf_link__destroy(link), "bpf_link__destroy"))
		goto exit;

	if (test_run)
		goto exit;

	cpu = libbpf_num_possible_cpus();
	if (!ASSERT_GT(cpu, 0, "libbpf_num_possible_cpus"))
		goto exit;

	pbuf = calloc(cpu, sizeof(buf));
	if (!ASSERT_OK_PTR(pbuf, "calloc(pbuf)"))
		goto exit;

	ret = bpf_map__update_elem(skel->maps.array_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "array_map update");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__update_elem(skel->maps.pcpu_array_map,
				   &key, sizeof(key), pbuf, cpu * sizeof(buf), 0);
	ASSERT_OK(ret, "pcpu_array_map update");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "hash_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.pcpu_hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "pcpu_hash_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.hash_malloc_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "hash_malloc_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.pcpu_hash_malloc_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "pcpu_hash_malloc_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.lru_hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "lru_hash_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	ret = bpf_map__delete_elem(skel->maps.lru_pcpu_hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "lru_pcpu_hash_map delete");
	skel->data->ref--;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_map_kptr_ref3), &opts);
	ASSERT_OK(ret, "test_map_kptr_ref3 refcount");
	ASSERT_OK(opts.retval, "test_map_kptr_ref3 retval");

	link = bpf_program__attach(skel->progs.test_ls_map_kptr_ref_del);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach ref_del"))
		goto exit;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_ls_map_kptr_ref_del), &lopts);
	ASSERT_OK(ret, "test_ls_map_kptr_ref_del delete");
	skel->data->ref--;
	ASSERT_EQ((lopts.retval << 16) >> 16, 9000, "test_ls_map_kptr_ref_del retval");
	if (!ASSERT_OK(bpf_link__destroy(link), "bpf_link__destroy"))
		goto exit;

	free(pbuf);
exit:
	map_kptr__destroy(skel);
}

void test_map_kptr(void)
{
	RUN_TESTS(map_kptr_fail);

	if (test__start_subtest("success-map")) {
		test_map_kptr_success(true);

		ASSERT_OK(kern_sync_rcu(), "sync rcu");
		/* Observe refcount dropping to 1 on bpf_map_free_deferred */
		test_map_kptr_success(false);

		ASSERT_OK(kern_sync_rcu(), "sync rcu");
		/* Observe refcount dropping to 1 on synchronous delete elem */
		test_map_kptr_success(true);
	}
}
