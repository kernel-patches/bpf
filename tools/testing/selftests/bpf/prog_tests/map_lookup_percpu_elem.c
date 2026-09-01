// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Bytedance */

#include <test_progs.h>
#include "bpf/libbpf_internal.h"
#include "test_map_lookup_percpu_elem.skel.h"

void test_map_lookup_percpu_elem(void)
{
	struct test_map_lookup_percpu_elem *skel;
	bool *possible = NULL;
	__u64 key = 0, sum = 0;
	int cpu, nr_cpu_ids, nr_cpus, ret, slot = 0;
	__u64 *buf;

	ret = parse_cpu_mask_file("/sys/devices/system/cpu/possible", &possible,
				  &nr_cpu_ids);
	if (!ASSERT_OK(ret, "parse possible CPU mask"))
		return;

	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "libbpf_num_possible_cpus"))
		goto free_mask;

	buf = malloc(nr_cpus * sizeof(*buf));
	if (!ASSERT_OK_PTR(buf, "malloc"))
		goto free_mask;

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		if (!possible[cpu])
			continue;
		buf[slot++] = cpu;
		sum += cpu;
	}
	if (!ASSERT_EQ(slot, nr_cpus, "possible CPU mask weight"))
		goto exit;

	skel = test_map_lookup_percpu_elem__open();
	if (!ASSERT_OK_PTR(skel, "test_map_lookup_percpu_elem__open"))
		goto exit;

	skel->rodata->my_pid = getpid();
	skel->rodata->nr_cpu_ids = nr_cpu_ids;

	ret = test_map_lookup_percpu_elem__load(skel);
	if (!ASSERT_OK(ret, "test_map_lookup_percpu_elem__load"))
		goto cleanup;

	ret = test_map_lookup_percpu_elem__attach(skel);
	if (!ASSERT_OK(ret, "test_map_lookup_percpu_elem__attach"))
		goto cleanup;

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.percpu_array_map), &key, buf, 0);
	ASSERT_OK(ret, "percpu_array_map update");

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.percpu_hash_map), &key, buf, 0);
	ASSERT_OK(ret, "percpu_hash_map update");

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.percpu_lru_hash_map), &key, buf, 0);
	ASSERT_OK(ret, "percpu_lru_hash_map update");

	syscall(__NR_getuid);

	test_map_lookup_percpu_elem__detach(skel);

	ASSERT_EQ(skel->bss->percpu_array_elem_sum, sum, "percpu_array lookup percpu elem");
	ASSERT_EQ(skel->bss->percpu_hash_elem_sum, sum, "percpu_hash lookup percpu elem");
	ASSERT_EQ(skel->bss->percpu_lru_hash_elem_sum, sum, "percpu_lru_hash lookup percpu elem");

cleanup:
	test_map_lookup_percpu_elem__destroy(skel);
exit:
	free(buf);
free_mask:
	free(possible);
}
