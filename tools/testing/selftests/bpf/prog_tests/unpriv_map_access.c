// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include <test_progs.h>
#include "test_unpriv_map_access.skel.h"

#include "cap_helpers.h"

/* need CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON to load progs */
#define ADMIN_CAPS (1ULL << CAP_SYS_ADMIN |	\
		    1ULL << CAP_PERFMON |	\
		    1ULL << CAP_BPF)

#define PINPATH		"/sys/fs/bpf/unpriv_map_access_"

static __u32 got_perfbuf_val;
static __u32 got_ringbuf_val;

static int process_ringbuf(void *ctx, void *data, size_t len)
{
	if (len == sizeof(__u32))
		got_ringbuf_val = *(__u32 *)data;
	return 0;
}

static void process_perfbuf(void *ctx, int cpu, void *data, __u32 len)
{
	if (len == sizeof(__u32))
		got_perfbuf_val = *(__u32 *)data;
}

static int sysctl_set(const char *sysctl_path, char *old_val, const char *new_val)
{
	int ret = 0;
	FILE *fp;

	fp = fopen(sysctl_path, "r+");
	if (!fp)
		return -errno;
	if (old_val && fscanf(fp, "%s", old_val) <= 0) {
		ret = -ENOENT;
	} else if (!old_val || strcmp(old_val, new_val) != 0) {
		fseek(fp, 0, SEEK_SET);
		if (fprintf(fp, "%s", new_val) < 0)
			ret = -errno;
	}
	fclose(fp);

	return ret;
}

void test_unpriv_map_access(void)
{
	struct test_unpriv_map_access *skel;
	struct perf_buffer *perfbuf = NULL;
	struct ring_buffer *ringbuf = NULL;
	__u64 save_caps = 0;
	int i, ret, nr_cpus, map_fds[7];
	char *map_paths[7] = { PINPATH "array",
			       PINPATH "percpu_array",
			       PINPATH "hash",
			       PINPATH "percpu_hash",
			       PINPATH "perfbuf",
			       PINPATH "ringbuf",
			       PINPATH "prog_array" };
	char unprivileged_bpf_disabled_orig[32] = {};
	char perf_event_paranoid_orig[32] = {};

	nr_cpus = bpf_num_possible_cpus();

	skel = test_unpriv_map_access__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	if (!ASSERT_OK_PTR(skel->kconfig, "skel_kconfig"))
		goto cleanup;

	if (!skel->kconfig->CONFIG_BPF_UNPRIV_MAP_ACCESS) {
		printf("%s:SKIP:CONFIG_BPF_UNPRIV_MAP_ACCESS is not set", __func__);
		test__skip();
		goto cleanup;
	}

	skel->bss->perfbuf_val = 1;
	skel->bss->ringbuf_val = 2;
	skel->bss->test_pid = getpid();

	if (!ASSERT_OK(test_unpriv_map_access__attach(skel), "skel_attach"))
		goto cleanup;

	map_fds[0] = bpf_map__fd(skel->maps.array);
	map_fds[1] = bpf_map__fd(skel->maps.percpu_array);
	map_fds[2] = bpf_map__fd(skel->maps.hash);
	map_fds[3] = bpf_map__fd(skel->maps.percpu_hash);
	map_fds[4] = bpf_map__fd(skel->maps.perfbuf);
	map_fds[5] = bpf_map__fd(skel->maps.ringbuf);
	map_fds[6] = bpf_map__fd(skel->maps.prog_array);

	for (i = 0; i < ARRAY_SIZE(map_fds); i++)
		ASSERT_OK(bpf_obj_pin(map_fds[i], map_paths[i]), "pin map_fd");

	/* allow user without caps to use perf events */
	if (!ASSERT_OK(sysctl_set("/proc/sys/kernel/perf_event_paranoid", perf_event_paranoid_orig,
				  "-1"),
		       "set_perf_event_paranoid"))
		goto cleanup;
	/* ensure unprivileged bpf id disabled */
	ret = sysctl_set("/proc/sys/kernel/unprivileged_bpf_disabled",
			 unprivileged_bpf_disabled_orig, "2");
	if (ret == -EPERM) {
		/* if unprivileged_bpf_disabled=1, we get -EPERM back; that's okay. */
		if (!ASSERT_OK(strcmp(unprivileged_bpf_disabled_orig, "1"),
			       "unpriviliged_bpf_disabled_on"))
			goto cleanup;
	} else {
		if (!ASSERT_OK(ret, "set unpriviliged_bpf_disabled"))
			goto cleanup;
	}

	if (!ASSERT_OK(cap_disable_effective(ADMIN_CAPS, &save_caps), "disable caps"))
		goto cleanup;

	perfbuf = perf_buffer__new(bpf_map__fd(skel->maps.perfbuf), 8, process_perfbuf, NULL, NULL,
				   NULL);
	if (!ASSERT_OK_PTR(perfbuf, "perf_buffer__new"))
		goto cleanup;

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), process_ringbuf, NULL, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ring_buffer__new"))
		goto cleanup;

	/* trigger & validate perf event, ringbuf output */
	usleep(1);

	ASSERT_GT(perf_buffer__poll(perfbuf, 100), -1, "perf_buffer__poll");

	ASSERT_EQ(got_perfbuf_val, skel->bss->perfbuf_val, "check_perfbuf_val");

	ASSERT_EQ(ring_buffer__consume(ringbuf), 1, "ring_buffer__consume");

	ASSERT_EQ(got_ringbuf_val, skel->bss->ringbuf_val, "check_ringbuf_val");

	for (i = 0; i < ARRAY_SIZE(map_fds); i++) {
		map_fds[i] = bpf_obj_get(map_paths[i]);
		if (!ASSERT_GT(map_fds[i], -1, "bpf_obj_get"))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(map_fds); i++) {
		bool prog_array = strstr(map_paths[i], "prog_array") != NULL;
		bool array = strstr(map_paths[i], "array") != NULL;
		bool buf = strstr(map_paths[i], "buf") != NULL;
		__u32 key = 0, vals[nr_cpus], lookup_vals[nr_cpus];
		int j;

		/* skip ringbuf, perfbuf */
		if (buf)
			continue;

		for (j = 0; j < nr_cpus; j++)
			vals[j] = 1;

		if (prog_array) {
			ASSERT_EQ(bpf_map_update_elem(map_fds[i], &key, vals, 0), -EPERM,
				  "bpf_map_update_elem_fail");
			ASSERT_EQ(bpf_map_lookup_elem(map_fds[i], &key, &lookup_vals), -EPERM,
				  "bpf_map_lookup_elem_fail");
		} else {
			ASSERT_OK(bpf_map_update_elem(map_fds[i], &key, vals, 0),
				  "bpf_map_update_elem");
			ASSERT_OK(bpf_map_lookup_elem(map_fds[i], &key, &lookup_vals),
				  "bpf_map_lookup_elem");
			ASSERT_EQ(lookup_vals[0], 1, "bpf_map_lookup_elem_values");
			if (!array)
				ASSERT_OK(bpf_map_delete_elem(map_fds[i], &key),
					  "bpf_map_delete_elem");
		}
	}
cleanup:
	if (save_caps)
		cap_enable_effective(save_caps, NULL);
	if (strlen(perf_event_paranoid_orig) > 0)
		sysctl_set("/proc/sys/kernel/perf_event_paranoid", NULL, perf_event_paranoid_orig);
	if (strlen(unprivileged_bpf_disabled_orig) > 0)
		sysctl_set("/proc/sys/kernel/unprivileged_bpf_disabled", NULL,
			   unprivileged_bpf_disabled_orig);
	if (perfbuf)
		perf_buffer__free(perfbuf);
	if (ringbuf)
		ring_buffer__free(ringbuf);
	for (i = 0; i < ARRAY_SIZE(map_paths); i++)
		unlink(map_paths[i]);
	test_unpriv_map_access__destroy(skel);
}
