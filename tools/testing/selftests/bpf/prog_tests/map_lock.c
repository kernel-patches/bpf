// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

static void *spin_lock_thread(void *arg)
{
	int err, prog_fd = *(u32 *) arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run_opts err");
	ASSERT_OK(topts.retval, "test_run_opts retval");

	pthread_exit(arg);
}

static void *parallel_map_access(void *arg)
{
	int err, map_fd = *(u32 *) arg;
	int vars[17], i, j, rnd, key = 0;

	for (i = 0; i < 10000; i++) {
		err = bpf_map_lookup_elem_flags(map_fd, &key, vars, BPF_F_LOCK);
		if (err) {
			PERROR("bpf_map_lookup_elem_flags");
			goto out;
		}
		if (vars[0]) {
			PRINT_FAIL("lookup #%d var[0]=%d\n", i, vars[0]);
			goto out;
		}
		rnd = vars[1];
		for (j = 2; j < 17; j++) {
			if (vars[j] == rnd)
				continue;
			PRINT_FAIL("lookup #%d var[1]=%d var[%d]=%d\n",
				   i, rnd, j, vars[j]);
			goto out;
		}
	}
out:
	pthread_exit(arg);
}

void test_map_lock(void)
{
	const char *file = "./test_map_lock.bpf.o";
	int prog_fd, map_fd[2], vars[17] = {};
	pthread_t thread_id[6];
	struct bpf_object *obj = NULL;
	int err = 0, key = 0, i;
	void *ret;

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_CGROUP_SKB, &obj, &prog_fd);
	if (!ASSERT_OK(err, "bpf_prog_test_load"))
		goto close_prog;
	map_fd[0] = bpf_find_map(__func__, obj, "hash_map");
	if (!ASSERT_OK_FD(map_fd[0], "bpf_find_map hash_map"))
		goto close_prog;
	map_fd[1] = bpf_find_map(__func__, obj, "array_map");
	if (!ASSERT_OK_FD(map_fd[1], "bpf_find_map array_map"))
		goto close_prog;

	bpf_map_update_elem(map_fd[0], &key, vars, BPF_F_LOCK);

	for (i = 0; i < 4; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL, &spin_lock_thread, &prog_fd),
			       "pthread_create spin_lock_thread"))
			goto close_prog;
	for (i = 4; i < 6; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL, &parallel_map_access, &map_fd[i - 4]),
			       "pthread_create parallel_map_access"))
			goto close_prog;
	for (i = 0; i < 4; i++)
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join") ||
		    !ASSERT_EQ(ret, (void *)&prog_fd, "return value"))
			goto close_prog;
	for (i = 4; i < 6; i++)
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join") ||
		    !ASSERT_EQ(ret, (void *)&map_fd[i - 4], "return value"))
			goto close_prog;
close_prog:
	bpf_object__close(obj);
}
