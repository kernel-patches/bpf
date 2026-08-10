// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

enum {
	QUEUE,
	STACK,
};

static void test_queue_stack_map_by_type(int type)
{
	const int MAP_SIZE = 32;
	__u32 vals[MAP_SIZE], val;
	int i, err, prog_fd, map_in_fd, map_out_fd;
	char file[32], buf[128];
	struct bpf_object *obj;
	struct iphdr iph = {};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	/* Fill test values to be used */
	for (i = 0; i < MAP_SIZE; i++)
		vals[i] = rand();

	if (type == QUEUE)
		strscpy(file, "./test_queue_map.bpf.o");
	else if (type == STACK)
		strscpy(file, "./test_stack_map.bpf.o");
	else
		return;

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	map_in_fd = bpf_find_map(__func__, obj, "map_in");
	if (map_in_fd < 0)
		goto out;

	map_out_fd = bpf_find_map(__func__, obj, "map_out");
	if (map_out_fd < 0)
		goto out;

	/* Push 32 elements to the input map */
	for (i = 0; i < MAP_SIZE; i++) {
		err = bpf_map_update_elem(map_in_fd, NULL, &vals[i], 0);
		if (CHECK_FAIL(err))
			goto out;
	}

	/* The eBPF program pushes iph.saddr in the output map,
	 * pops the input map and saves this value in iph.daddr
	 */
	for (i = 0; i < MAP_SIZE; i++) {
		if (type == QUEUE) {
			val = vals[i];
			pkt_v4.iph.saddr = vals[i] * 5;
		} else if (type == STACK) {
			val = vals[MAP_SIZE - 1 - i];
			pkt_v4.iph.saddr = vals[MAP_SIZE - 1 - i] * 5;
		}

		topts.data_size_out = sizeof(buf);
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (err || topts.retval ||
		    topts.data_size_out != sizeof(pkt_v4))
			break;
		memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
		if (iph.daddr != val)
			break;
	}

	ASSERT_OK(err, "bpf_map_pop_elem");
	ASSERT_OK(topts.retval, "bpf_map_pop_elem test retval");
	ASSERT_EQ(topts.data_size_out, sizeof(pkt_v4),
		  "bpf_map_pop_elem data_size_out");
	ASSERT_EQ(iph.daddr, val, "bpf_map_pop_elem iph.daddr");

	/* Queue is empty, program should return TC_ACT_SHOT */
	topts.data_size_out = sizeof(buf);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "check-queue-stack-map-empty");
	ASSERT_EQ(topts.retval, 2  /* TC_ACT_SHOT */,
		  "check-queue-stack-map-empty test retval");
	ASSERT_EQ(topts.data_size_out, sizeof(pkt_v4),
		  "check-queue-stack-map-empty data_size_out");

	/* Check that the program pushed elements correctly */
	for (i = 0; i < MAP_SIZE; i++) {
		err = bpf_map_lookup_and_delete_elem(map_out_fd, NULL, &val);
		ASSERT_OK(err, "bpf_map_lookup_and_delete_elem");
		ASSERT_EQ(val, vals[i] * 5, "bpf_map_push_elem val");
	}
out:
	pkt_v4.iph.saddr = 0;
	bpf_object__close(obj);
}

static void test_queue_stack_map_alloc_check(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	const __u32 big_value = 1 << 20; /* 1MB */
	int fd, saved_errno;

	/*
	 * Regression test for the u32 index overflow in queue/stack maps:
	 * a map whose element storage (max_entries * value_size) exceeds
	 * U32_MAX bytes must be rejected at creation time, otherwise the
	 * u32 head/tail index multiplication wraps and push/peek/pop
	 * address the wrong element. 8192 * 1MB = 8GB > U32_MAX.
	 */
	fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, NULL, 0, big_value, 8192, &opts);
	saved_errno = errno;
	ASSERT_LT(fd, 0, "queue_oversize_fd");
	ASSERT_EQ(saved_errno, E2BIG, "queue_oversize_errno");

	/*
	 * max_entries == U32_MAX would make the u32 capacity counter
	 * qs->size (max_entries + 1) wrap to 0, permanently breaking the
	 * map, so it must be rejected as well.
	 */
	fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, NULL, 0, 1, U32_MAX, &opts);
	saved_errno = errno;
	ASSERT_LT(fd, 0, "queue_u32max_fd");
	ASSERT_EQ(saved_errno, E2BIG, "queue_u32max_errno");
	if (fd >= 0)
		close(fd);

	fd = bpf_map_create(BPF_MAP_TYPE_STACK, NULL, 0, big_value, 8192, &opts);
	saved_errno = errno;
	ASSERT_LT(fd, 0, "stack_oversize_fd");
	ASSERT_EQ(saved_errno, E2BIG, "stack_oversize_errno");
	if (fd >= 0)
		close(fd);

	/* A normal-sized map must still be created successfully. */
	fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, NULL, 0, 64, 100, &opts);
	ASSERT_GE(fd, 0, "queue_normal_fd");
	if (fd >= 0)
		close(fd);
}

void test_queue_stack_map(void)
{
	test_queue_stack_map_by_type(QUEUE);
	test_queue_stack_map_by_type(STACK);
	test_queue_stack_map_alloc_check();
}
