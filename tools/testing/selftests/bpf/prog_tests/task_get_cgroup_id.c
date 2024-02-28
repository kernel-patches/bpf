#include <test_progs.h>
#include <cgroup_helpers.h>
#include "test_task_get_cgroup_id.skel.h"
#include <unistd.h>

#define TEST_CGROUP "/test-task-get-cgroup-id/"

void test_task_get_cgroup_id(void)
{
	struct test_task_get_cgroup_id *skel;
	int err, fd;
	pid_t pid;
	__u64 cgroup_id, actual_cgroup_id;
	const struct timespec req = {
		.tv_sec = 1,
		.tv_nsec = 0,
	};

	fd = test__join_cgroup(TEST_CGROUP);
	if (!ASSERT_OK(fd < 0, "test_join_cgroup_TEST_CGROUP"))
		return;

	skel = test_task_get_cgroup_id__open();
	if (!ASSERT_OK_PTR(skel, "test_task_get_cgroup_id__open"))
		goto cleanup;

	err = test_task_get_cgroup_id__load(skel);
	if (!ASSERT_OK(err, "test_task_get_cgroup_id__load"))
		goto cleanup;

	err = test_task_get_cgroup_id__attach(skel);
	if (!ASSERT_OK(err, "test_task_get_cgroup_id__attach"))
		goto cleanup;

	pid = getpid();
	actual_cgroup_id = get_cgroup_id(TEST_CGROUP);
	if (!ASSERT_GT(actual_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	/* Trigger nanosleep to enter the sched_switch tracepoint */
    /* The previous task should be this process */
	syscall(__NR_nanosleep, &req, NULL);

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.pid_to_cgid_map), &pid,
				  &cgroup_id);

	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		goto cleanup;

	ASSERT_EQ(actual_cgroup_id, cgroup_id, "cgroup_id");

cleanup:
	test_task_get_cgroup_id__destroy(skel);
	close(fd);
}