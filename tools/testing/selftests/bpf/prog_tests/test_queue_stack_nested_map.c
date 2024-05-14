// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "test_queue_stack_nested_map.skel.h"


static void test_map_queue_stack_nesting_success(bool is_map_queue)
{
	struct test_queue_stack_nested_map *skel;
	int err;

	skel = test_queue_stack_nested_map__open();
	if (!ASSERT_OK_PTR(skel, "test_queue_stack_nested_map__open"))
		return;

	err = test_queue_stack_nested_map__load(skel);
	if (!ASSERT_OK(err, "test_queue_stack_nested_map__load"))
		goto out;

	skel->bss->pid = getpid();
	err = test_queue_stack_nested_map__attach(skel);
	if (!ASSERT_OK(err, "test_queue_stack_nested_map__attach"))
		goto out;

	/* trigger map from userspace to check nesting */
	int value = 0;

	do {
		if (is_map_queue) {
			err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_queue),
								NULL, &value, 0);
			if (err < 0)
				break;
			err = bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.map_queue),
								 NULL, &value);
		} else {
			err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_stack),
								NULL, &value, 0);
			if (err < 0)
				break;
			err = bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.map_stack),
								NULL, &value);
		}
	} while (0);


	if (!ASSERT_OK(err, "MAP Write"))
		goto out;

	if (is_map_queue) {
		ASSERT_EQ(skel->bss->err_queue_push, -EBUSY, "no map nesting");
		ASSERT_EQ(skel->bss->err_queue_pop, -EBUSY, "no map nesting");
	} else {
		ASSERT_EQ(skel->bss->err_stack, -EBUSY, "no map nesting");
	}
out:
	test_queue_stack_nested_map__destroy(skel);
}

void test_test_queue_stack_nested_map(void)
{
	if (test__start_subtest("map_queue_nesting"))
		test_map_queue_stack_nesting_success(true);
	if (test__start_subtest("map_stack_nesting"))
		test_map_queue_stack_nesting_success(false);

}

