// SPDX-License-Identifier: GPL-2.0
#include <unistd.h>
#include <test_progs.h>
#include "tailcall_poke.skel.h"

#define JMP_TABLE "/sys/fs/bpf/jmp_table"

static int thread_exit;

static void *update(void *arg)
{
	__u32 zero = 0, prog1_fd, prog2_fd, map_fd;
	struct tailcall_poke *call = arg;

	map_fd = bpf_map__fd(call->maps.jmp_table);
	prog1_fd = bpf_program__fd(call->progs.call1);
	prog2_fd = bpf_program__fd(call->progs.call2);

	while (!thread_exit) {
		bpf_map_update_elem(map_fd, &zero, &prog1_fd, BPF_ANY);
		bpf_map_update_elem(map_fd, &zero, &prog2_fd, BPF_ANY);
	}

	return NULL;
}

void test_tailcall_poke(void)
{
	struct tailcall_poke *call, *test;
	int err, cnt = 10;
	pthread_t thread;

	unlink(JMP_TABLE);

	call = tailcall_poke__open_and_load();
	if (!ASSERT_OK_PTR(call, "tailcall_poke__open"))
		return;

	err = bpf_map__pin(call->maps.jmp_table, JMP_TABLE);
	if (!ASSERT_OK(err, "bpf_map__pin"))
		goto out;

	err = pthread_create(&thread, NULL, update, call);
	if (!ASSERT_OK(err, "new toggler"))
		goto out;

	while (cnt--) {
		test = tailcall_poke__open();
		if (!ASSERT_OK_PTR(test, "tailcall_poke__open"))
			break;

		err = bpf_map__set_pin_path(test->maps.jmp_table, JMP_TABLE);
		if (!ASSERT_OK(err, "bpf_map__pin")) {
			tailcall_poke__destroy(test);
			break;
		}

		bpf_program__set_autoload(test->progs.test, true);
		bpf_program__set_autoload(test->progs.call1, false);
		bpf_program__set_autoload(test->progs.call2, false);

		err = tailcall_poke__load(test);
		if (!ASSERT_OK(err, "tailcall_poke__load")) {
			tailcall_poke__destroy(test);
			break;
		}

		tailcall_poke__destroy(test);
	}

	thread_exit = 1;
	ASSERT_OK(pthread_join(thread, NULL), "pthread_join");

out:
	bpf_map__unpin(call->maps.jmp_table, JMP_TABLE);
	tailcall_poke__destroy(call);
}
