// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>   /* For mmap and associated flags */
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/types.h>
#include <test_progs.h>
#include <network_helpers.h>
#include "task_local_storage_helpers.h"
#include "task_local_storage.skel.h"
#include "task_local_storage_exit_creds.skel.h"
#include "task_local_storage__mmap.skel.h"
#include "task_local_storage__mmap_fail.skel.h"
#include "task_ls_recursion.skel.h"
#include "task_storage_nodeadlock.skel.h"
#include "progs/task_local_storage__mmap.h"

static void test_sys_enter_exit(void)
{
	struct task_local_storage *skel;
	int err;

	skel = task_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->target_pid = syscall(SYS_gettid);

	err = task_local_storage__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	syscall(SYS_gettid);
	syscall(SYS_gettid);

	/* 3x syscalls: 1x attach and 2x gettid */
	ASSERT_EQ(skel->bss->enter_cnt, 3, "enter_cnt");
	ASSERT_EQ(skel->bss->exit_cnt, 3, "exit_cnt");
	ASSERT_EQ(skel->bss->mismatch_cnt, 0, "mismatch_cnt");
out:
	task_local_storage__destroy(skel);
}

static int basic_mmapable_read_write(struct task_local_storage__mmap *skel,
				     long *mmaped_task_local)
{
	int err;

	*mmaped_task_local = 42;

	err = task_local_storage__mmap__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		return -1;

	syscall(SYS_gettid);
	ASSERT_EQ(skel->bss->mmaped_mapval, 42, "mmaped_mapval");

	/* Incr from userspace should be visible when BPF prog reads */
	*mmaped_task_local = *mmaped_task_local + 1;
	syscall(SYS_gettid);
	ASSERT_EQ(skel->bss->mmaped_mapval, 43, "mmaped_mapval_user_incr");

	/* Incr from BPF prog should be visible from userspace */
	skel->bss->read_and_incr = 1;
	syscall(SYS_gettid);
	ASSERT_EQ(skel->bss->mmaped_mapval, 44, "mmaped_mapval_bpf_incr");
	ASSERT_EQ(skel->bss->mmaped_mapval, *mmaped_task_local, "bpf_incr_eq");
	skel->bss->read_and_incr = 0;

	return 0;
}

static void test_sys_enter_mmap(void)
{
	struct task_local_storage__mmap *skel;
	long *task_local, *task_local2, value;
	int err, task_fd, map_fd;

	task_local = task_local2 = (long *)-1;
	task_fd = sys_pidfd_open(getpid(), 0);
	if (!ASSERT_NEQ(task_fd, -1, "sys_pidfd_open"))
		return;

	skel = task_local_storage__mmap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load")) {
		close(task_fd);
		return;
	}

	map_fd = bpf_map__fd(skel->maps.mmapable);
	task_local = mmap(NULL, sizeof(long), PROT_READ | PROT_WRITE,
			  MAP_SHARED, map_fd, 0);
	if (!ASSERT_OK_PTR(task_local, "mmap_task_local_storage"))
		goto out;

	err = basic_mmapable_read_write(skel, task_local);
	if (!ASSERT_OK(err, "basic_mmapable_read_write"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem") ||
	    !ASSERT_EQ(value, 44, "bpf_map_lookup_elem value"))
		goto out;

	value = 148;
	bpf_map_update_elem(map_fd, &task_fd, &value, BPF_EXIST);
	if (!ASSERT_EQ(READ_ONCE(*task_local), 148, "mmaped_read_after_update"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem") ||
	    !ASSERT_EQ(value, 148, "bpf_map_lookup_elem value"))
		goto out;

	/* The mmapable page is not released by map_delete_elem, but no longer
	 * linked to local_storage
	 */
	err = bpf_map_delete_elem(map_fd, &task_fd);
	if (!ASSERT_OK(err, "bpf_map_delete_elem") ||
	    !ASSERT_EQ(READ_ONCE(*task_local), 148, "mmaped_read_after_delete"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	if (!ASSERT_EQ(err, -ENOENT, "bpf_map_lookup_elem_after_delete"))
		goto out;

	task_local_storage__mmap__destroy(skel);

	/* The mmapable page is not released when __destroy unloads the map.
	 * It will stick around until we munmap it
	 */
	*task_local = -999;

	/* Although task_local's page is still around, it won't be reused */
	skel = task_local_storage__mmap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load2"))
		return;

	map_fd = bpf_map__fd(skel->maps.mmapable);
	err = task_local_storage__mmap__attach(skel);
	if (!ASSERT_OK(err, "skel_attach2"))
		goto out;

	skel->bss->read_and_incr = 1;
	skel->bss->create_flag = BPF_LOCAL_STORAGE_GET_F_CREATE;
	syscall(SYS_gettid);
	ASSERT_EQ(skel->bss->mmaped_mapval, 1, "mmaped_mapval2");

	skel->bss->read_and_incr = 0;
	task_local2 = mmap(NULL, sizeof(long), PROT_READ | PROT_WRITE,
			   MAP_SHARED, map_fd, 0);
	if (!ASSERT_OK_PTR(task_local, "mmap_task_local_storage2"))
		goto out;

	if (!ASSERT_NEQ(task_local, task_local2, "second_mmap_address"))
		goto out;

	ASSERT_EQ(READ_ONCE(*task_local2), 1, "mmaped_mapval2_bpf_create_incr");

out:
	close(task_fd);
	if (task_local > 0)
		munmap(task_local, sizeof(long));
	if (task_local2 > 0)
		munmap(task_local2, sizeof(long));
	task_local_storage__mmap__destroy(skel);
}

static void test_sys_enter_mmap_big_mapval(void)
{
	struct two_page_struct *task_local, value;
	struct task_local_storage__mmap *skel;
	int task_fd, map_fd, err;

	task_local = (struct two_page_struct *)-1;
	task_fd = sys_pidfd_open(getpid(), 0);
	if (!ASSERT_NEQ(task_fd, -1, "sys_pidfd_open"))
		return;

	skel = task_local_storage__mmap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load")) {
		close(task_fd);
		return;
	}
	map_fd = bpf_map__fd(skel->maps.mmapable_two_pages);
	task_local = mmap(NULL, sizeof(struct two_page_struct),
			  PROT_READ | PROT_WRITE, MAP_SHARED,
			  map_fd, 0);
	if (!ASSERT_OK_PTR(task_local, "mmap_task_local_storage"))
		goto out;

	skel->bss->use_big_mapval = 1;
	err = basic_mmapable_read_write(skel, &task_local->val);
	if (!ASSERT_OK(err, "basic_mmapable_read_write"))
		goto out;

	task_local->c[4096] = 'z';

	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem") ||
	    !ASSERT_EQ(value.val, 44, "bpf_map_lookup_elem value"))
		goto out;

out:
	close(task_fd);
	if (task_local > 0)
		munmap(task_local, sizeof(struct two_page_struct));
	task_local_storage__mmap__destroy(skel);
}

static void test_exit_creds(void)
{
	struct task_local_storage_exit_creds *skel;
	int err, run_count, sync_rcu_calls = 0;
	const int MAX_SYNC_RCU_CALLS = 1000;

	skel = task_local_storage_exit_creds__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = task_local_storage_exit_creds__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* trigger at least one exit_creds() */
	if (CHECK_FAIL(system("ls > /dev/null")))
		goto out;

	/* kern_sync_rcu is not enough on its own as the read section we want
	 * to wait for may start after we enter synchronize_rcu, so our call
	 * won't wait for the section to finish. Loop on the run counter
	 * as well to ensure the program has run.
	 */
	do {
		kern_sync_rcu();
		run_count = __atomic_load_n(&skel->bss->run_count, __ATOMIC_SEQ_CST);
	} while (run_count == 0 && ++sync_rcu_calls < MAX_SYNC_RCU_CALLS);

	ASSERT_NEQ(sync_rcu_calls, MAX_SYNC_RCU_CALLS,
		   "sync_rcu count too high");
	ASSERT_NEQ(run_count, 0, "run_count");
	ASSERT_EQ(skel->bss->valid_ptr_count, 0, "valid_ptr_count");
	ASSERT_NEQ(skel->bss->null_ptr_count, 0, "null_ptr_count");
out:
	task_local_storage_exit_creds__destroy(skel);
}

static void test_recursion(void)
{
	int err, map_fd, prog_fd, task_fd;
	struct task_ls_recursion *skel;
	struct bpf_prog_info info;
	__u32 info_len = sizeof(info);
	long value;

	task_fd = sys_pidfd_open(getpid(), 0);
	if (!ASSERT_NEQ(task_fd, -1, "sys_pidfd_open"))
		return;

	skel = task_ls_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;

	err = task_ls_recursion__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* trigger sys_enter, make sure it does not cause deadlock */
	skel->bss->test_pid = getpid();
	syscall(SYS_gettid);
	skel->bss->test_pid = 0;
	task_ls_recursion__detach(skel);

	/* Refer to the comment in BPF_PROG(on_update) for
	 * the explanation on the value 201 and 100.
	 */
	map_fd = bpf_map__fd(skel->maps.map_a);
	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	ASSERT_OK(err, "lookup map_a");
	ASSERT_EQ(value, 201, "map_a value");
	ASSERT_EQ(skel->bss->nr_del_errs, 1, "bpf_task_storage_delete busy");

	map_fd = bpf_map__fd(skel->maps.map_b);
	err = bpf_map_lookup_elem(map_fd, &task_fd, &value);
	ASSERT_OK(err, "lookup map_b");
	ASSERT_EQ(value, 100, "map_b value");

	prog_fd = bpf_program__fd(skel->progs.on_lookup);
	memset(&info, 0, sizeof(info));
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_GT(info.recursion_misses, 0, "on_lookup prog recursion");

	prog_fd = bpf_program__fd(skel->progs.on_update);
	memset(&info, 0, sizeof(info));
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_EQ(info.recursion_misses, 0, "on_update prog recursion");

	prog_fd = bpf_program__fd(skel->progs.on_enter);
	memset(&info, 0, sizeof(info));
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_EQ(info.recursion_misses, 0, "on_enter prog recursion");

out:
	close(task_fd);
	task_ls_recursion__destroy(skel);
}

static bool stop;

static void waitall(const pthread_t *tids, int nr)
{
	int i;

	stop = true;
	for (i = 0; i < nr; i++)
		pthread_join(tids[i], NULL);
}

static void *sock_create_loop(void *arg)
{
	struct task_storage_nodeadlock *skel = arg;
	int fd;

	while (!stop) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		close(fd);
		if (skel->bss->nr_get_errs || skel->bss->nr_del_errs)
			stop = true;
	}

	return NULL;
}

static void test_nodeadlock(void)
{
	struct task_storage_nodeadlock *skel;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const int nr_threads = 32;
	pthread_t tids[nr_threads];
	int i, prog_fd, err;
	cpu_set_t old, new;

	/* Pin all threads to one cpu to increase the chance of preemption
	 * in a sleepable bpf prog.
	 */
	CPU_ZERO(&new);
	CPU_SET(0, &new);
	err = sched_getaffinity(getpid(), sizeof(old), &old);
	if (!ASSERT_OK(err, "getaffinity"))
		return;
	err = sched_setaffinity(getpid(), sizeof(new), &new);
	if (!ASSERT_OK(err, "setaffinity"))
		return;

	skel = task_storage_nodeadlock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto done;

	/* Unnecessary recursion and deadlock detection are reproducible
	 * in the preemptible kernel.
	 */
	if (!skel->kconfig->CONFIG_PREEMPT) {
		test__skip();
		goto done;
	}

	err = task_storage_nodeadlock__attach(skel);
	ASSERT_OK(err, "attach prog");

	for (i = 0; i < nr_threads; i++) {
		err = pthread_create(&tids[i], NULL, sock_create_loop, skel);
		if (err) {
			/* Only assert once here to avoid excessive
			 * PASS printing during test failure.
			 */
			ASSERT_OK(err, "pthread_create");
			waitall(tids, i);
			goto done;
		}
	}

	/* With 32 threads, 1s is enough to reproduce the issue */
	sleep(1);
	waitall(tids, nr_threads);

	info_len = sizeof(info);
	prog_fd = bpf_program__fd(skel->progs.socket_post_create);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	ASSERT_OK(err, "get prog info");
	ASSERT_EQ(info.recursion_misses, 0, "prog recursion");

	ASSERT_EQ(skel->bss->nr_get_errs, 0, "bpf_task_storage_get busy");
	ASSERT_EQ(skel->bss->nr_del_errs, 0, "bpf_task_storage_delete busy");

done:
	task_storage_nodeadlock__destroy(skel);
	sched_setaffinity(getpid(), sizeof(old), &old);
}

void test_task_local_storage(void)
{
	if (test__start_subtest("sys_enter_exit"))
		test_sys_enter_exit();
	if (test__start_subtest("sys_enter_mmap"))
		test_sys_enter_mmap();
	if (test__start_subtest("sys_enter_mmap_big_mapval"))
		test_sys_enter_mmap_big_mapval();
	if (test__start_subtest("exit_creds"))
		test_exit_creds();
	if (test__start_subtest("recursion"))
		test_recursion();
	if (test__start_subtest("nodeadlock"))
		test_nodeadlock();
	RUN_TESTS(task_local_storage__mmap_fail);
}
