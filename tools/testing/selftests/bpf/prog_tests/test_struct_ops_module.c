// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <time.h>

#include <sys/epoll.h>

#include "struct_ops_module.skel.h"
#include "struct_ops_nulled_out_cb.skel.h"
#include "struct_ops_forgotten_cb.skel.h"
#include "struct_ops_detach.skel.h"
#include "struct_ops_map_release.skel.h"
#include "unsupported_ops.skel.h"

static void check_map_info(struct bpf_map_info *info)
{
	struct bpf_btf_info btf_info;
	char btf_name[256];
	u32 btf_info_len = sizeof(btf_info);
	int err, fd;

	fd = bpf_btf_get_fd_by_id(info->btf_vmlinux_id);
	if (!ASSERT_GE(fd, 0, "get_value_type_btf_obj_fd"))
		return;

	memset(&btf_info, 0, sizeof(btf_info));
	btf_info.name = ptr_to_u64(btf_name);
	btf_info.name_len = sizeof(btf_name);
	err = bpf_btf_get_info_by_fd(fd, &btf_info, &btf_info_len);
	if (!ASSERT_OK(err, "get_value_type_btf_obj_info"))
		goto cleanup;

	if (!ASSERT_EQ(strcmp(btf_name, "bpf_testmod"), 0, "get_value_type_btf_obj_name"))
		goto cleanup;

cleanup:
	close(fd);
}

static int attach_ops_and_check(struct struct_ops_module *skel,
				struct bpf_map *map,
				int expected_test_2_result)
{
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(map);
	ASSERT_OK_PTR(link, "attach_test_mod_1");
	if (!link)
		return -1;

	/* test_{1,2}() would be called from bpf_dummy_reg() in bpf_testmod.c */
	ASSERT_EQ(skel->bss->test_1_result, 0xdeadbeef, "test_1_result");
	ASSERT_EQ(skel->bss->test_2_result, expected_test_2_result, "test_2_result");

	bpf_link__destroy(link);
	return 0;
}

static void test_struct_ops_load(void)
{
	struct struct_ops_module *skel;
	struct bpf_map_info info = {};
	int err;
	u32 len;

	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;

	skel->struct_ops.testmod_1->data = 13;
	skel->struct_ops.testmod_1->test_2 = skel->progs.test_3;
	/* Since test_2() is not being used, it should be disabled from
	 * auto-loading, or it will fail to load.
	 */
	bpf_program__set_autoload(skel->progs.test_2, false);
	bpf_map__set_autocreate(skel->maps.testmod_zeroed, false);

	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		goto cleanup;

	len = sizeof(info);
	err = bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.testmod_1), &info,
				     &len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto cleanup;

	check_map_info(&info);
	/* test_3() will be called from bpf_dummy_reg() in bpf_testmod.c
	 *
	 * In bpf_testmod.c it will pass 4 and 13 (the value of data) to
	 * .test_2.  So, the value of test_2_result should be 20 (4 + 13 +
	 * 3).
	 */
	if (!attach_ops_and_check(skel, skel->maps.testmod_1, 20))
		goto cleanup;
	if (!attach_ops_and_check(skel, skel->maps.testmod_2, 12))
		goto cleanup;

cleanup:
	struct_ops_module__destroy(skel);
}

static void test_struct_ops_not_zeroed(void)
{
	struct struct_ops_module *skel;
	int err;

	/* zeroed is 0, and zeroed_op is null */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;

	skel->struct_ops.testmod_zeroed->zeroed = 0;
	/* zeroed_op prog should be not loaded automatically now */
	skel->struct_ops.testmod_zeroed->zeroed_op = NULL;

	err = struct_ops_module__load(skel);
	ASSERT_OK(err, "struct_ops_module_load");

	struct_ops_module__destroy(skel);

	/* zeroed is not 0 */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_not_zeroed"))
		return;

	/* libbpf should reject the testmod_zeroed since struct
	 * bpf_testmod_ops in the kernel has no "zeroed" field and the
	 * value of "zeroed" is non-zero.
	 */
	skel->struct_ops.testmod_zeroed->zeroed = 0xdeadbeef;
	skel->struct_ops.testmod_zeroed->zeroed_op = NULL;
	err = struct_ops_module__load(skel);
	ASSERT_ERR(err, "struct_ops_module_load_not_zeroed");

	struct_ops_module__destroy(skel);

	/* zeroed_op is not null */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_not_zeroed_op"))
		return;

	/* libbpf should reject the testmod_zeroed since the value of its
	 * "zeroed_op" is not null.
	 */
	skel->struct_ops.testmod_zeroed->zeroed_op = skel->progs.test_3;
	err = struct_ops_module__load(skel);
	ASSERT_ERR(err, "struct_ops_module_load_not_zeroed_op");

	struct_ops_module__destroy(skel);
}

/* The signature of an implementation might not match the signature of the
 * function pointer prototype defined in the BPF program. This mismatch
 * should be allowed as long as the behavior of the operator program
 * adheres to the signature in the kernel. Libbpf should not enforce the
 * signature; rather, let the kernel verifier handle the enforcement.
 */
static void test_struct_ops_incompatible(void)
{
	struct struct_ops_module *skel;
	struct bpf_link *link;
	int err;

	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;

	bpf_map__set_autocreate(skel->maps.testmod_zeroed, false);

	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_incompatible);
	if (ASSERT_OK_PTR(link, "attach_struct_ops"))
		bpf_link__destroy(link);

cleanup:
	struct_ops_module__destroy(skel);
}

/* validate that it's ok to "turn off" callback that kernel supports */
static void test_struct_ops_nulled_out_cb(void)
{
	struct struct_ops_nulled_out_cb *skel;
	int err;

	skel = struct_ops_nulled_out_cb__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/* kernel knows about test_1, but we still null it out */
	skel->struct_ops.ops->test_1 = NULL;

	err = struct_ops_nulled_out_cb__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	ASSERT_FALSE(bpf_program__autoload(skel->progs.test_1_turn_off), "prog_autoload");
	ASSERT_LT(bpf_program__fd(skel->progs.test_1_turn_off), 0, "prog_fd");

cleanup:
	struct_ops_nulled_out_cb__destroy(skel);
}

/* validate that libbpf generates reasonable error message if struct_ops is
 * not referenced in any struct_ops map
 */
static void test_struct_ops_forgotten_cb(void)
{
	struct struct_ops_forgotten_cb *skel;
	char *log;
	int err;

	skel = struct_ops_forgotten_cb__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	start_libbpf_log_capture();

	err = struct_ops_forgotten_cb__load(skel);
	if (!ASSERT_ERR(err, "skel_load"))
		goto cleanup;

	log = stop_libbpf_log_capture();
	ASSERT_HAS_SUBSTR(log,
			  "prog 'test_1_forgotten': SEC(\"struct_ops\") program isn't referenced anywhere, did you forget to use it?",
			  "libbpf_log");
	free(log);

	struct_ops_forgotten_cb__destroy(skel);

	/* now let's programmatically use it, we should be fine now */
	skel = struct_ops_forgotten_cb__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->struct_ops.ops->test_1 = skel->progs.test_1_forgotten; /* not anymore */

	err = struct_ops_forgotten_cb__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

cleanup:
	struct_ops_forgotten_cb__destroy(skel);
}

struct test_context {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int total_threads;
	int wait_threads;
	int dead_threads;
	int repeat;
	int loop;
};

static int wait_others(struct test_context *ctx)
{
	int ret = 0;

	pthread_mutex_lock(&ctx->mutex);

	if (ctx->dead_threads) {
		pthread_cond_broadcast(&ctx->cond);
		pthread_mutex_unlock(&ctx->mutex);
		return -1;
	}

	++ctx->wait_threads;
	if (ctx->wait_threads >= ctx->total_threads) {
		pthread_cond_broadcast(&ctx->cond);
		ctx->wait_threads = 0;
	} else {
		pthread_cond_wait(&ctx->cond, &ctx->mutex);
		if (ctx->dead_threads)
			ret = -1;
	}

	pthread_mutex_unlock(&ctx->mutex);

	return ret;
}

static void mark_dead(struct test_context *ctx)
{
	pthread_mutex_lock(&ctx->mutex);
	ctx->dead_threads++;
	pthread_cond_broadcast(&ctx->cond);
	pthread_mutex_unlock(&ctx->mutex);
}

static int load_release(struct test_context *ctx)
{
	int ret = 0;
	struct bpf_link *link = NULL;
	struct struct_ops_map_release *skel = NULL;

	skel = struct_ops_map_release__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load")) {
		ret = -1;
		mark_dead(ctx);
		goto out;
	}

	link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops")) {
		ret = -1;
		mark_dead(ctx);
		goto out;
	}

	if (wait_others(ctx)) {
		ret = -1;
		goto out;
	}

out:
	bpf_link__destroy(link);
	struct_ops_map_release__destroy(skel);
	return ret;
}

static void *thread_load_release(void *arg)
{
	struct test_context *ctx = (struct test_context *)arg;

	for (int i = 0; i < ctx->loop; i++)
		if (load_release(ctx))
			break;
	return NULL;
}

static void *thread_run_prog(void *arg)
{
	int fd;
	int len;
	char buf[8];
	struct test_context *ctx = (struct test_context *)arg;

	fd = open("/sys/module/bpf_testmod/parameters/run_struct_ops", O_WRONLY);
	if (!ASSERT_OK_FD(fd, "open run_struct_ops for write")) {
		mark_dead(ctx);
		return NULL;
	}

	len = snprintf(buf, sizeof(buf), "%d", ctx->repeat);
	if (!ASSERT_GT(len, 0, "snprintf repeat number")) {
		mark_dead(ctx);
		goto out;
	}

	for (int i = 0; i < ctx->loop; i++) {
		if (wait_others(ctx))
			goto out;
		if (!ASSERT_EQ(write(fd, buf, len), len, "write file")) {
			mark_dead(ctx);
			goto out;
		}
	}

out:
	close(fd);
	return NULL;
}

#define NR_REL_THREAD	2
#define NR_RUN_THREAD	8
#define NR_THREAD	(NR_REL_THREAD + NR_RUN_THREAD)
#define NR_REPEAT	4
#define NR_LOOP		5

static void test_struct_ops_map_release(void)
{
	int i, j;
	pthread_t t[NR_THREAD];
	struct test_context ctx = {
		.loop = NR_LOOP,
		.repeat = NR_REPEAT,
		.total_threads = NR_THREAD,
		.wait_threads = 0,
		.dead_threads = 0,
	};

	pthread_mutex_init(&ctx.mutex, NULL);
	pthread_cond_init(&ctx.cond, NULL);

	j = 0;
	for (i = 0; i < NR_REL_THREAD; i++)
		pthread_create(&t[j++], NULL, thread_load_release, &ctx);

	for (i = 0; i < NR_RUN_THREAD; i++)
		pthread_create(&t[j++], NULL, thread_run_prog, &ctx);

	for (i = 0; i < NR_THREAD; i++)
		pthread_join(t[i], NULL);
}

/* Detach a link from a user space program */
static void test_detach_link(void)
{
	struct epoll_event ev, events[2];
	struct struct_ops_detach *skel;
	struct bpf_link *link = NULL;
	int fd, epollfd = -1, nfds;
	int err;

	skel = struct_ops_detach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_detach__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_do_detach);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto cleanup;

	fd = bpf_link__fd(link);
	if (!ASSERT_GE(fd, 0, "link_fd"))
		goto cleanup;

	epollfd = epoll_create1(0);
	if (!ASSERT_GE(epollfd, 0, "epoll_create1"))
		goto cleanup;

	ev.events = EPOLLHUP;
	ev.data.fd = fd;
	err = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
	if (!ASSERT_OK(err, "epoll_ctl"))
		goto cleanup;

	err = bpf_link__detach(link);
	if (!ASSERT_OK(err, "detach_link"))
		goto cleanup;

	/* Wait for EPOLLHUP */
	nfds = epoll_wait(epollfd, events, 2, 500);
	if (!ASSERT_EQ(nfds, 1, "epoll_wait"))
		goto cleanup;

	if (!ASSERT_EQ(events[0].data.fd, fd, "epoll_wait_fd"))
		goto cleanup;
	if (!ASSERT_TRUE(events[0].events & EPOLLHUP, "events[0].events"))
		goto cleanup;

cleanup:
	if (epollfd >= 0)
		close(epollfd);
	bpf_link__destroy(link);
	struct_ops_detach__destroy(skel);
}

void serial_test_struct_ops_module(void)
{
	if (test__start_subtest("struct_ops_load"))
		test_struct_ops_load();
	if (test__start_subtest("struct_ops_not_zeroed"))
		test_struct_ops_not_zeroed();
	if (test__start_subtest("struct_ops_incompatible"))
		test_struct_ops_incompatible();
	if (test__start_subtest("struct_ops_null_out_cb"))
		test_struct_ops_nulled_out_cb();
	if (test__start_subtest("struct_ops_forgotten_cb"))
		test_struct_ops_forgotten_cb();
	if (test__start_subtest("struct_ops_map_release"))
		test_struct_ops_map_release();
	if (test__start_subtest("test_detach_link"))
		test_detach_link();
	RUN_TESTS(unsupported_ops);
}

