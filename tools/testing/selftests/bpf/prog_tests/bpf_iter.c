// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <sys/mman.h>
#include <sys/epoll.h>
#include <test_progs.h>
#include <linux/io_uring.h>

#include "bpf_iter_ipv6_route.skel.h"
#include "bpf_iter_netlink.skel.h"
#include "bpf_iter_bpf_map.skel.h"
#include "bpf_iter_task.skel.h"
#include "bpf_iter_task_stack.skel.h"
#include "bpf_iter_task_file.skel.h"
#include "bpf_iter_task_vma.skel.h"
#include "bpf_iter_task_btf.skel.h"
#include "bpf_iter_tcp4.skel.h"
#include "bpf_iter_tcp6.skel.h"
#include "bpf_iter_udp4.skel.h"
#include "bpf_iter_udp6.skel.h"
#include "bpf_iter_unix.skel.h"
#include "bpf_iter_test_kern1.skel.h"
#include "bpf_iter_test_kern2.skel.h"
#include "bpf_iter_test_kern3.skel.h"
#include "bpf_iter_test_kern4.skel.h"
#include "bpf_iter_bpf_hash_map.skel.h"
#include "bpf_iter_bpf_percpu_hash_map.skel.h"
#include "bpf_iter_bpf_array_map.skel.h"
#include "bpf_iter_bpf_percpu_array_map.skel.h"
#include "bpf_iter_bpf_sk_storage_helpers.skel.h"
#include "bpf_iter_bpf_sk_storage_map.skel.h"
#include "bpf_iter_test_kern5.skel.h"
#include "bpf_iter_test_kern6.skel.h"
#include "bpf_iter_io_uring.skel.h"
#include "bpf_iter_epoll.skel.h"

static int duration;

static void test_btf_id_or_null(void)
{
	struct bpf_iter_test_kern3 *skel;

	skel = bpf_iter_test_kern3__open_and_load();
	if (CHECK(skel, "bpf_iter_test_kern3__open_and_load",
		  "skeleton open_and_load unexpectedly succeeded\n")) {
		bpf_iter_test_kern3__destroy(skel);
		return;
	}
}

static void do_dummy_read(struct bpf_program *prog)
{
	struct bpf_link *link;
	char buf[16] = {};
	int iter_fd, len;

	link = bpf_program__attach_iter(prog, NULL);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* not check contents, but ensure read() ends without error */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	CHECK(len < 0, "read", "read failed: %s\n", strerror(errno));

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
}

static int read_fd_into_buffer(int fd, char *buf, int size)
{
	int bufleft = size;
	int len;

	do {
		len = read(fd, buf, bufleft);
		if (len > 0) {
			buf += len;
			bufleft -= len;
		}
	} while (len > 0);

	return len < 0 ? len : size - bufleft;
}

static void test_ipv6_route(void)
{
	struct bpf_iter_ipv6_route *skel;

	skel = bpf_iter_ipv6_route__open_and_load();
	if (CHECK(!skel, "bpf_iter_ipv6_route__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_ipv6_route);

	bpf_iter_ipv6_route__destroy(skel);
}

static void test_netlink(void)
{
	struct bpf_iter_netlink *skel;

	skel = bpf_iter_netlink__open_and_load();
	if (CHECK(!skel, "bpf_iter_netlink__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_netlink);

	bpf_iter_netlink__destroy(skel);
}

static void test_bpf_map(void)
{
	struct bpf_iter_bpf_map *skel;

	skel = bpf_iter_bpf_map__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_map__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_bpf_map);

	bpf_iter_bpf_map__destroy(skel);
}

static void test_task(void)
{
	struct bpf_iter_task *skel;

	skel = bpf_iter_task__open_and_load();
	if (CHECK(!skel, "bpf_iter_task__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_task);

	bpf_iter_task__destroy(skel);
}

static void test_task_stack(void)
{
	struct bpf_iter_task_stack *skel;

	skel = bpf_iter_task_stack__open_and_load();
	if (CHECK(!skel, "bpf_iter_task_stack__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_task_stack);
	do_dummy_read(skel->progs.get_task_user_stacks);

	bpf_iter_task_stack__destroy(skel);
}

static void *do_nothing(void *arg)
{
	pthread_exit(arg);
}

static void test_task_file(void)
{
	struct bpf_iter_task_file *skel;
	pthread_t thread_id;
	void *ret;

	skel = bpf_iter_task_file__open_and_load();
	if (CHECK(!skel, "bpf_iter_task_file__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	skel->bss->tgid = getpid();

	if (CHECK(pthread_create(&thread_id, NULL, &do_nothing, NULL),
		  "pthread_create", "pthread_create failed\n"))
		goto done;

	do_dummy_read(skel->progs.dump_task_file);

	if (CHECK(pthread_join(thread_id, &ret) || ret != NULL,
		  "pthread_join", "pthread_join failed\n"))
		goto done;

	CHECK(skel->bss->count != 0, "check_count",
	      "invalid non pthread file visit count %d\n", skel->bss->count);

done:
	bpf_iter_task_file__destroy(skel);
}

#define TASKBUFSZ		32768

static char taskbuf[TASKBUFSZ];

static int do_btf_read(struct bpf_iter_task_btf *skel)
{
	struct bpf_program *prog = skel->progs.dump_task_struct;
	struct bpf_iter_task_btf__bss *bss = skel->bss;
	int iter_fd = -1, err;
	struct bpf_link *link;
	char *buf = taskbuf;
	int ret = 0;

	link = bpf_program__attach_iter(prog, NULL);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return ret;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	err = read_fd_into_buffer(iter_fd, buf, TASKBUFSZ);
	if (bss->skip) {
		printf("%s:SKIP:no __builtin_btf_type_id\n", __func__);
		ret = 1;
		test__skip();
		goto free_link;
	}

	if (CHECK(err < 0, "read", "read failed: %s\n", strerror(errno)))
		goto free_link;

	CHECK(strstr(taskbuf, "(struct task_struct)") == NULL,
	      "check for btf representation of task_struct in iter data",
	      "struct task_struct not found");
free_link:
	if (iter_fd > 0)
		close(iter_fd);
	bpf_link__destroy(link);
	return ret;
}

static void test_task_btf(void)
{
	struct bpf_iter_task_btf__bss *bss;
	struct bpf_iter_task_btf *skel;
	int ret;

	skel = bpf_iter_task_btf__open_and_load();
	if (CHECK(!skel, "bpf_iter_task_btf__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	bss = skel->bss;

	ret = do_btf_read(skel);
	if (ret)
		goto cleanup;

	if (CHECK(bss->tasks == 0, "check if iterated over tasks",
		  "no task iteration, did BPF program run?\n"))
		goto cleanup;

	CHECK(bss->seq_err != 0, "check for unexpected err",
	      "bpf_seq_printf_btf returned %ld", bss->seq_err);

cleanup:
	bpf_iter_task_btf__destroy(skel);
}

static void test_tcp4(void)
{
	struct bpf_iter_tcp4 *skel;

	skel = bpf_iter_tcp4__open_and_load();
	if (CHECK(!skel, "bpf_iter_tcp4__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_tcp4);

	bpf_iter_tcp4__destroy(skel);
}

static void test_tcp6(void)
{
	struct bpf_iter_tcp6 *skel;

	skel = bpf_iter_tcp6__open_and_load();
	if (CHECK(!skel, "bpf_iter_tcp6__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_tcp6);

	bpf_iter_tcp6__destroy(skel);
}

static void test_udp4(void)
{
	struct bpf_iter_udp4 *skel;

	skel = bpf_iter_udp4__open_and_load();
	if (CHECK(!skel, "bpf_iter_udp4__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_udp4);

	bpf_iter_udp4__destroy(skel);
}

static void test_udp6(void)
{
	struct bpf_iter_udp6 *skel;

	skel = bpf_iter_udp6__open_and_load();
	if (CHECK(!skel, "bpf_iter_udp6__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	do_dummy_read(skel->progs.dump_udp6);

	bpf_iter_udp6__destroy(skel);
}

static void test_unix(void)
{
	struct bpf_iter_unix *skel;

	skel = bpf_iter_unix__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_unix__open_and_load"))
		return;

	do_dummy_read(skel->progs.dump_unix);

	bpf_iter_unix__destroy(skel);
}

/* The expected string is less than 16 bytes */
static int do_read_with_fd(int iter_fd, const char *expected,
			   bool read_one_char)
{
	int err = -1, len, read_buf_len, start;
	char buf[16] = {};

	read_buf_len = read_one_char ? 1 : 16;
	start = 0;
	while ((len = read(iter_fd, buf + start, read_buf_len)) > 0) {
		start += len;
		if (CHECK(start >= 16, "read", "read len %d\n", len))
			return -1;
		read_buf_len = read_one_char ? 1 : 16 - start;
	}
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		return -1;

	err = strcmp(buf, expected);
	if (CHECK(err, "read", "incorrect read result: buf %s, expected %s\n",
		  buf, expected))
		return -1;

	return 0;
}

static void test_anon_iter(bool read_one_char)
{
	struct bpf_iter_test_kern1 *skel;
	struct bpf_link *link;
	int iter_fd, err;

	skel = bpf_iter_test_kern1__open_and_load();
	if (CHECK(!skel, "bpf_iter_test_kern1__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	err = bpf_iter_test_kern1__attach(skel);
	if (CHECK(err, "bpf_iter_test_kern1__attach",
		  "skeleton attach failed\n")) {
		goto out;
	}

	link = skel->links.dump_task;
	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto out;

	do_read_with_fd(iter_fd, "abcd", read_one_char);
	close(iter_fd);

out:
	bpf_iter_test_kern1__destroy(skel);
}

static int do_read(const char *path, const char *expected)
{
	int err, iter_fd;

	iter_fd = open(path, O_RDONLY);
	if (CHECK(iter_fd < 0, "open", "open %s failed: %s\n",
		  path, strerror(errno)))
		return -1;

	err = do_read_with_fd(iter_fd, expected, false);
	close(iter_fd);
	return err;
}

static void test_file_iter(void)
{
	const char *path = "/sys/fs/bpf/bpf_iter_test1";
	struct bpf_iter_test_kern1 *skel1;
	struct bpf_iter_test_kern2 *skel2;
	struct bpf_link *link;
	int err;

	skel1 = bpf_iter_test_kern1__open_and_load();
	if (CHECK(!skel1, "bpf_iter_test_kern1__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	link = bpf_program__attach_iter(skel1->progs.dump_task, NULL);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	/* unlink this path if it exists. */
	unlink(path);

	err = bpf_link__pin(link, path);
	if (CHECK(err, "pin_iter", "pin_iter to %s failed: %d\n", path, err))
		goto free_link;

	err = do_read(path, "abcd");
	if (err)
		goto unlink_path;

	/* file based iterator seems working fine. Let us a link update
	 * of the underlying link and `cat` the iterator again, its content
	 * should change.
	 */
	skel2 = bpf_iter_test_kern2__open_and_load();
	if (CHECK(!skel2, "bpf_iter_test_kern2__open_and_load",
		  "skeleton open_and_load failed\n"))
		goto unlink_path;

	err = bpf_link__update_program(link, skel2->progs.dump_task);
	if (CHECK(err, "update_prog", "update_prog failed\n"))
		goto destroy_skel2;

	do_read(path, "ABCD");

destroy_skel2:
	bpf_iter_test_kern2__destroy(skel2);
unlink_path:
	unlink(path);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_test_kern1__destroy(skel1);
}

static void test_overflow(bool test_e2big_overflow, bool ret1)
{
	__u32 map_info_len, total_read_len, expected_read_len;
	int err, iter_fd, map1_fd, map2_fd, len;
	struct bpf_map_info map_info = {};
	struct bpf_iter_test_kern4 *skel;
	struct bpf_link *link;
	__u32 iter_size;
	char *buf;

	skel = bpf_iter_test_kern4__open();
	if (CHECK(!skel, "bpf_iter_test_kern4__open",
		  "skeleton open failed\n"))
		return;

	/* create two maps: bpf program will only do bpf_seq_write
	 * for these two maps. The goal is one map output almost
	 * fills seq_file buffer and then the other will trigger
	 * overflow and needs restart.
	 */
	map1_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0);
	if (CHECK(map1_fd < 0, "bpf_create_map",
		  "map_creation failed: %s\n", strerror(errno)))
		goto out;
	map2_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0);
	if (CHECK(map2_fd < 0, "bpf_create_map",
		  "map_creation failed: %s\n", strerror(errno)))
		goto free_map1;

	/* bpf_seq_printf kernel buffer is 8 pages, so one map
	 * bpf_seq_write will mostly fill it, and the other map
	 * will partially fill and then trigger overflow and need
	 * bpf_seq_read restart.
	 */
	iter_size = sysconf(_SC_PAGE_SIZE) << 3;

	if (test_e2big_overflow) {
		skel->rodata->print_len = (iter_size + 8) / 8;
		expected_read_len = 2 * (iter_size + 8);
	} else if (!ret1) {
		skel->rodata->print_len = (iter_size - 8) / 8;
		expected_read_len = 2 * (iter_size - 8);
	} else {
		skel->rodata->print_len = 1;
		expected_read_len = 2 * 8;
	}
	skel->rodata->ret1 = ret1;

	if (CHECK(bpf_iter_test_kern4__load(skel),
		  "bpf_iter_test_kern4__load", "skeleton load failed\n"))
		goto free_map2;

	/* setup filtering map_id in bpf program */
	map_info_len = sizeof(map_info);
	err = bpf_obj_get_info_by_fd(map1_fd, &map_info, &map_info_len);
	if (CHECK(err, "get_map_info", "get map info failed: %s\n",
		  strerror(errno)))
		goto free_map2;
	skel->bss->map1_id = map_info.id;

	err = bpf_obj_get_info_by_fd(map2_fd, &map_info, &map_info_len);
	if (CHECK(err, "get_map_info", "get map info failed: %s\n",
		  strerror(errno)))
		goto free_map2;
	skel->bss->map2_id = map_info.id;

	link = bpf_program__attach_iter(skel->progs.dump_bpf_map, NULL);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto free_map2;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	buf = malloc(expected_read_len);
	if (!buf)
		goto close_iter;

	/* do read */
	total_read_len = 0;
	if (test_e2big_overflow) {
		while ((len = read(iter_fd, buf, expected_read_len)) > 0)
			total_read_len += len;

		CHECK(len != -1 || errno != E2BIG, "read",
		      "expected ret -1, errno E2BIG, but get ret %d, error %s\n",
			  len, strerror(errno));
		goto free_buf;
	} else if (!ret1) {
		while ((len = read(iter_fd, buf, expected_read_len)) > 0)
			total_read_len += len;

		if (CHECK(len < 0, "read", "read failed: %s\n",
			  strerror(errno)))
			goto free_buf;
	} else {
		do {
			len = read(iter_fd, buf, expected_read_len);
			if (len > 0)
				total_read_len += len;
		} while (len > 0 || len == -EAGAIN);

		if (CHECK(len < 0, "read", "read failed: %s\n",
			  strerror(errno)))
			goto free_buf;
	}

	if (CHECK(total_read_len != expected_read_len, "read",
		  "total len %u, expected len %u\n", total_read_len,
		  expected_read_len))
		goto free_buf;

	if (CHECK(skel->bss->map1_accessed != 1, "map1_accessed",
		  "expected 1 actual %d\n", skel->bss->map1_accessed))
		goto free_buf;

	if (CHECK(skel->bss->map2_accessed != 2, "map2_accessed",
		  "expected 2 actual %d\n", skel->bss->map2_accessed))
		goto free_buf;

	CHECK(skel->bss->map2_seqnum1 != skel->bss->map2_seqnum2,
	      "map2_seqnum", "two different seqnum %lld %lld\n",
	      skel->bss->map2_seqnum1, skel->bss->map2_seqnum2);

free_buf:
	free(buf);
close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
free_map2:
	close(map2_fd);
free_map1:
	close(map1_fd);
out:
	bpf_iter_test_kern4__destroy(skel);
}

static void test_bpf_hash_map(void)
{
	__u32 expected_key_a = 0, expected_key_b = 0;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_hash_map *skel;
	int err, i, len, map_fd, iter_fd;
	union bpf_iter_link_info linfo;
	__u64 val, expected_val = 0;
	struct bpf_link *link;
	struct key_t {
		int a;
		int b;
		int c;
	} key;
	char buf[64];

	skel = bpf_iter_bpf_hash_map__open();
	if (CHECK(!skel, "bpf_iter_bpf_hash_map__open",
		  "skeleton open failed\n"))
		return;

	skel->bss->in_test_mode = true;

	err = bpf_iter_bpf_hash_map__load(skel);
	if (CHECK(!skel, "bpf_iter_bpf_hash_map__load",
		  "skeleton load failed\n"))
		goto out;

	/* iterator with hashmap2 and hashmap3 should fail */
	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = bpf_map__fd(skel->maps.hashmap2);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		goto out;

	linfo.map.map_fd = bpf_map__fd(skel->maps.hashmap3);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		goto out;

	/* hashmap1 should be good, update map values here */
	map_fd = bpf_map__fd(skel->maps.hashmap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.hashmap1); i++) {
		key.a = i + 1;
		key.b = i + 2;
		key.c = i + 3;
		val = i + 4;
		expected_key_a += key.a;
		expected_key_b += key.b;
		expected_val += val;

		err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	linfo.map.map_fd = map_fd;
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	if (CHECK(skel->bss->key_sum_a != expected_key_a,
		  "key_sum_a", "got %u expected %u\n",
		  skel->bss->key_sum_a, expected_key_a))
		goto close_iter;
	if (CHECK(skel->bss->key_sum_b != expected_key_b,
		  "key_sum_b", "got %u expected %u\n",
		  skel->bss->key_sum_b, expected_key_b))
		goto close_iter;
	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %llu expected %llu\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_hash_map__destroy(skel);
}

static void test_bpf_percpu_hash_map(void)
{
	__u32 expected_key_a = 0, expected_key_b = 0;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_percpu_hash_map *skel;
	int err, i, j, len, map_fd, iter_fd;
	union bpf_iter_link_info linfo;
	__u32 expected_val = 0;
	struct bpf_link *link;
	struct key_t {
		int a;
		int b;
		int c;
	} key;
	char buf[64];
	void *val;

	skel = bpf_iter_bpf_percpu_hash_map__open();
	if (CHECK(!skel, "bpf_iter_bpf_percpu_hash_map__open",
		  "skeleton open failed\n"))
		return;

	skel->rodata->num_cpus = bpf_num_possible_cpus();
	val = malloc(8 * bpf_num_possible_cpus());

	err = bpf_iter_bpf_percpu_hash_map__load(skel);
	if (CHECK(!skel, "bpf_iter_bpf_percpu_hash_map__load",
		  "skeleton load failed\n"))
		goto out;

	/* update map values here */
	map_fd = bpf_map__fd(skel->maps.hashmap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.hashmap1); i++) {
		key.a = i + 1;
		key.b = i + 2;
		key.c = i + 3;
		expected_key_a += key.a;
		expected_key_b += key.b;

		for (j = 0; j < bpf_num_possible_cpus(); j++) {
			*(__u32 *)(val + j * 8) = i + j;
			expected_val += i + j;
		}

		err = bpf_map_update_elem(map_fd, &key, val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_percpu_hash_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	if (CHECK(skel->bss->key_sum_a != expected_key_a,
		  "key_sum_a", "got %u expected %u\n",
		  skel->bss->key_sum_a, expected_key_a))
		goto close_iter;
	if (CHECK(skel->bss->key_sum_b != expected_key_b,
		  "key_sum_b", "got %u expected %u\n",
		  skel->bss->key_sum_b, expected_key_b))
		goto close_iter;
	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %u expected %u\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_percpu_hash_map__destroy(skel);
	free(val);
}

static void test_bpf_array_map(void)
{
	__u64 val, expected_val = 0, res_first_val, first_val = 0;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	__u32 expected_key = 0, res_first_key;
	struct bpf_iter_bpf_array_map *skel;
	union bpf_iter_link_info linfo;
	int err, i, map_fd, iter_fd;
	struct bpf_link *link;
	char buf[64] = {};
	int len, start;

	skel = bpf_iter_bpf_array_map__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_array_map__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	map_fd = bpf_map__fd(skel->maps.arraymap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.arraymap1); i++) {
		val = i + 4;
		expected_key += i;
		expected_val += val;

		if (i == 0)
			first_val = val;

		err = bpf_map_update_elem(map_fd, &i, &val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_array_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	start = 0;
	while ((len = read(iter_fd, buf + start, sizeof(buf) - start)) > 0)
		start += len;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	res_first_key = *(__u32 *)buf;
	res_first_val = *(__u64 *)(buf + sizeof(__u32));
	if (CHECK(res_first_key != 0 || res_first_val != first_val,
		  "bpf_seq_write",
		  "seq_write failure: first key %u vs expected 0, "
		  " first value %llu vs expected %llu\n",
		  res_first_key, res_first_val, first_val))
		goto close_iter;

	if (CHECK(skel->bss->key_sum != expected_key,
		  "key_sum", "got %u expected %u\n",
		  skel->bss->key_sum, expected_key))
		goto close_iter;
	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %llu expected %llu\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

	for (i = 0; i < bpf_map__max_entries(skel->maps.arraymap1); i++) {
		err = bpf_map_lookup_elem(map_fd, &i, &val);
		if (CHECK(err, "map_lookup", "map_lookup failed\n"))
			goto out;
		if (CHECK(i != val, "invalid_val",
			  "got value %llu expected %u\n", val, i))
			goto out;
	}

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_array_map__destroy(skel);
}

static void test_bpf_percpu_array_map(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_percpu_array_map *skel;
	__u32 expected_key = 0, expected_val = 0;
	union bpf_iter_link_info linfo;
	int err, i, j, map_fd, iter_fd;
	struct bpf_link *link;
	char buf[64];
	void *val;
	int len;

	skel = bpf_iter_bpf_percpu_array_map__open();
	if (CHECK(!skel, "bpf_iter_bpf_percpu_array_map__open",
		  "skeleton open failed\n"))
		return;

	skel->rodata->num_cpus = bpf_num_possible_cpus();
	val = malloc(8 * bpf_num_possible_cpus());

	err = bpf_iter_bpf_percpu_array_map__load(skel);
	if (CHECK(!skel, "bpf_iter_bpf_percpu_array_map__load",
		  "skeleton load failed\n"))
		goto out;

	/* update map values here */
	map_fd = bpf_map__fd(skel->maps.arraymap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.arraymap1); i++) {
		expected_key += i;

		for (j = 0; j < bpf_num_possible_cpus(); j++) {
			*(__u32 *)(val + j * 8) = i + j;
			expected_val += i + j;
		}

		err = bpf_map_update_elem(map_fd, &i, val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_percpu_array_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	if (CHECK(skel->bss->key_sum != expected_key,
		  "key_sum", "got %u expected %u\n",
		  skel->bss->key_sum, expected_key))
		goto close_iter;
	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %u expected %u\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_percpu_array_map__destroy(skel);
	free(val);
}

/* An iterator program deletes all local storage in a map. */
static void test_bpf_sk_storage_delete(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_sk_storage_helpers *skel;
	union bpf_iter_link_info linfo;
	int err, len, map_fd, iter_fd;
	struct bpf_link *link;
	int sock_fd = -1;
	__u32 val = 42;
	char buf[64];

	skel = bpf_iter_bpf_sk_storage_helpers__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_sk_storage_helpers__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	map_fd = bpf_map__fd(skel->maps.sk_stg_map);

	sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (CHECK(sock_fd < 0, "socket", "errno: %d\n", errno))
		goto out;
	err = bpf_map_update_elem(map_fd, &sock_fd, &val, BPF_NOEXIST);
	if (CHECK(err, "map_update", "map_update failed\n"))
		goto out;

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.delete_bpf_sk_storage_map,
					&opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	err = bpf_map_lookup_elem(map_fd, &sock_fd, &val);
	if (CHECK(!err || errno != ENOENT, "bpf_map_lookup_elem",
		  "map value wasn't deleted (err=%d, errno=%d)\n", err, errno))
		goto close_iter;

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	if (sock_fd >= 0)
		close(sock_fd);
	bpf_iter_bpf_sk_storage_helpers__destroy(skel);
}

/* This creates a socket and its local storage. It then runs a task_iter BPF
 * program that replaces the existing socket local storage with the tgid of the
 * only task owning a file descriptor to this socket, this process, prog_tests.
 * It then runs a tcp socket iterator that negates the value in the existing
 * socket local storage, the test verifies that the resulting value is -pid.
 */
static void test_bpf_sk_storage_get(void)
{
	struct bpf_iter_bpf_sk_storage_helpers *skel;
	int err, map_fd, val = -1;
	int sock_fd = -1;

	skel = bpf_iter_bpf_sk_storage_helpers__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_sk_storage_helpers__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (CHECK(sock_fd < 0, "socket", "errno: %d\n", errno))
		goto out;

	err = listen(sock_fd, 1);
	if (CHECK(err != 0, "listen", "errno: %d\n", errno))
		goto close_socket;

	map_fd = bpf_map__fd(skel->maps.sk_stg_map);

	err = bpf_map_update_elem(map_fd, &sock_fd, &val, BPF_NOEXIST);
	if (CHECK(err, "bpf_map_update_elem", "map_update_failed\n"))
		goto close_socket;

	do_dummy_read(skel->progs.fill_socket_owner);

	err = bpf_map_lookup_elem(map_fd, &sock_fd, &val);
	if (CHECK(err || val != getpid(), "bpf_map_lookup_elem",
	    "map value wasn't set correctly (expected %d, got %d, err=%d)\n",
	    getpid(), val, err))
		goto close_socket;

	do_dummy_read(skel->progs.negate_socket_local_storage);

	err = bpf_map_lookup_elem(map_fd, &sock_fd, &val);
	CHECK(err || val != -getpid(), "bpf_map_lookup_elem",
	      "map value wasn't set correctly (expected %d, got %d, err=%d)\n",
	      -getpid(), val, err);

close_socket:
	close(sock_fd);
out:
	bpf_iter_bpf_sk_storage_helpers__destroy(skel);
}

static void test_bpf_sk_storage_map(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	int err, i, len, map_fd, iter_fd, num_sockets;
	struct bpf_iter_bpf_sk_storage_map *skel;
	union bpf_iter_link_info linfo;
	int sock_fd[3] = {-1, -1, -1};
	__u32 val, expected_val = 0;
	struct bpf_link *link;
	char buf[64];

	skel = bpf_iter_bpf_sk_storage_map__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_sk_storage_map__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	map_fd = bpf_map__fd(skel->maps.sk_stg_map);
	num_sockets = ARRAY_SIZE(sock_fd);
	for (i = 0; i < num_sockets; i++) {
		sock_fd[i] = socket(AF_INET6, SOCK_STREAM, 0);
		if (CHECK(sock_fd[i] < 0, "socket", "errno: %d\n", errno))
			goto out;

		val = i + 1;
		expected_val += val;

		err = bpf_map_update_elem(map_fd, &sock_fd[i], &val,
					  BPF_NOEXIST);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_sk_storage_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	if (CHECK(skel->bss->ipv6_sk_count != num_sockets,
		  "ipv6_sk_count", "got %u expected %u\n",
		  skel->bss->ipv6_sk_count, num_sockets))
		goto close_iter;

	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %u expected %u\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	for (i = 0; i < num_sockets; i++) {
		if (sock_fd[i] >= 0)
			close(sock_fd[i]);
	}
	bpf_iter_bpf_sk_storage_map__destroy(skel);
}

static void test_rdonly_buf_out_of_bound(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_test_kern5 *skel;
	union bpf_iter_link_info linfo;
	struct bpf_link *link;

	skel = bpf_iter_test_kern5__open_and_load();
	if (CHECK(!skel, "bpf_iter_test_kern5__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = bpf_map__fd(skel->maps.hashmap1);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		bpf_link__destroy(link);

	bpf_iter_test_kern5__destroy(skel);
}

static void test_buf_neg_offset(void)
{
	struct bpf_iter_test_kern6 *skel;

	skel = bpf_iter_test_kern6__open_and_load();
	if (CHECK(skel, "bpf_iter_test_kern6__open_and_load",
		  "skeleton open_and_load unexpected success\n"))
		bpf_iter_test_kern6__destroy(skel);
}

#define CMP_BUFFER_SIZE 1024
static char task_vma_output[CMP_BUFFER_SIZE];
static char proc_maps_output[CMP_BUFFER_SIZE];

/* remove \0 and \t from str, and only keep the first line */
static void str_strip_first_line(char *str)
{
	char *dst = str, *src = str;

	do {
		if (*src == ' ' || *src == '\t')
			src++;
		else
			*(dst++) = *(src++);

	} while (*src != '\0' && *src != '\n');

	*dst = '\0';
}

#define min(a, b) ((a) < (b) ? (a) : (b))

static void test_task_vma(void)
{
	int err, iter_fd = -1, proc_maps_fd = -1;
	struct bpf_iter_task_vma *skel;
	int len, read_size = 4;
	char maps_path[64];

	skel = bpf_iter_task_vma__open();
	if (CHECK(!skel, "bpf_iter_task_vma__open", "skeleton open failed\n"))
		return;

	skel->bss->pid = getpid();

	err = bpf_iter_task_vma__load(skel);
	if (CHECK(err, "bpf_iter_task_vma__load", "skeleton load failed\n"))
		goto out;

	skel->links.proc_maps = bpf_program__attach_iter(
		skel->progs.proc_maps, NULL);

	if (!ASSERT_OK_PTR(skel->links.proc_maps, "bpf_program__attach_iter")) {
		skel->links.proc_maps = NULL;
		goto out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.proc_maps));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto out;

	/* Read CMP_BUFFER_SIZE (1kB) from bpf_iter. Read in small chunks
	 * to trigger seq_file corner cases. The expected output is much
	 * longer than 1kB, so the while loop will terminate.
	 */
	len = 0;
	while (len < CMP_BUFFER_SIZE) {
		err = read_fd_into_buffer(iter_fd, task_vma_output + len,
					  min(read_size, CMP_BUFFER_SIZE - len));
		if (CHECK(err < 0, "read_iter_fd", "read_iter_fd failed\n"))
			goto out;
		len += err;
	}

	/* read CMP_BUFFER_SIZE (1kB) from /proc/pid/maps */
	snprintf(maps_path, 64, "/proc/%u/maps", skel->bss->pid);
	proc_maps_fd = open(maps_path, O_RDONLY);
	if (CHECK(proc_maps_fd < 0, "open_proc_maps", "open_proc_maps failed\n"))
		goto out;
	err = read_fd_into_buffer(proc_maps_fd, proc_maps_output, CMP_BUFFER_SIZE);
	if (CHECK(err < 0, "read_prog_maps_fd", "read_prog_maps_fd failed\n"))
		goto out;

	/* strip and compare the first line of the two files */
	str_strip_first_line(task_vma_output);
	str_strip_first_line(proc_maps_output);

	CHECK(strcmp(task_vma_output, proc_maps_output), "compare_output",
	      "found mismatch\n");
out:
	close(proc_maps_fd);
	close(iter_fd);
	bpf_iter_task_vma__destroy(skel);
}

static int sys_io_uring_setup(u32 entries, struct io_uring_params *p)
{
	return syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_register_bufs(int io_uring_fd, struct iovec *iovs, unsigned int nr)
{
	return syscall(__NR_io_uring_register, io_uring_fd,
		       IORING_REGISTER_BUFFERS, iovs, nr);
}

static int io_uring_register_files(int io_uring_fd, int *fds, unsigned int nr)
{
	return syscall(__NR_io_uring_register, io_uring_fd,
		       IORING_REGISTER_FILES, fds, nr);
}

static unsigned long long page_addr_to_pfn(unsigned long addr)
{
	int page_size = sysconf(_SC_PAGE_SIZE), fd, ret;
	unsigned long long pfn;

	if (page_size < 0)
		return 0;
	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return 0;

	ret = pread(fd, &pfn, sizeof(pfn), (addr / page_size) * 8);
	close(fd);
	if (ret < 0)
		return 0;
	/* Bits 0-54 have PFN for non-swapped page */
	return pfn & 0x7fffffffffffff;
}

void test_io_uring_buf(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	char rbuf[4096], buf[4096] = "B\n";
	union bpf_iter_link_info linfo;
	struct bpf_iter_io_uring *skel;
	int ret, fd, i, len = 128;
	struct io_uring_params p;
	struct iovec iovs[8];
	int iter_fd;
	char *str;

	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	skel = bpf_iter_io_uring__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_io_uring__open_and_load"))
		return;

	for (i = 0; i < ARRAY_SIZE(iovs); i++) {
		iovs[i].iov_len	 = len;
		iovs[i].iov_base = mmap(NULL, len, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_SHARED, -1, 0);
		if (iovs[i].iov_base == MAP_FAILED)
			goto end;
		len *= 2;
	}

	memset(&p, 0, sizeof(p));
	fd = sys_io_uring_setup(1, &p);
	if (!ASSERT_GE(fd, 0, "io_uring_setup"))
		goto end;

	linfo.io_uring.io_uring_fd = fd;
	skel->links.dump_io_uring_buf = bpf_program__attach_iter(skel->progs.dump_io_uring_buf,
								 &opts);
	if (!ASSERT_OK_PTR(skel->links.dump_io_uring_buf, "bpf_program__attach_iter"))
		goto end_close_fd;

	ret = io_uring_register_bufs(fd, iovs, ARRAY_SIZE(iovs));
	if (!ASSERT_OK(ret, "io_uring_register_bufs"))
		goto end_close_fd;

	/* "B\n" */
	len = 2;
	str = buf + len;
	for (int j = 0; j < ARRAY_SIZE(iovs); j++) {
		ret = snprintf(str, sizeof(buf) - len, "%d:0x%lx:%zu\n", j,
			       (unsigned long)iovs[j].iov_base,
			       iovs[j].iov_len);
		if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf) - len, "snprintf"))
			goto end_close_fd;
		len += ret;
		str += ret;

		ret = snprintf(str, sizeof(buf) - len, "`-PFN for bvec[0]=%llu\n",
			       page_addr_to_pfn((unsigned long)iovs[j].iov_base));
		if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf) - len, "snprintf"))
			goto end_close_fd;
		len += ret;
		str += ret;
	}

	ret = snprintf(str, sizeof(buf) - len, "E:%zu\n", ARRAY_SIZE(iovs));
	if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf) - len, "snprintf"))
		goto end_close_fd;

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.dump_io_uring_buf));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto end_close_fd;

	ret = read_fd_into_buffer(iter_fd, rbuf, sizeof(rbuf));
	if (!ASSERT_GT(ret, 0, "read_fd_into_buffer"))
		goto end_close_iter;

	ASSERT_OK(strcmp(rbuf, buf), "compare iterator output");

	puts("=== Expected Output ===");
	printf("%s", buf);
	puts("==== Actual Output ====");
	printf("%s", rbuf);
	puts("=======================");

end_close_iter:
	close(iter_fd);
end_close_fd:
	close(fd);
end:
	while (i--)
		munmap(iovs[i].iov_base, iovs[i].iov_len);
	bpf_iter_io_uring__destroy(skel);
}

void test_io_uring_file(void)
{
	int reg_files[] = { [0 ... 7] = -1 };
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	char buf[4096] = "B\n", rbuf[4096] = {}, *str;
	union bpf_iter_link_info linfo = {};
	struct bpf_iter_io_uring *skel;
	int iter_fd, fd, len = 0, ret;
	struct io_uring_params p;

	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	skel = bpf_iter_io_uring__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_io_uring__open_and_load"))
		return;

	/* "B\n" */
	len = 2;
	str = buf + len;
	ret = snprintf(str, sizeof(buf) - len, "B\n");
	for (int i = 0; i < ARRAY_SIZE(reg_files); i++) {
		char templ[] = "/tmp/io_uringXXXXXX";
		const char *name, *def = "<none>";

		/* create sparse set */
		if (i & 1) {
			name = def;
		} else {
			reg_files[i] = mkstemp(templ);
			if (!ASSERT_GE(reg_files[i], 0, templ))
				goto end_close_reg_files;
			name = templ;
			ASSERT_OK(unlink(name), "unlink");
		}
		ret = snprintf(str, sizeof(buf) - len, "%d:%s%s\n", i, name, name != def ? " (deleted)" : "");
		if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf) - len, "snprintf"))
			goto end_close_reg_files;
		len += ret;
		str += ret;
	}

	ret = snprintf(str, sizeof(buf) - len, "E:%zu\n", ARRAY_SIZE(reg_files));
	if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf) - len, "snprintf"))
		goto end_close_reg_files;

	memset(&p, 0, sizeof(p));
	fd = sys_io_uring_setup(1, &p);
	if (!ASSERT_GE(fd, 0, "io_uring_setup"))
		goto end_close_reg_files;

	linfo.io_uring.io_uring_fd = fd;
	skel->links.dump_io_uring_file = bpf_program__attach_iter(skel->progs.dump_io_uring_file,
								  &opts);
	if (!ASSERT_OK_PTR(skel->links.dump_io_uring_file, "bpf_program__attach_iter"))
		goto end_close_fd;

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.dump_io_uring_file));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto end;

	ret = io_uring_register_files(fd, reg_files, ARRAY_SIZE(reg_files));
	if (!ASSERT_OK(ret, "io_uring_register_files"))
		goto end_iter_fd;

	ret = read_fd_into_buffer(iter_fd, rbuf, sizeof(rbuf));
	if (!ASSERT_GT(ret, 0, "read_fd_into_buffer(iterator_fd, buf)"))
		goto end_iter_fd;

	ASSERT_OK(strcmp(rbuf, buf), "compare iterator output");

	puts("=== Expected Output ===");
	printf("%s", buf);
	puts("==== Actual Output ====");
	printf("%s", rbuf);
	puts("=======================");
end_iter_fd:
	close(iter_fd);
end_close_fd:
	close(fd);
end_close_reg_files:
	for (int i = 0; i < ARRAY_SIZE(reg_files); i++) {
		if (reg_files[i] != -1)
			close(reg_files[i]);
	}
end:
	bpf_iter_io_uring__destroy(skel);
}

void test_epoll(void)
{
	const char *fmt = "B\npipe:%d\nsocket:%d\npipe:%d\nsocket:%d\nE\n";
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	char buf[4096] = {}, rbuf[4096] = {};
	union bpf_iter_link_info linfo;
	int fds[2], sk[2], epfd, ret;
	struct bpf_iter_epoll *skel;
	struct epoll_event ev = {};
	int iter_fd, set[4];
	char *s, *t;

	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	skel = bpf_iter_epoll__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_epoll__open_and_load"))
		return;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (!ASSERT_GE(epfd, 0, "epoll_create1"))
		goto end;

	ret = pipe(fds);
	if (!ASSERT_OK(ret, "pipe(fds)"))
		goto end_epfd;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sk);
	if (!ASSERT_OK(ret, "socketpair"))
		goto end_pipe;

	ev.events = EPOLLIN;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fds[0], &ev);
	if (!ASSERT_OK(ret, "epoll_ctl"))
		goto end_sk;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sk[0], &ev);
	if (!ASSERT_OK(ret, "epoll_ctl"))
		goto end_sk;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fds[1], &ev);
	if (!ASSERT_OK(ret, "epoll_ctl"))
		goto end_sk;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sk[1], &ev);
	if (!ASSERT_OK(ret, "epoll_ctl"))
		goto end_sk;

	linfo.epoll.epoll_fd = epfd;
	skel->links.dump_epoll = bpf_program__attach_iter(skel->progs.dump_epoll, &opts);
	if (!ASSERT_OK_PTR(skel->links.dump_epoll, "bpf_program__attach_iter"))
		goto end_sk;

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.dump_epoll));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto end_sk;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, iter_fd, &ev);
	if (!ASSERT_EQ(ret, -1, "epoll_ctl add for iter_fd"))
		goto end_iter_fd;

	ret = snprintf(buf, sizeof(buf), fmt, fds[0], sk[0], fds[1], sk[1]);
	if (!ASSERT_GE(ret, 0, "snprintf") || !ASSERT_LT(ret, sizeof(buf), "snprintf"))
		goto end_iter_fd;

	ret = read_fd_into_buffer(iter_fd, rbuf, sizeof(rbuf));
	if (!ASSERT_GT(ret, 0, "read_fd_into_buffer"))
		goto end_iter_fd;

	puts("=== Expected Output ===");
	printf("%s", buf);
	puts("==== Actual Output ====");
	printf("%s", rbuf);
	puts("=======================");

	s = rbuf;
	while ((s = strtok_r(s, "\n", &t))) {
		int fd = -1;

		if (s[0] == 'B' || s[0] == 'E')
			goto next;
		ASSERT_EQ(sscanf(s, s[0] == 'p' ? "pipe:%d" : "socket:%d", &fd), 1, s);
		if (fd == fds[0]) {
			ASSERT_NEQ(set[0], 1, "pipe[0]");
			set[0] = 1;
		} else if (fd == fds[1]) {
			ASSERT_NEQ(set[1], 1, "pipe[1]");
			set[1] = 1;
		} else if (fd == sk[0]) {
			ASSERT_NEQ(set[2], 1, "sk[0]");
			set[2] = 1;
		} else if (fd == sk[1]) {
			ASSERT_NEQ(set[3], 1, "sk[1]");
			set[3] = 1;
		} else {
			ASSERT_TRUE(0, "Incorrect fd in iterator output");
		}
next:
		s = NULL;
	}
	for (int i = 0; i < ARRAY_SIZE(set); i++)
		ASSERT_EQ(set[i], 1, "fd found");
end_iter_fd:
	close(iter_fd);
end_sk:
	close(sk[1]);
	close(sk[0]);
end_pipe:
	close(fds[1]);
	close(fds[0]);
end_epfd:
	close(epfd);
end:
	bpf_iter_epoll__destroy(skel);
}

void test_bpf_iter(void)
{
	if (test__start_subtest("btf_id_or_null"))
		test_btf_id_or_null();
	if (test__start_subtest("ipv6_route"))
		test_ipv6_route();
	if (test__start_subtest("netlink"))
		test_netlink();
	if (test__start_subtest("bpf_map"))
		test_bpf_map();
	if (test__start_subtest("task"))
		test_task();
	if (test__start_subtest("task_stack"))
		test_task_stack();
	if (test__start_subtest("task_file"))
		test_task_file();
	if (test__start_subtest("task_vma"))
		test_task_vma();
	if (test__start_subtest("task_btf"))
		test_task_btf();
	if (test__start_subtest("tcp4"))
		test_tcp4();
	if (test__start_subtest("tcp6"))
		test_tcp6();
	if (test__start_subtest("udp4"))
		test_udp4();
	if (test__start_subtest("udp6"))
		test_udp6();
	if (test__start_subtest("unix"))
		test_unix();
	if (test__start_subtest("anon"))
		test_anon_iter(false);
	if (test__start_subtest("anon-read-one-char"))
		test_anon_iter(true);
	if (test__start_subtest("file"))
		test_file_iter();
	if (test__start_subtest("overflow"))
		test_overflow(false, false);
	if (test__start_subtest("overflow-e2big"))
		test_overflow(true, false);
	if (test__start_subtest("prog-ret-1"))
		test_overflow(false, true);
	if (test__start_subtest("bpf_hash_map"))
		test_bpf_hash_map();
	if (test__start_subtest("bpf_percpu_hash_map"))
		test_bpf_percpu_hash_map();
	if (test__start_subtest("bpf_array_map"))
		test_bpf_array_map();
	if (test__start_subtest("bpf_percpu_array_map"))
		test_bpf_percpu_array_map();
	if (test__start_subtest("bpf_sk_storage_map"))
		test_bpf_sk_storage_map();
	if (test__start_subtest("bpf_sk_storage_delete"))
		test_bpf_sk_storage_delete();
	if (test__start_subtest("bpf_sk_storage_get"))
		test_bpf_sk_storage_get();
	if (test__start_subtest("rdonly-buf-out-of-bound"))
		test_rdonly_buf_out_of_bound();
	if (test__start_subtest("buf-neg-offset"))
		test_buf_neg_offset();
	if (test__start_subtest("io_uring_buf"))
		test_io_uring_buf();
	if (test__start_subtest("io_uring_file"))
		test_io_uring_file();
	if (test__start_subtest("epoll"))
		test_epoll();
}
