// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include "task_local_storage_helpers.h"

/* The same as in progs/local_storage_inline.c */
#define LS_VAL_WORDS	4
#define NR_MAPS		4

struct ls_val {
	__u64 w[LS_VAL_WORDS];
};

#include "local_storage_inline.skel.h"

#ifndef PIDFD_THREAD
#define PIDFD_THREAD	O_EXCL
#endif

#define INLINE_FLAGS	(BPF_F_NO_PREALLOC | BPF_F_INLINE_VALUE)
/* All inline maps of one owner type share an area that ends at 1 KB */
#define AREA_END	1024
#define MAX_INLINE_MAPS	16
#define NR_SOCKS	2
/*
 * Map free is deferred: the slot of a closed map can stay taken for a time.
 * All waits share one time budget, so that the test fails fast after the
 * first timeout.
 */
#define WAIT_BUDGET_NS	(30ULL * 1000 * 1000 * 1000)
#define WAIT_US		10000

static __u64 wait_end;

/* Sleep a little and return true, or return false if the budget is spent */
static bool wait_more(void)
{
	if (get_time_ns() >= wait_end)
		return false;
	usleep(WAIT_US);
	return true;
}

/* A create that must fail with err. Close the map if it worked */
static void assert_err(int fd, int err, const char *name)
{
	if (!ASSERT_EQ(fd, err, name) && fd >= 0)
		close(fd);
}

/* A create that must work. The test needs only the result */
static void assert_fd_close(int fd, const char *name)
{
	if (ASSERT_OK_FD(fd, name))
		close(fd);
}

static void close_fds(const int *fds, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

struct socks {
	int fd[NR_SOCKS];
	bool ok;	/* All sockets are open */
};

static struct socks open_socks(void)
{
	struct socks s = { .ok = true };
	int i;

	for (i = 0; i < NR_SOCKS; i++) {
		s.fd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (!ASSERT_OK_FD(s.fd[i], "socket"))
			s.ok = false;
	}
	return s;
}

/* BTF with an int key (id 1) and, as the last type, a value of value_size bytes */
static struct btf *load_btf(__u32 value_size)
{
	struct btf *btf;

	btf = btf__new_empty();
	if (!btf)
		return NULL;
	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	btf__add_int(btf, "char", 1, 0);
	btf__add_array(btf, 1, 2, value_size);
	if (btf__load_into_kernel(btf)) {
		btf__free(btf);
		return NULL;
	}
	return btf;
}

static int map_create_btf(struct btf *btf, enum bpf_map_type type, __u32 flags,
			  __u32 value_size)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = flags,
		    .btf_fd = btf__fd(btf), .btf_key_type_id = 1,
		    .btf_value_type_id = btf__type_cnt(btf) - 1);

	return bpf_map_create(type, "ls_inline", sizeof(int), value_size, 0, &opts);
}

/* Make a local storage map with an int key */
static int create_map(enum bpf_map_type type, __u32 flags, __u32 value_size)
{
	struct btf *btf = load_btf(value_size);
	int fd;

	if (!ASSERT_OK_PTR(btf, "load_btf"))
		return -ENOMEM;
	fd = map_create_btf(btf, type, flags, value_size);
	btf__free(btf);
	return fd;
}

/* An inline map. Retry while the slots of closed maps are not free */
static int create_inline(enum bpf_map_type type, __u32 value_size)
{
	struct btf *btf = load_btf(value_size);
	int fd;

	if (!ASSERT_OK_PTR(btf, "load_btf"))
		return -ENOMEM;
	do {
		fd = map_create_btf(btf, type, INLINE_FLAGS, value_size);
	} while (fd == -ENOSPC && wait_more());
	btf__free(btf);
	return fd;
}

/*
 * The largest inline value. The area starts after struct bpf_local_storage,
 * aligned to 8 B. A slot is an 8 B tag and the value, aligned to 8 B.
 */
static int read_value_max(void)
{
	const struct btf_type *t;
	struct btf *btf;
	int id, max = -1;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return -1;
	id = btf__find_by_name_kind(btf, "bpf_local_storage", BTF_KIND_STRUCT);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		max = AREA_END - (t->size + 7) / 8 * 8 - 8;
	}
	btf__free(btf);
	return max;
}

static void fill_val(struct ls_val *v, __u64 first)
{
	int i;

	for (i = 0; i < LS_VAL_WORDS; i++)
		v->w[i] = first + i;
}

/* Run the program on sk and on the current task. Return the number of NULL gets */
static int run_prog(struct local_storage_inline *skel, int sk, __u64 get_flags)
{
	socklen_t len = sizeof(int);
	int ttl;

	skel->bss->get_flags = get_flags;
	skel->bss->nr_null = 0;
	ASSERT_OK(getsockopt(sk, SOL_IP, IP_TTL, &ttl, &len), "getsockopt");
	return skel->bss->nr_null;
}

/* The value that get i saw is in the storage object of its owner: a slot */
static bool in_obj(struct local_storage_inline *skel, int i)
{
	__u64 off = skel->bss->val_addr[i] - skel->bss->obj_addr[i];

	return skel->bss->obj_addr[i] && off < skel->bss->obj_size[i];
}

/* The program and the syscall must see the same value */
static void check_values(struct local_storage_inline *skel, const int *fds,
			 const int *keys, const struct ls_val *v)
{
	struct ls_val out;
	int i;

	for (i = 0; i < NR_MAPS; i++) {
		ASSERT_OK(memcmp(&skel->bss->seen_val[i], v, sizeof(*v)), "seen");
		ASSERT_OK(bpf_map_lookup_elem(fds[i], &keys[i], &out), "lookup");
		ASSERT_OK(memcmp(&out, v, sizeof(*v)), "lookup value");
	}
}

enum { OP_UPDATE, OP_DELETE, OP_LOOKUP };

/* All maps get the same ops: an inline map must give the codes of a normal map */
static void check_ops(int fd, int key)
{
	static const struct {
		int op;
		__u64 flags;
		int ret;
	} ops[] = {
		{ OP_DELETE, 0, 0 },
		{ OP_DELETE, 0, -ENOENT },
		{ OP_LOOKUP, 0, -ENOENT },
		{ OP_UPDATE, BPF_EXIST, -ENOENT },
		{ OP_UPDATE, BPF_NOEXIST, 0 },
		{ OP_UPDATE, BPF_NOEXIST, -EEXIST },
		{ OP_UPDATE, BPF_F_LOCK, -EINVAL },
		{ OP_UPDATE, BPF_ANY, 0 },
		{ OP_DELETE, 0, 0 },
		{ OP_UPDATE, BPF_ANY, 0 },
		{ OP_UPDATE, BPF_EXIST, 0 },
		{ OP_LOOKUP, 0, 0 },
	};
	struct ls_val v, out;
	char name[16];
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		fill_val(&v, 0x4000 + i * 0x10);
		if (ops[i].op == OP_UPDATE)
			ret = bpf_map_update_elem(fd, &key, &v, ops[i].flags);
		else if (ops[i].op == OP_DELETE)
			ret = bpf_map_delete_elem(fd, &key);
		else
			ret = bpf_map_lookup_elem(fd, &key, &out);
		snprintf(name, sizeof(name), "op %d", i);
		ASSERT_EQ(ret, ops[i].ret, name);
	}
	/* The last op reads the value of the update before it */
	fill_val(&v, 0x4000 + (i - 2) * 0x10);
	ASSERT_OK(memcmp(&out, &v, sizeof(v)), "last value");
}

/* Runs in a new thread: the task is the owner of the task values */
static void test_values(int max)
{
	struct local_storage_inline *skel;
	int fds[NR_MAPS], keys[NR_MAPS], i, j, sk = -1, pidfd = -1;
	struct ls_val v, zero = {};

	skel = local_storage_inline__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;
	bpf_map__set_map_flags(skel->maps.sk_inline, INLINE_FLAGS);
	bpf_map__set_map_flags(skel->maps.task_inline, INLINE_FLAGS);
	if (!ASSERT_OK(local_storage_inline__load(skel), "skel load") ||
	    !ASSERT_OK(local_storage_inline__attach(skel), "attach"))
		goto out;
	sk = socket(AF_INET, SOCK_STREAM, 0);
	pidfd = sys_pidfd_open(sys_gettid(), PIDFD_THREAD);
	if (!ASSERT_OK_FD(sk, "socket") || !ASSERT_OK_FD(pidfd, "pidfd"))
		goto out;

	/* The order of the maps in the program */
	fds[0] = bpf_map__fd(skel->maps.sk_inline);
	fds[1] = bpf_map__fd(skel->maps.sk_normal);
	fds[2] = bpf_map__fd(skel->maps.task_inline);
	fds[3] = bpf_map__fd(skel->maps.task_normal);
	for (i = 0; i < NR_MAPS; i++)
		keys[i] = i < 2 ? sk : pidfd;
	skel->bss->target_tid = sys_gettid();

	fill_val(&skel->bss->init_val, 0x1000);
	skel->bss->use_init = true;
	ASSERT_EQ(run_prog(skel, sk, BPF_LOCAL_STORAGE_GET_F_CREATE), 0,
		  "create with init");
	check_values(skel, fds, keys, &skel->bss->init_val);
	/* The program finds inline values in a slot, normal values elsewhere */
	for (i = 0; i < NR_MAPS; i++)
		ASSERT_EQ(in_obj(skel, i), !(i & 1), "value in object");

	fill_val(&v, 0x2000);
	for (i = 0; i < NR_MAPS; i++)
		ASSERT_OK(bpf_map_update_elem(fds[i], &keys[i], &v, BPF_EXIST), "update");
	skel->bss->val_add = 0x100;
	ASSERT_EQ(run_prog(skel, sk, 0), 0, "get");
	fill_val(&v, 0x2100);
	check_values(skel, fds, keys, &v);

	/* A slot keeps its bytes after a delete, but they must not show */
	for (i = 0; i < NR_MAPS; i++)
		ASSERT_OK(bpf_map_delete_elem(fds[i], &keys[i]), "delete");
	ASSERT_EQ(run_prog(skel, sk, 0), NR_MAPS, "get after delete");
	skel->bss->use_init = false;
	skel->bss->val_add = 0;
	ASSERT_EQ(run_prog(skel, sk, BPF_LOCAL_STORAGE_GET_F_CREATE), 0, "create");
	check_values(skel, fds, keys, &zero);

	/* A delete in the program must give the codes of a normal map too */
	skel->bss->do_delete = true;
	for (i = 0; i < 2; i++) {
		run_prog(skel, sk, 0);
		for (j = 0; j < NR_MAPS; j++)
			ASSERT_EQ(skel->bss->del_ret[j], i ? -ENOENT : 0, "prog delete");
	}
	skel->bss->do_delete = false;
	ASSERT_EQ(run_prog(skel, sk, BPF_LOCAL_STORAGE_GET_F_CREATE), 0, "create again");

	skel->bss->target_tid = 0;
	for (i = 0; i < NR_MAPS; i++)
		check_ops(fds[i], keys[i]);
out:
	if (sk >= 0)
		close(sk);
	if (pidfd >= 0)
		close(pidfd);
	local_storage_inline__destroy(skel);
}

/*
 * A value that never fits gets -E2BIG at once, with no retry. The biggest
 * value takes the full area: retry until the maps of earlier subtests are
 * freed.
 */
static void check_biggest(int max)
{
	int big;

	assert_err(create_map(BPF_MAP_TYPE_TASK_STORAGE, INLINE_FLAGS, max + 1),
		   -E2BIG, "value too big");
	big = create_inline(BPF_MAP_TYPE_TASK_STORAGE, max);
	if (!ASSERT_OK_FD(big, "biggest value"))
		return;
	/* No room now: the biggest value takes the full area */
	assert_err(create_map(BPF_MAP_TYPE_TASK_STORAGE, INLINE_FLAGS, 8),
		   -ENOSPC, "no room now");
	close(big);
	assert_fd_close(create_inline(BPF_MAP_TYPE_TASK_STORAGE, 8), "room after free");
}

static const char excl_hash[32];

/* A create that fails after the slot claim gives the slot back */
static void check_claim_undo(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = INLINE_FLAGS,
		    .btf_key_type_id = 1, .excl_prog_hash = excl_hash,
		    .excl_prog_hash_size = 1);
	struct btf *btf = load_btf(8);
	int i, fd = -EINVAL;

	if (!ASSERT_OK_PTR(btf, "load_btf"))
		return;
	opts.btf_fd = btf__fd(btf);
	opts.btf_value_type_id = btf__type_cnt(btf) - 1;
	/* More failures than table entries: each must give its entry back */
	for (i = 0; i <= MAX_INLINE_MAPS && fd == -EINVAL; i++)
		fd = bpf_map_create(BPF_MAP_TYPE_TASK_STORAGE, "ls_inline",
				    sizeof(int), 8, 0, &opts);
	assert_err(fd, -EINVAL, "bad excl_prog_hash_size");
	btf__free(btf);
}

/* libbpf gives the error of the kernel, not -EINVAL of a retry without BTF */
static void check_load_err(int max)
{
	struct local_storage_inline *skel;
	int err;

	skel = local_storage_inline__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;
	bpf_map__set_map_flags(skel->maps.task_inline, INLINE_FLAGS);
	bpf_map__set_value_size(skel->maps.task_inline, max + 1);
	err = local_storage_inline__load(skel);
	ASSERT_EQ(err, -E2BIG, "skeleton load");
	local_storage_inline__destroy(skel);
}

static void test_limits(int max)
{
	int fds[MAX_INLINE_MAPS], i;

	check_biggest(max);
	check_load_err(max);

	for (i = 0; i < MAX_INLINE_MAPS; i++) {
		fds[i] = create_inline(BPF_MAP_TYPE_TASK_STORAGE, 8);
		if (!ASSERT_OK_FD(fds[i], "inline map"))
			break;
		/* The first map proves room: the failed creates need no retry */
		if (!i)
			check_claim_undo();
	}
	if (i == MAX_INLINE_MAPS) {
		/* The area has room, but the owner type has 16 inline maps */
		assert_err(create_map(BPF_MAP_TYPE_TASK_STORAGE, INLINE_FLAGS, 8),
			   -ENOSPC, "too many maps");
		/* Each owner type has its own limit */
		assert_fd_close(create_inline(BPF_MAP_TYPE_SK_STORAGE, 8),
				"other owner type");
	}
	close_fds(fds, i);
}

/* Load the program with map_fd in place of sk_reuse, and attach it */
static struct local_storage_inline *load_reuse(int map_fd)
{
	struct local_storage_inline *skel;

	skel = local_storage_inline__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return NULL;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.sk_reuse, map_fd), "reuse_fd") ||
	    !ASSERT_OK(local_storage_inline__load(skel), "skel load") ||
	    !ASSERT_OK(local_storage_inline__attach(skel), "attach")) {
		local_storage_inline__destroy(skel);
		return NULL;
	}
	skel->bss->target_tid = sys_gettid();
	skel->bss->reuse_test = true;
	return skel;
}

static void test_fallback(int max)
{
	struct socks s = open_socks();
	struct local_storage_inline *skel;
	int normal, map = -1, i;
	char val[AREA_END], out[AREA_END];

	normal = create_map(BPF_MAP_TYPE_SK_STORAGE, BPF_F_NO_PREALLOC, 4);
	if (!s.ok || !ASSERT_OK_FD(normal, "normal map"))
		goto out;

	/* sk 0 gets its storage before the inline map exists, sk 1 after */
	ASSERT_OK(bpf_map_update_elem(normal, &s.fd[0], &s.fd[0], 0), "normal update");
	/* The slot takes the full area, so the storage of sk 0 has no room */
	map = create_inline(BPF_MAP_TYPE_SK_STORAGE, max);
	if (!ASSERT_OK_FD(map, "inline map"))
		goto out;

	for (i = 0; i < 2; i++) {
		memset(val, 0x5a + i, max);
		ASSERT_OK(bpf_map_update_elem(map, &s.fd[i], val, BPF_NOEXIST), "update");
	}
	/* sk 0 keeps the value in a normal element, sk 1 in the slot */
	skel = load_reuse(map);
	for (i = 0; skel && i < 2; i++) {
		ASSERT_EQ(run_prog(skel, s.fd[i], 0), 0, "prog get");
		ASSERT_EQ(in_obj(skel, 0), i, "value in object");
	}
	local_storage_inline__destroy(skel);
	for (i = 0; i < 2; i++) {
		memset(val, 0x5a + i, max);
		ASSERT_OK(bpf_map_lookup_elem(map, &s.fd[i], out), "lookup");
		ASSERT_OK(memcmp(out, val, max), "lookup value");
		ASSERT_OK(bpf_map_delete_elem(map, &s.fd[i]), "delete");
	}
	ASSERT_OK(bpf_map_lookup_elem(normal, &s.fd[0], out), "normal lookup");
	ASSERT_EQ(*(int *)out, s.fd[0], "normal value");
out:
	close_fds(s.fd, NR_SOCKS);
	if (normal >= 0)
		close(normal);
	if (map >= 0)
		close(map);
}

/*
 * Map B gets the slot of the freed map A in a live object. The old tag and
 * value bytes of A must not show as a value of B.
 */
static void test_reuse(int max)
{
	struct local_storage_inline *skel = NULL;
	struct socks s = open_socks();
	int a, b = -1, i;
	char val[AREA_END], out[AREA_END];
	struct ls_val zero = {};

	if (!s.ok)
		goto out;
	/* The biggest value: the slot of A and of B starts at the area start */
	a = create_inline(BPF_MAP_TYPE_SK_STORAGE, max);
	if (!ASSERT_OK_FD(a, "map A"))
		goto out;
	memset(val, 0x5a, max);
	for (i = 0; i < 2; i++)
		ASSERT_OK(bpf_map_update_elem(a, &s.fd[i], val, BPF_NOEXIST), "update A");
	close(a);

	/* B gets room only after the deferred free of A, with a new tag */
	b = create_inline(BPF_MAP_TYPE_SK_STORAGE, max);
	if (!ASSERT_OK_FD(b, "map B"))
		goto out;
	for (i = 0; i < 2; i++)
		ASSERT_EQ(bpf_map_lookup_elem(b, &s.fd[i], out), -ENOENT, "lookup B");

	memset(val, 0xa5, max);
	ASSERT_OK(bpf_map_update_elem(b, &s.fd[0], val, BPF_NOEXIST), "syscall create");
	ASSERT_OK(bpf_map_lookup_elem(b, &s.fd[0], out), "lookup syscall value");
	ASSERT_OK(memcmp(out, val, max), "syscall value");

	skel = load_reuse(b);
	if (!skel)
		goto out;
	ASSERT_EQ(run_prog(skel, s.fd[1], BPF_LOCAL_STORAGE_GET_F_CREATE), 0,
		  "prog create");
	ASSERT_OK(memcmp(&skel->bss->seen_val[0], &zero, sizeof(zero)), "prog value");
	memset(val, 0, max);
	ASSERT_OK(bpf_map_lookup_elem(b, &s.fd[1], out), "lookup prog value");
	ASSERT_OK(memcmp(out, val, max), "prog value zero");
out:
	local_storage_inline__destroy(skel);
	close_fds(s.fd, NR_SOCKS);
	if (b >= 0)
		close(b);
}

struct subtest {
	const char *name;
	void (*fn)(int max);
	bool thread;	/* Task storage: a new task has a new storage object */
};

struct thread_arg {
	const struct subtest *t;
	int max;
};

static void *subtest_thread(void *arg)
{
	struct thread_arg *a = arg;

	a->t->fn(a->max);
	return NULL;
}

static void run_subtest(const struct subtest *t, int max)
{
	struct thread_arg a = { t, max };
	pthread_t thread;

	if (!t->thread) {
		t->fn(max);
		return;
	}
	if (ASSERT_OK(pthread_create(&thread, NULL, subtest_thread, &a), "pthread_create"))
		pthread_join(thread, NULL);
}

/* Serial: all inline maps of an owner type share one area and one limit */
void serial_test_local_storage_inline(void)
{
	static const struct subtest tests[] = {
		{ "values", test_values, true },
		{ "limits", test_limits },
		{ "fallback", test_fallback },
		{ "reuse", test_reuse },
	};
	__u64 start;
	int fd, i, max;

	wait_end = get_time_ns() + WAIT_BUDGET_NS;
	assert_fd_close(create_map(BPF_MAP_TYPE_SK_STORAGE, BPF_F_NO_PREALLOC, 8),
			"normal map");
	/* 32-bit kernels refuse the flag */
	fd = create_inline(BPF_MAP_TYPE_SK_STORAGE, 8);
	if (fd == -EOPNOTSUPP) {
		test__skip();
		return;
	}
	assert_fd_close(fd, "inline map");
	max = read_value_max();
	if (!ASSERT_GT(max, 0, "inline value max"))
		return;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!test__start_subtest(tests[i].name))
			continue;
		start = get_time_ns();
		run_subtest(&tests[i], max);
		printf("subtest time: %s %llu ms\n", tests[i].name,
		       (get_time_ns() - start) / 1000000);
	}
}
