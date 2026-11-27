// SPDX-License-Identifier: GPL-2.0
/* Limits of the load that an ELF file cannot show, or shows at a high price */

#include <test_progs.h>
#include <bpf/btf.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include "cgroup_helpers.h"
#include "many_progs.lskel.h"

static int load(struct bpf_insn *insns, int cnt)
{
	return bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS, NULL, "GPL", insns, cnt, NULL);
}

static struct bpf_insn *straight_code(int cnt)
{
	struct bpf_insn *insns = calloc(cnt, sizeof(*insns));
	int i;

	if (!ASSERT_OK_PTR(insns, "insns"))
		return NULL;
	for (i = 0; i < cnt - 1; i++)
		insns[i] = BPF_MOV64_IMM(BPF_REG_0, i);
	insns[i] = BPF_EXIT_INSN();
	return insns;
}

static void on_alarm(int sig)
{
}

/* A signal that does not kill does not stop the load */
static void test_signals(void)
{
	struct itimerval on = { { 0, 200 }, { 0, 200 } }, off = {};
	struct sigaction sa = { .sa_handler = on_alarm }, old;
	struct bpf_insn *insns = straight_code(20000);
	int fd;

	if (!insns)
		return;
	sigaction(SIGALRM, &sa, &old);
	setitimer(ITIMER_REAL, &on, NULL);
	fd = load(insns, 20000);
	setitimer(ITIMER_REAL, &off, NULL);
	sigaction(SIGALRM, &old, NULL);
	if (ASSERT_OK_FD(fd, "load"))
		close(fd);
	free(insns);
}

static int exit_code(pid_t pid)
{
	int status;

	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "wait") ||
	    !ASSERT_TRUE(WIFEXITED(status), "exited"))
		return -1;
	return WEXITSTATUS(status);
}

/* The freezer does not wait for the end of the load. The load starts again after it. */
static void test_freezer(int flag)
{
	struct bpf_insn *insns = straight_code(200000);
	struct bpf_common_attr common = {};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
		.insns = ptr_to_u64(insns),
		.insn_cnt = 200000,
		.license = ptr_to_u64("GPL"),
	};
	int cg = -1, pipes[2] = { -1, -1 }, fd;
	char buf[64] = "";
	pid_t pid;

	if (!insns || !ASSERT_OK(setup_cgroup_environment(), "setup") ||
	    !ASSERT_OK(pipe(pipes), "pipe"))
		goto out;
	cg = create_and_get_cgroup("/no_limits");
	if (!ASSERT_OK_FD(cg, "cgroup"))
		goto out;
	pid = fork();
	if (!pid) {
		/* the fd that the prog gets */
		if (join_parent_cgroup("/no_limits"))
			_exit(1);
		fd = dup(pipes[0]);
		close(fd);
		if (write(pipes[1], &fd, sizeof(fd)) != sizeof(fd))
			_exit(2);
		_exit(syscall(__NR_bpf, BPF_PROG_LOAD | flag, &attr, sizeof(attr), &common,
			      sizeof(common)) != fd ? 3 : 0);
	}
	close(pipes[1]);
	if (ASSERT_EQ(read(pipes[0], &fd, sizeof(fd)), sizeof(fd), "read")) {
		usleep(10000);
		ASSERT_OK(write_cgroup_file("/no_limits", "cgroup.freeze", "1"), "freeze");
		while (!strstr(buf, "frozen 1") &&
		       !read_cgroup_file("/no_limits", "cgroup.events", buf, sizeof(buf)))
			usleep(1000);
		snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", pid, fd);
		ASSERT_ERR(faccessat(AT_FDCWD, buf, F_OK, AT_SYMLINK_NOFOLLOW), "no prog yet");
		ASSERT_OK(write_cgroup_file("/no_limits", "cgroup.freeze", "0"), "thaw");
	}
	ASSERT_OK(exit_code(pid), "load");
out:
	close(pipes[0]);
	if (cg >= 0)
		close(cg);
	cleanup_cgroup_environment();
	free(insns);
}

/* 4 * funcs + 1 insns */
static struct bpf_insn *many_funcs(int funcs)
{
	struct bpf_insn *insns = calloc(4 * funcs + 1, sizeof(*insns)), *f;
	int i;

	if (!ASSERT_OK_PTR(insns, "insns"))
		return NULL;
	for (i = 0, f = insns + funcs + 1; i < funcs; i++) {
		insns[i] = BPF_CALL_REL(f - &insns[i] - 1);
		*f++ = BPF_MOV64_IMM(BPF_REG_0, i);
		*f++ = BPF_MOV64_IMM(BPF_REG_2, 0);
		*f++ = BPF_EXIT_INSN();
	}
	insns[funcs] = BPF_EXIT_INSN();
	return insns;
}

static int load_in_memcg(struct bpf_insn *insns, int cnt)
{
	pid_t pid = fork();
	int fd;

	if (pid)
		return exit_code(pid);
	fd = join_parent_cgroup("/no_limits") ? -EINVAL : load(insns, cnt);
	_exit(fd < 0 ? -fd : 0);
}

/* The load fails. The OOM killer leaves the loader alone. */
static void test_memcg(void)
{
	struct bpf_insn *insns = straight_code(200000), *funcs = many_funcs(2000);
	int cg = -1, mb, err;
	char max[16];

	if (!insns || !funcs || !ASSERT_OK(setup_cgroup_environment(), "setup"))
		goto out;
	cg = create_and_get_cgroup("/no_limits");
	if (!ASSERT_OK_FD(cg, "cgroup"))
		goto out;
	if (write_cgroup_file("/no_limits", "memory.max", "16M")) {
		test__skip();
		goto out;
	}
	ASSERT_EQ(load_in_memcg(insns, 200000), ENOMEM, "errno");

	/* some of these end in the JIT of the subprogs */
	for (mb = 4; mb <= 24; mb += 2) {
		snprintf(max, sizeof(max), "%dM", mb);
		ASSERT_OK(write_cgroup_file("/no_limits", "memory.max", max), "max");
		err = load_in_memcg(funcs, 4 * 2000 + 1);
		ASSERT_TRUE(!err || err == ENOMEM, "errno");
	}
out:
	if (cg >= 0)
		close(cg);
	cleanup_cgroup_environment();
	free(insns);
	free(funcs);
}

static int run(int fd)
{
	char pkt[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = sizeof(pkt));

	return bpf_prog_test_run_opts(fd, &opts) ?: opts.retval;
}

/* The target of a tail call reads the context at 'off'. The run passes 8 bytes. */
static void check_syscall_target(int off, int expected)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .prog_flags = BPF_F_SLEEPABLE);
	int map = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, NULL, 4, 4, 1, NULL);
	struct bpf_insn first[] = {
		BPF_LD_MAP_FD(BPF_REG_2, map),
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_EMIT_CALL(BPF_FUNC_tail_call),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_EXIT_INSN(),
	}, target[] = {
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, off),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
		BPF_EXIT_INSN(),
	};
	int ctx[2] = { 5, 7 }, key = 0, fd, target_fd;
	LIBBPF_OPTS(bpf_test_run_opts, run_opts, .ctx_in = ctx, .ctx_size_in = sizeof(ctx));

	fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", first, ARRAY_SIZE(first), &opts);
	target_fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", target, ARRAY_SIZE(target),
				  &opts);
	if (ASSERT_OK_FD(fd, "load") && ASSERT_OK_FD(target_fd, "target"))
		ASSERT_EQ(bpf_map_update_elem(map, &key, &target_fd, 0) ?:
			  bpf_prog_test_run_opts(fd, &run_opts) ?: (int)run_opts.retval,
			  expected, "result");
	close(fd);
	close(target_fd);
	close(map);
}

static void test_syscall_ctx(void)
{
	int off;

	check_syscall_target(4, 7);
	for (off = 8; off < 65532; off += 4096)
		check_syscall_target(off, 0);
}

/* The number of a subprog does not fit into s16 */
static void test_subprogs(void)
{
	const int funcs = 33000, cnt = 4 * funcs + 1;
	struct bpf_insn *insns = many_funcs(funcs);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd;

	if (!insns)
		return;
	fd = load(insns, cnt);
	if (!ASSERT_OK_FD(fd, "load"))
		goto out;
	ASSERT_EQ(run(fd), funcs - 1, "retval");
	info.xlated_prog_len = cnt * sizeof(*insns);
	info.xlated_prog_insns = ptr_to_u64(insns);
	if (ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "dump"))
		ASSERT_EQ(insns[funcs - 1].imm, funcs, "subprog");
	close(fd);
out:
	free(insns);
}

/* A division takes 4 insns. The dump has more than 4 MB. */
static void test_dump(void)
{
	const int cnt = 140000;
	struct bpf_insn *insns = straight_code(4 * cnt);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd, i;

	if (!insns)
		return;
	insns[0] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
	insns[1] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
	for (i = 2; i < cnt - 1; i++)
		insns[i] = BPF_ALU64_REG(BPF_DIV, BPF_REG_0, BPF_REG_1);
	insns[i] = BPF_EXIT_INSN();

	fd = load(insns, cnt);
	if (ASSERT_OK_FD(fd, "load")) {
		info.xlated_prog_len = 4 * cnt * sizeof(*insns);
		info.xlated_prog_insns = ptr_to_u64(insns);
		if (ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "dump"))
			ASSERT_GT(info.xlated_prog_len, 4 << 20, "len");
		close(fd);
	}
	free(insns);
}

/* Calls of all kfuncs that the verifier can describe, in dead code */
static void test_kfuncs(void)
{
	struct btf *btf = btf__load_vmlinux_btf();
	struct bpf_insn insns[1024], one[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, 0),
		BPF_EXIT_INSN(),
	};
	const struct btf_type *t;
	int id, fd, cnt = 2;

	if (!ASSERT_OK_PTR(btf, "btf"))
		return;
	for (id = 1; id < btf__type_cnt(btf) && cnt < 302; id++) {
		t = btf__type_by_id(btf, id);
		if (!btf_is_func(t) || strncmp(btf__name_by_offset(btf, t->name_off), "bpf_", 4))
			continue;
		one[2].imm = id;
		fd = load(one, ARRAY_SIZE(one));
		if (fd < 0)
			continue;
		close(fd);
		insns[cnt++] = one[2];
	}
	btf__free(btf);
	if (cnt < 302) {
		test__skip();
		return;
	}
	insns[0] = one[0];
	insns[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, cnt - 2);
	insns[cnt++] = one[3];
	fd = load(insns, cnt);
	if (ASSERT_OK_FD(fd, "load"))
		close(fd);
}

/* Type 1 is int, type 'value' is the value of a map */
static void check_btf(struct btf *btf, int value, int expected)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .btf_key_type_id = 1, .btf_value_type_id = value);
	int fd;

	if (ASSERT_EQ(btf__load_into_kernel(btf), expected, "load") && !expected) {
		opts.btf_fd = btf__fd(btf);
		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, &opts);
		if (ASSERT_OK_FD(fd, "map"))
			close(fd);
	}
	btf__free(btf);
}

static struct btf *new_btf(void)
{
	struct btf *btf = btf__new_empty();

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	return btf;
}

enum chain { STRUCTS, ARRAYS, TYPEDEFS, DAG };

/* Type 2 holds type 3, ... The last one holds type 'last'. */
static struct btf *btf_chain(enum chain kind, int cnt, int last)
{
	struct btf *btf = new_btf();
	int i, next;

	for (i = 2; i < cnt + 2; i++) {
		next = i == cnt + 1 ? last : i + 1;
		if (kind == ARRAYS) {
			btf__add_array(btf, 1, next, 1);
		} else if (kind == TYPEDEFS) {
			btf__add_typedef(btf, "t", next);
		} else {
			btf__add_struct(btf, "s", 4);
			btf__add_field(btf, "a", next, 0, 0);
			if (kind != DAG)
				continue;
			btf__add_field(btf, "b", next, 0, 0);
			btf__add_field(btf, "c", next, 0, 0);
		}
	}
	return btf;
}

static void test_btf(void)
{
	static char name[4098];
	struct btf *btf;
	enum chain kind;
	int i;

	for (kind = STRUCTS; kind <= DAG; kind++) {
		check_btf(btf_chain(kind, 30, 1), 2, 0);
		check_btf(btf_chain(kind, 30, 2), 2, -EEXIST);
	}

	/* 1M kptrs in a struct that nobody can allocate */
	btf = new_btf();
	btf__add_struct(btf, "task_struct", 4);
	btf__add_field(btf, "a", 1, 0, 0);
	btf__add_type_tag(btf, "kptr", 2);
	btf__add_ptr(btf, 3);
	btf__add_array(btf, 1, 4, 1000000);
	for (i = 0; i < 100; i++) {
		btf__add_struct(btf, "s", 8000008);
		btf__add_field(btf, "p", 4, 0, 0);
		btf__add_field(btf, "a", 5, 64, 0);
	}
	check_btf(btf, 1, 0);

	/* ptr -> typedef -> struct -> array -> typedef */
	btf = new_btf();
	btf__add_ptr(btf, 3);
	btf__add_typedef(btf, "t", 4);
	btf__add_struct(btf, "s", 4);
	btf__add_field(btf, "a", 5, 0, 0);
	btf__add_array(btf, 1, 3, 1);
	check_btf(btf, 4, -EEXIST);

	/* ptr -> typedef -> array -> typedef */
	btf = new_btf();
	btf__add_ptr(btf, 3);
	btf__add_typedef(btf, "t", 4);
	btf__add_array(btf, 1, 3, 1);
	check_btf(btf, 4, -EEXIST);

	memset(name, 'x', 4097);
	btf = new_btf();
	btf__add_typedef(btf, name, 1);
	check_btf(btf, 2, -EINVAL);

	name[4096] = 0;
	btf = new_btf();
	btf__add_typedef(btf, name, 1);
	check_btf(btf, 2, 0);

	name[4000] = 7;
	btf = new_btf();
	btf__add_typedef(btf, name, 1);
	check_btf(btf, 2, -EINVAL);
}

/* 600 maps and 601 programs */
static void test_lskel(void)
{
	struct rlimit old, new = { 4096, 4096 };
	struct many_progs_lskel *skel;

	getrlimit(RLIMIT_NOFILE, &old);
	new.rlim_max = MAX(new.rlim_max, old.rlim_max);
	setrlimit(RLIMIT_NOFILE, &new);
	skel = many_progs_lskel__open_and_load();
	setrlimit(RLIMIT_NOFILE, &old);
	if (!ASSERT_OK_PTR(skel, "load"))
		return;
	ASSERT_EQ(run(skel->progs.prog699.prog_fd), 699, "retval");
	ASSERT_EQ(run(skel->progs.last.prog_fd), 2, "weak ksym");
	many_progs_lskel__destroy(skel);
}

void serial_test_no_limits(void)
{
	if (test__start_subtest("signals"))
		test_signals();
	if (test__start_subtest("freezer"))
		test_freezer(0);
	if (test__start_subtest("freezer_common_attrs"))
		test_freezer(BPF_COMMON_ATTRS);
	if (test__start_subtest("memcg"))
		test_memcg();
	if (test__start_subtest("syscall_ctx"))
		test_syscall_ctx();
	if (test__start_subtest("subprogs"))
		test_subprogs();
	if (test__start_subtest("dump"))
		test_dump();
	if (test__start_subtest("kfuncs"))
		test_kfuncs();
	if (test__start_subtest("btf"))
		test_btf();
	if (test__start_subtest("lskel"))
		test_lskel();
}
