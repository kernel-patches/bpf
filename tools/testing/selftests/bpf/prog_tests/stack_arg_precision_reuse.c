// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

#define BPF_REG_PARAMS 11

/* Construct BTF and instructions directly so these tests also run with
 * compilers which cannot emit stack arguments yet.
 */
struct test_program {
	struct bpf_insn insns[128];
	struct bpf_func_info funcs[3];
	struct btf *btf;
	int insn_cnt;
	int func_cnt;
};

static char log_buf[1024 * 1024];

static int emit(struct test_program *p, struct bpf_insn insn)
{
	int idx = p->insn_cnt++;

	p->insns[idx] = insn;
	return idx;
}

static void jump_to(struct test_program *p, int from, int to)
{
	p->insns[from].off = to - from - 1;
}

static bool add_func(struct test_program *p, int nargs)
{
	char name[16];
	int proto, id, i;

	proto = btf__add_func_proto(p->btf, 1);
	if (!ASSERT_GT(proto, 0, "func_proto"))
		return false;
	for (i = 0; i < nargs; i++) {
		snprintf(name, sizeof(name), "arg%d", i + 1);
		id = btf__add_func_param(p->btf, name, i == 0 ? 2 : 1);
		if (!ASSERT_OK(id, "func_param"))
			return false;
	}
	snprintf(name, sizeof(name), "func%d", p->func_cnt);
	id = btf__add_func(p->btf, name,
			   p->func_cnt ? BTF_FUNC_STATIC : BTF_FUNC_GLOBAL, proto);
	if (!ASSERT_GT(id, 0, "func"))
		return false;
	p->funcs[p->func_cnt++] = (struct bpf_func_info) {
		.insn_off = p->insn_cnt,
		.type_id = id,
	};
	return true;
}

static bool init_program(struct test_program *p)
{
	p->btf = btf__new_empty();
	if (!ASSERT_OK_PTR(p->btf, "btf_new"))
		return false;
	if (!ASSERT_EQ(btf__add_int(p->btf, "u64", 8, 0), 1, "btf_int") ||
	    !ASSERT_EQ(btf__add_ptr(p->btf, 0), 2, "btf_ptr"))
		return false;
	return add_func(p, 1);
}

static void lookup_map(struct test_program *p, int map_fd)
{
	struct bpf_insn insns[] = {
		BPF_ST_MEM(BPF_W, BPF_REG_10, -8, 0),
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
		BPF_EXIT_INSN(),
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		emit(p, insns[i]);
}

struct reuse_test {
	const char *name;
	int slot;
	int offset;
	bool discard;
	bool callee_join;
	bool nested;
};

static bool build_reuse(struct test_program *p, int map_fd,
			const struct reuse_test *test)
{
	int branch, path1, path2, path3, call, i;
	int off = -(test->slot + 1) * 8;

	if (test->nested) {
		emit(p, BPF_CALL_REL(1));
		emit(p, BPF_EXIT_INSN());
		if (!add_func(p, 1))
			return false;
	}
	lookup_map(p, map_fd);
	emit(p, BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32));
	/* Keep the unused earlier argument initialized when testing arg7. */
	for (i = 0; i < test->slot; i++)
		emit(p, BPF_ST_MEM(BPF_DW, BPF_REG_PARAMS, -(i + 1) * 8, 0));
	branch = emit(p, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));
	emit(p, BPF_MOV64_IMM(BPF_REG_6, 0));
	if (test->slot >= 0)
		emit(p, BPF_ST_MEM(BPF_DW, BPF_REG_PARAMS, off, 0));
	if (test->callee_join)
		emit(p, BPF_MOV64_IMM(BPF_REG_8, 1));
	path1 = emit(p, BPF_JMP_A(0));
	jump_to(p, branch, p->insn_cnt);
	if (test->callee_join)
		emit(p, BPF_MOV64_IMM(BPF_REG_8, 0));
	branch = emit(p, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 1, 0));
	emit(p, BPF_MOV64_IMM(BPF_REG_6, 0));
	path2 = emit(p, BPF_JMP_A(0));
	jump_to(p, branch, p->insn_cnt);
	emit(p, BPF_MOV64_IMM(BPF_REG_6, test->offset));
	path3 = emit(p, BPF_JMP_A(0));
	/* M: paths 2 and 3 meet with their offsets still in r6. Path 2
	 * must acquire precision here when it reuses path 1's state at P.
	 */
	jump_to(p, path2, p->insn_cnt);
	jump_to(p, path3, p->insn_cnt);
	if (test->slot >= 0) {
		emit(p, BPF_STX_MEM(BPF_DW, BPF_REG_PARAMS, BPF_REG_6, off));
		emit(p, BPF_MOV64_IMM(BPF_REG_6, 0));
	}
	branch = emit(p, BPF_JMP_A(0));
	/* P: the precise offset is now in the outgoing argument slot. */
	jump_to(p, path1, p->insn_cnt);
	jump_to(p, branch, p->insn_cnt);
	emit(p, BPF_MOV64_REG(BPF_REG_1, BPF_REG_7));
	for (i = 2; i <= 5; i++) {
		if (i == 2 && (test->slot < 0 || test->callee_join))
			emit(p, BPF_MOV64_REG(i, test->slot < 0 ? BPF_REG_6 : BPF_REG_8));
		else
			emit(p, BPF_MOV64_IMM(i, 0));
	}
	call = emit(p, BPF_CALL_REL(0));
	emit(p, BPF_EXIT_INSN());
	p->insns[call].imm = p->insn_cnt - call - 1;
	if (!add_func(p, test->slot < 0 ? 2 : 6 + test->slot))
		return false;
	/* Different precise r2 values prevent reuse before the callee.
	 * They converge here while the offset is still in the caller's slot.
	 */
	if (test->callee_join) {
		emit(p, BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 2));
		emit(p, BPF_MOV64_IMM(BPF_REG_2, 0));
		emit(p, BPF_JMP_A(0));
	}
	if (test->slot < 0)
		emit(p, BPF_MOV64_REG(BPF_REG_6, BPF_REG_2));
	else
		emit(p, BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_PARAMS, -off));
	if (test->discard)
		emit(p, BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0));
	emit(p, BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_6));
	emit(p, BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0));
	emit(p, BPF_EXIT_INSN());
	return true;
}

static bool build_fallback(struct test_program *p, int map_fd, bool callee)
{
	lookup_map(p, map_fd);
	emit(p, BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32));
	emit(p, BPF_STX_MEM(BPF_DW, BPF_REG_PARAMS, BPF_REG_0, -8));
	emit(p, BPF_STX_MEM(BPF_DW, BPF_REG_PARAMS, BPF_REG_0, -16));
	emit(p, BPF_JMP_A(0));
	if (callee) {
		emit(p, BPF_MOV64_REG(BPF_REG_1, BPF_REG_7));
		emit(p, BPF_MOV64_IMM(BPF_REG_2, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_3, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_4, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_5, 0));
		emit(p, BPF_CALL_REL(1));
		emit(p, BPF_EXIT_INSN());
		if (!add_func(p, 7))
			return false;
		emit(p, BPF_MOV64_REG(BPF_REG_7, BPF_REG_1));
	}
	/* Subtraction turns r1 into a scalar. Precision backtracking across
	 * the store through its old pointer value needs conservative fallback.
	 * The resulting offset is bounded, so this program is always safe.
	 */
	emit(p, BPF_MOV64_REG(BPF_REG_1, BPF_REG_7));
	emit(p, BPF_ST_MEM(BPF_W, BPF_REG_1, 0, 0));
	emit(p, BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_7));
	emit(p, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 7));
	emit(p, BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_1));
	emit(p, BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_7, 0));
	if (!callee) {
		/* Consume the outgoing slots after exercising fallback. */
		emit(p, BPF_MOV64_REG(BPF_REG_1, BPF_REG_7));
		emit(p, BPF_MOV64_IMM(BPF_REG_2, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_3, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_4, 0));
		emit(p, BPF_MOV64_IMM(BPF_REG_5, 0));
		emit(p, BPF_CALL_REL(1));
		emit(p, BPF_EXIT_INSN());
		if (!add_func(p, 7))
			return false;
		emit(p, BPF_MOV64_IMM(BPF_REG_0, 0));
	}
	emit(p, BPF_EXIT_INSN());
	return true;
}

static void check_program(struct test_program *p, bool reject, bool fallback)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.prog_flags = BPF_F_TEST_STATE_FREQ,
		.log_buf = log_buf,
		.log_size = sizeof(log_buf),
		.log_level = 2,
		.func_info = p->funcs,
		.func_info_cnt = p->func_cnt,
		.func_info_rec_size = sizeof(p->funcs[0]),
	);
	int fd;

	if (!ASSERT_OK(btf__load_into_kernel(p->btf), "load_btf"))
		return;
	opts.prog_btf_fd = btf__fd(p->btf);
	log_buf[0] = '\0';
	fd = bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS, "stack_precision", "GPL",
			   p->insns, p->insn_cnt, &opts);
	if (env.verbosity > VERBOSE_NONE)
		printf("%s\n", log_buf);
	if (reject) {
		ASSERT_LT(fd, 0, "reject_unsafe_offset");
		ASSERT_HAS_SUBSTR(log_buf, "invalid access to map value", "bounds_error");
	} else {
		ASSERT_GE(fd, 0, "accept_safe_program");
	}
	if (fallback) {
		ASSERT_HAS_SUBSTR(log_buf, "falling back to forcing all scalars precise",
				  "fallback_reached");
		ASSERT_HAS_SUBSTR(log_buf, "force_precise: frame0: forcing r11-8 to be precise",
				  "fallback_arg6");
		ASSERT_HAS_SUBSTR(log_buf, "force_precise: frame0: forcing r11-16 to be precise",
				  "fallback_arg7");
	}
	if (fd >= 0)
		close(fd);
}

void test_stack_arg_precision_reuse(void)
{
	const struct reuse_test tests[] = {
		{ .name = "arg6", .slot = 0, .offset = 32 },
		{ .name = "arg7", .slot = 1, .offset = 32 },
		{ .name = "caller_frame", .slot = 0, .offset = 32, .callee_join = true },
		{ .name = "nested_caller_frame", .slot = 1, .offset = 32,
		  .callee_join = true, .nested = true },
		{ .name = "in_bounds", .slot = 1, .offset = 8 },
		{ .name = "discarded", .slot = 0, .offset = 32, .discard = true },
		{ .name = "register_control", .slot = -1, .offset = 32 },
	};
	struct test_program p;
	int map_fd, i;

	/* Stack argument JIT support currently exists on x86-64 and arm64. */
#if !defined(__x86_64__) && !defined(__aarch64__)
	test__skip();
	return;
#endif
	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 16, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!test__start_subtest(tests[i].name))
			continue;
		memset(&p, 0, sizeof(p));
		if (init_program(&p) && build_reuse(&p, map_fd, &tests[i]))
			check_program(&p, tests[i].offset > 8 && !tests[i].discard, false);
		btf__free(p.btf);
	}
	for (i = 0; i < 2; i++) {
		if (!test__start_subtest(i ? "fallback_caller_frame" : "fallback"))
			continue;
		memset(&p, 0, sizeof(p));
		if (init_program(&p) && build_fallback(&p, map_fd, i))
			check_program(&p, false, true);
		btf__free(p.btf);
	}
	close(map_fd);
}
