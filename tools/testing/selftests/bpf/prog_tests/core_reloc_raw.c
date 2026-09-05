// SPDX-License-Identifier: GPL-2.0

/* Test cases that can't load programs using libbpf and need direct
 * BPF syscall access
 */

#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "test_progs.h"
#include "test_btf.h"
#include "bpf/libbpf_internal.h"

static char log[16 * 1024];

static int load_core_relo_subprog(int btf_fd, int main_id, int sub_id,
				  int enum_id, int access_str_off, bool relocate)
{
	struct bpf_insn insns[] = {
		BPF_CALL_REL(2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_func_info funcs[] = {
		{ .insn_off = 0, .type_id = main_id },
		{ .insn_off = 3, .type_id = sub_id },
	};
	struct bpf_core_relo relo = {
		.insn_off = 2 * sizeof(struct bpf_insn),
		.type_id = enum_id,
		.access_str_off = access_str_off,
		.kind = BPF_CORE_ENUMVAL_VALUE,
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.insn_cnt = ARRAY_SIZE(insns),
		.insns = (__u64)insns,
		.license = (__u64)"GPL",
		.log_buf = (__u64)log,
		.log_size = sizeof(log),
		.log_level = 1,
		.prog_btf_fd = btf_fd,
		.func_info_rec_size = sizeof(struct bpf_func_info),
		.func_info = (__u64)funcs,
		.func_info_cnt = ARRAY_SIZE(funcs),
	};

	if (relocate) {
		attr.core_relo_cnt = 1;
		attr.core_relos = (__u64)&relo;
		attr.core_relo_rec_size = sizeof(relo);
	}
	memset(log, 0, sizeof(log));
	return sys_bpf_prog_load(&attr, sizeof(attr), 1);
}

static void test_poisoned_subprog_terminator(void)
{
	const void *raw_btf;
	struct btf *btf = NULL;
	__u32 raw_btf_size;
	int access_str_off, btf_fd = -1, enum_id;
	int int_id, main_id, prog_fd = -1, proto_id, sub_id;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf_new_empty"))
		return;
	int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(int_id, 0, "add_int"))
		goto cleanup;
	proto_id = btf__add_func_proto(btf, int_id);
	if (!ASSERT_GT(proto_id, 0, "add_func_proto"))
		goto cleanup;
	main_id = btf__add_func(btf, "main_fn", BTF_FUNC_STATIC, proto_id);
	if (!ASSERT_GT(main_id, 0, "add_main_func"))
		goto cleanup;
	sub_id = btf__add_func(btf, "sub_fn", BTF_FUNC_STATIC, proto_id);
	if (!ASSERT_GT(sub_id, 0, "add_sub_func"))
		goto cleanup;
	enum_id = btf__add_enum(btf, "core_relo_subprog_poison_missing", 4);
	if (!ASSERT_GT(enum_id, 0, "add_enum") ||
	    !ASSERT_OK(btf__add_enum_value(btf, "value", 0), "add_enum_value"))
		goto cleanup;
	access_str_off = btf__add_str(btf, "0");
	if (!ASSERT_GT(access_str_off, 0, "add_access_str"))
		goto cleanup;

	raw_btf = btf__raw_data(btf, &raw_btf_size);
	if (!ASSERT_OK_PTR(raw_btf, "raw_btf"))
		goto cleanup;
	btf_fd = bpf_btf_load(raw_btf, raw_btf_size, NULL);
	if (!ASSERT_GE(btf_fd, 0, "btf_load"))
		goto cleanup;

	/* The same two-subprogram program is valid before the relocation. */
	prog_fd = load_core_relo_subprog(btf_fd, main_id, sub_id, enum_id,
					 access_str_off, false);
	if (!ASSERT_GE(prog_fd, 0, "control_load"))
		goto cleanup;
	close(prog_fd);
	prog_fd = -1;

	/*
	 * Poison the first subprogram's terminal exit. The verifier must reject
	 * the resulting control flow across the subprogram boundary in the CFG.
	 */
	prog_fd = load_core_relo_subprog(btf_fd, main_id, sub_id, enum_id,
					 access_str_off, true);
	if (!ASSERT_LT(prog_fd, 0, "poisoned_load"))
		goto cleanup;
	ASSERT_HAS_SUBSTR(log, "fall-through out of subprog from insn 2 to 3",
			  "poisoned_load_log");

cleanup:
	if (env.verbosity > VERBOSE_NORMAL && log[0]) {
		printf("-------- program load log start --------\n");
		printf("%s", log);
		printf("-------- program load log end ----------\n");
	}
	close(prog_fd);
	close(btf_fd);
	btf__free(btf);
}

/* Check that verifier rejects BPF program containing relocation
 * pointing to non-existent BTF type.
 */
static void test_bad_local_id(void)
{
	struct test_btf {
		struct btf_header hdr;
		__u32 types[15];
		char strings[128];
	} raw_btf = {
		.hdr = {
			.magic = BTF_MAGIC,
			.version = BTF_VERSION,
			.hdr_len = sizeof(struct btf_header),
			.type_off = 0,
			.type_len = sizeof(raw_btf.types),
			.str_off = offsetof(struct test_btf, strings) -
				   offsetof(struct test_btf, types),
			.str_len = sizeof(raw_btf.strings),
		},
		.types = {
			BTF_PTR_ENC(0),					/* [1] void*  */
			BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4),	/* [2] int    */
			BTF_FUNC_PROTO_ENC(2, 1),			/* [3] int (*)(void*) */
			BTF_FUNC_PROTO_ARG_ENC(8, 1),
			BTF_FUNC_ENC(8, 3)			/* [4] FUNC 'foo' type_id=2   */
		},
		.strings = "\0int\0 0\0foo\0"
	};
	__u32 log_level = 1 | 2 | 4;
	LIBBPF_OPTS(bpf_btf_load_opts, opts,
		    .log_buf = log,
		    .log_size = sizeof(log),
		    .log_level = log_level,
	);
	struct bpf_insn insns[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_func_info funcs[] = {
		{
			.insn_off = 0,
			.type_id = 4,
		}
	};
	struct bpf_core_relo relos[] = {
		{
			.insn_off = 0,		/* patch first instruction (r0 = 0) */
			.type_id = 100500,	/* !!! this type id does not exist */
			.access_str_off = 6,	/* offset of "0" */
			.kind = BPF_CORE_TYPE_ID_LOCAL,
		}
	};
	union bpf_attr attr;
	int saved_errno;
	int prog_fd = -1;
	int btf_fd = -1;

	btf_fd = bpf_btf_load(&raw_btf, sizeof(raw_btf), &opts);
	saved_errno = errno;
	if (btf_fd < 0 || env.verbosity > VERBOSE_NORMAL) {
		printf("-------- BTF load log start --------\n");
		printf("%s", log);
		printf("-------- BTF load log end ----------\n");
	}
	if (btf_fd < 0) {
		PRINT_FAIL("bpf_btf_load() failed, errno=%d\n", saved_errno);
		return;
	}

	log[0] = 0;
	memset(&attr, 0, sizeof(attr));
	attr.prog_btf_fd = btf_fd;
	attr.prog_type = BPF_TRACE_RAW_TP;
	attr.license = (__u64)"GPL";
	attr.insns = (__u64)&insns;
	attr.insn_cnt = sizeof(insns) / sizeof(*insns);
	attr.log_buf = (__u64)log;
	attr.log_size = sizeof(log);
	attr.log_level = log_level;
	attr.func_info = (__u64)funcs;
	attr.func_info_cnt = sizeof(funcs) / sizeof(*funcs);
	attr.func_info_rec_size = sizeof(*funcs);
	attr.core_relos = (__u64)relos;
	attr.core_relo_cnt = sizeof(relos) / sizeof(*relos);
	attr.core_relo_rec_size = sizeof(*relos);
	prog_fd = sys_bpf_prog_load(&attr, sizeof(attr), 1);
	saved_errno = errno;
	if (prog_fd < 0 || env.verbosity > VERBOSE_NORMAL) {
		printf("-------- program load log start --------\n");
		printf("%s", log);
		printf("-------- program load log end ----------\n");
	}
	if (prog_fd >= 0) {
		PRINT_FAIL("sys_bpf_prog_load() expected to fail\n");
		goto out;
	}
	ASSERT_HAS_SUBSTR(log, "relo #0: bad type id 100500", "program load log");

out:
	close(prog_fd);
	close(btf_fd);
}

void test_core_reloc_raw(void)
{
	if (test__start_subtest("poisoned_subprog_terminator"))
		test_poisoned_subprog_terminator();
	if (test__start_subtest("bad_local_id"))
		test_bad_local_id();
}
