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

struct test_btf {
	struct btf_header hdr;
	__u32 types[15];
	char strings[128];
};

static struct test_btf raw_btf = {
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

static int load_test_btf(void)
{
	__u32 log_level = 1 | 2 | 4;
	LIBBPF_OPTS(bpf_btf_load_opts, opts,
		    .log_buf = log,
		    .log_size = sizeof(log),
		    .log_level = log_level,
	);
	int saved_errno, btf_fd;

	log[0] = 0;
	btf_fd = bpf_btf_load(&raw_btf, sizeof(raw_btf), &opts);
	saved_errno = errno;
	if (btf_fd < 0 || env.verbosity > VERBOSE_NORMAL) {
		printf("-------- BTF load log start --------\n");
		printf("%s", log);
		printf("-------- BTF load log end ----------\n");
	}
	if (btf_fd < 0)
		PRINT_FAIL("bpf_btf_load() failed, errno=%d\n", saved_errno);
	return btf_fd;
}

static int load_test_prog(int btf_fd, struct bpf_insn *insns, size_t insn_cnt,
			  struct bpf_core_relo *relos, size_t relo_cnt)
{
	struct bpf_func_info funcs[] = {
		{
			.insn_off = 0,
			.type_id = 4,
		}
	};
	__u32 log_level = 1 | 2 | 4;
	union bpf_attr attr = {};
	int prog_fd;

	log[0] = 0;
	attr.prog_btf_fd = btf_fd;
	attr.prog_type = BPF_TRACE_RAW_TP;
	attr.license = (__u64)"GPL";
	attr.insns = (__u64)insns;
	attr.insn_cnt = insn_cnt;
	attr.log_buf = (__u64)log;
	attr.log_size = sizeof(log);
	attr.log_level = log_level;
	attr.func_info = (__u64)funcs;
	attr.func_info_cnt = sizeof(funcs) / sizeof(*funcs);
	attr.func_info_rec_size = sizeof(*funcs);
	attr.core_relos = (__u64)relos;
	attr.core_relo_cnt = relo_cnt;
	attr.core_relo_rec_size = sizeof(*relos);
	prog_fd = sys_bpf_prog_load(&attr, sizeof(attr), 1);
	if (prog_fd < 0 || env.verbosity > VERBOSE_NORMAL) {
		printf("-------- program load log start --------\n");
		printf("%s", log);
		printf("-------- program load log end ----------\n");
	}
	return prog_fd;
}

/* Check that verifier rejects BPF program containing relocation
 * pointing to non-existent BTF type.
 */
static void test_bad_local_id(void)
{
	struct bpf_insn insns[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_core_relo relos[] = {
		{
			.insn_off = 0,		/* patch first instruction (r0 = 0) */
			.type_id = 100500,	/* !!! this type id does not exist */
			.access_str_off = 6,	/* offset of "0" */
			.kind = BPF_CORE_TYPE_ID_LOCAL,
		}
	};
	int prog_fd = -1;
	int btf_fd = -1;

	btf_fd = load_test_btf();
	if (btf_fd < 0)
		return;

	prog_fd = load_test_prog(btf_fd, insns, ARRAY_SIZE(insns),
				 relos, ARRAY_SIZE(relos));
	if (prog_fd >= 0) {
		PRINT_FAIL("sys_bpf_prog_load() expected to fail\n");
		goto out;
	}
	ASSERT_HAS_SUBSTR(log, "relo #0: bad type id 100500", "program load log");

out:
	close(prog_fd);
	close(btf_fd);
}

static void test_truncated_ldimm64(void)
{
	struct bpf_insn insns[] = {
		BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_0, 0, 0, 0),
	};
	struct bpf_core_relo relos[] = {
		{
			.insn_off = 0,
			.type_id = 2,
			.access_str_off = 6,
			.kind = BPF_CORE_TYPE_ID_LOCAL,
		}
	};
	int prog_fd = -1;
	int btf_fd = -1;

	btf_fd = load_test_btf();
	if (btf_fd < 0)
		return;

	prog_fd = load_test_prog(btf_fd, insns, ARRAY_SIZE(insns),
				 relos, ARRAY_SIZE(relos));
	if (prog_fd >= 0) {
		PRINT_FAIL("sys_bpf_prog_load() expected to fail\n");
		goto out;
	}
	ASSERT_HAS_SUBSTR(log, "core_relo[0] targets truncated bpf_ld_imm64 insn",
			  "program load log");

out:
	close(prog_fd);
	close(btf_fd);
}

void test_core_reloc_raw(void)
{
	if (test__start_subtest("bad_local_id"))
		test_bad_local_id();
	if (test__start_subtest("truncated_ldimm64"))
		test_truncated_ldimm64();
}
