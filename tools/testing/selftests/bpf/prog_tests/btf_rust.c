// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <bpf/btf.h>

#define FUNC_NAME "write_fmt<scx_simple::BpfStream>"
#define KSYM_NAME "write_fmt_scx_simple__BpfStream_"

/* The name of a function of Rust is a part of the name of the program in kallsyms */
static void test_func_name(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	int int_id, proto_id, prog_fd = -1, i;
	struct bpf_func_info func_info = {};
	struct bpf_prog_info info = {};
	unsigned long long addr;
	__u32 len = sizeof(info);
	char sym[128], *p = sym;
	struct btf *btf;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf"))
		return;
	int_id = btf__add_int(btf, "i32", 4, BTF_INT_SIGNED);
	ASSERT_GT(int_id, 0, "int");
	proto_id = btf__add_func_proto(btf, int_id);
	ASSERT_GT(proto_id, 0, "proto");
	ASSERT_OK(btf__add_func_param(btf, "ctx", int_id), "param");
	func_info.type_id = btf__add_func(btf, FUNC_NAME, BTF_FUNC_STATIC, proto_id);
	ASSERT_GT(func_info.type_id, 0, "func");
	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf load"))
		goto out;

	opts.prog_btf_fd = btf__fd(btf);
	opts.func_info = &func_info;
	opts.func_info_cnt = 1;
	opts.func_info_rec_size = sizeof(func_info);
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns,
				ARRAY_SIZE(insns), &opts);
	if (!ASSERT_GE(prog_fd, 0, "prog load"))
		goto out;
	if (!ASSERT_OK(bpf_prog_get_info_by_fd(prog_fd, &info, &len), "prog info"))
		goto out;
	if (!info.jited_prog_len) {
		test__skip();
		goto out;
	}

	p += sprintf(p, "bpf_prog_");
	for (i = 0; i < BPF_TAG_SIZE; i++)
		p += sprintf(p, "%02x", info.tag[i]);
	sprintf(p, "_%s", KSYM_NAME);
	ASSERT_OK(kallsyms_find(sym, &addr), sym);
out:
	if (prog_fd >= 0)
		close(prog_fd);
	btf__free(btf);
}

/* Serial: programs are not in kallsyms while another test sets bpf_jit_harden */
void serial_test_btf_rust(void)
{
	if (test__start_subtest("func_name"))
		test_func_name();
}
