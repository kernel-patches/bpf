// SPDX-License-Identifier: GPL-2.0
#include <bpf/btf.h>
#include <test_btf.h>
#include <linux/btf.h>
#include <test_progs.h>
#include <network_helpers.h>

#include "linked_list.skel.h"
#include "linked_list_fail.skel.h"

static char log_buf[1024 * 1024];

static struct {
	const char *prog_name;
	const char *err_msg;
} linked_list_fail_tests[] = {
#define TEST(test, off) \
	{ #test "_missing_lock_push_front", \
	  "bpf_spin_lock at off=" #off " must be held for bpf_list_head" }, \
	{ #test "_missing_lock_push_back", \
	  "bpf_spin_lock at off=" #off " must be held for bpf_list_head" }, \
	{ #test "_missing_lock_pop_front", \
	  "bpf_spin_lock at off=" #off " must be held for bpf_list_head" }, \
	{ #test "_missing_lock_pop_back", \
	  "bpf_spin_lock at off=" #off " must be held for bpf_list_head" },
	TEST(kptr, 32)
	TEST(global, 16)
	TEST(map, 0)
	TEST(inner_map, 0)
#undef TEST
#define TEST(test, op) \
	{ #test "_kptr_incorrect_lock_" #op, \
	  "held lock and object are not in the same allocation\n" \
	  "bpf_spin_lock at off=32 must be held for bpf_list_head" }, \
	{ #test "_global_incorrect_lock_" #op, \
	  "held lock and object are not in the same allocation\n" \
	  "bpf_spin_lock at off=16 must be held for bpf_list_head" }, \
	{ #test "_map_incorrect_lock_" #op, \
	  "held lock and object are not in the same allocation\n" \
	  "bpf_spin_lock at off=0 must be held for bpf_list_head" }, \
	{ #test "_inner_map_incorrect_lock_" #op, \
	  "held lock and object are not in the same allocation\n" \
	  "bpf_spin_lock at off=0 must be held for bpf_list_head" },
	TEST(kptr, push_front)
	TEST(kptr, push_back)
	TEST(kptr, pop_front)
	TEST(kptr, pop_back)
	TEST(global, push_front)
	TEST(global, push_back)
	TEST(global, pop_front)
	TEST(global, pop_back)
	TEST(map, push_front)
	TEST(map, push_back)
	TEST(map, pop_front)
	TEST(map, pop_back)
	TEST(inner_map, push_front)
	TEST(inner_map, push_back)
	TEST(inner_map, pop_front)
	TEST(inner_map, pop_back)
#undef TEST
	{ "map_compat_kprobe", "tracing progs cannot use bpf_list_head yet" },
	{ "map_compat_kretprobe", "tracing progs cannot use bpf_list_head yet" },
	{ "map_compat_tp", "tracing progs cannot use bpf_list_head yet" },
	{ "map_compat_perf", "tracing progs cannot use bpf_list_head yet" },
	{ "map_compat_raw_tp", "tracing progs cannot use bpf_list_head yet" },
	{ "map_compat_raw_tp_w", "tracing progs cannot use bpf_list_head yet" },
	{ "obj_type_id_oor", "local type ID argument must be in range [0, U32_MAX]" },
	{ "obj_new_no_composite", "bpf_obj_new type ID argument must be of a struct" },
	{ "obj_new_no_struct", "bpf_obj_new type ID argument must be of a struct" },
	{ "obj_drop_non_zero_off", "R1 must have zero offset when passed to release func" },
	{ "new_null_ret", "R0 invalid mem access 'ptr_or_null_'" },
	{ "obj_new_acq", "Unreleased reference id=" },
	{ "use_after_drop", "invalid mem access 'scalar'" },
	{ "ptr_walk_scalar", "type=scalar expected=percpu_ptr_" },
	{ "direct_read_lock", "direct access to bpf_spin_lock is disallowed" },
	{ "direct_write_lock", "direct access to bpf_spin_lock is disallowed" },
	{ "direct_read_head", "direct access to bpf_list_head is disallowed" },
	{ "direct_write_head", "direct access to bpf_list_head is disallowed" },
	{ "direct_read_node", "direct access to bpf_list_node is disallowed" },
	{ "direct_write_node", "direct access to bpf_list_node is disallowed" },
	{ "write_after_push_front", "only read is supported" },
	{ "write_after_push_back", "only read is supported" },
	{ "use_after_unlock_push_front", "invalid mem access 'scalar'" },
	{ "use_after_unlock_push_back", "invalid mem access 'scalar'" },
	{ "double_push_front", "arg#1 expected pointer to local kptr" },
	{ "double_push_back", "arg#1 expected pointer to local kptr" },
	{ "no_node_value_type", "bpf_list_node not found for local kptr\n" },
	{ "incorrect_value_type", "bpf_list_head value type does not match arg#1" },
	{ "incorrect_node_var_off", "variable ptr_ access var_off=(0x0; 0xffffffff) disallowed" },
	{ "incorrect_node_off1", "bpf_list_node not found at offset=1" },
	{ "incorrect_node_off2", "arg#1 offset must be for bpf_list_node at off=0" },
	{ "no_head_type", "bpf_list_head not found for local kptr" },
	{ "incorrect_head_var_off1", "R1 doesn't have constant offset" },
	{ "incorrect_head_var_off2", "variable ptr_ access var_off=(0x0; 0xffffffff) disallowed" },
	{ "incorrect_head_off1", "bpf_list_head not found at offset=17" },
	{ "incorrect_head_off2", "bpf_list_head not found at offset=1" },
	{ "pop_front_off",
	  "15: (bf) r1 = r6                      ; R1_w=ptr_or_null_foo(id=4,ref_obj_id=4,off=40,imm=0) "
	  "R6_w=ptr_or_null_foo(id=4,ref_obj_id=4,off=40,imm=0) refs=2,4\n"
	  "16: (85) call bpf_this_cpu_ptr#154\nR1 type=ptr_or_null_ expected=percpu_ptr_" },
	{ "pop_back_off",
	  "15: (bf) r1 = r6                      ; R1_w=ptr_or_null_foo(id=4,ref_obj_id=4,off=40,imm=0) "
	  "R6_w=ptr_or_null_foo(id=4,ref_obj_id=4,off=40,imm=0) refs=2,4\n"
	  "16: (85) call bpf_this_cpu_ptr#154\nR1 type=ptr_or_null_ expected=percpu_ptr_" },
};

static void test_linked_list_fail_prog(const char *prog_name, const char *err_msg)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = log_buf,
						.kernel_log_size = sizeof(log_buf),
						.kernel_log_level = 1);
	struct linked_list_fail *skel;
	struct bpf_program *prog;
	int ret;

	skel = linked_list_fail__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "linked_list_fail__open_opts"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto end;

	bpf_program__set_autoload(prog, true);

	ret = linked_list_fail__load(skel);
	if (!ASSERT_ERR(ret, "linked_list_fail__load must fail"))
		goto end;

	if (!ASSERT_OK_PTR(strstr(log_buf, err_msg), "expected error message")) {
		fprintf(stderr, "Expected: %s\n", err_msg);
		fprintf(stderr, "Verifier: %s\n", log_buf);
	}

end:
	linked_list_fail__destroy(skel);
}

static void clear_fields(struct bpf_map *map)
{
	char buf[24];
	int key = 0;

	memset(buf, 0xff, sizeof(buf));
	ASSERT_OK(bpf_map__update_elem(map, &key, sizeof(key), buf, sizeof(buf), 0), "check_and_free_fields");
}

enum {
	TEST_ALL,
	PUSH_POP,
	PUSH_POP_MULT,
	LIST_IN_LIST,
};

static void test_linked_list_success(int mode, bool leave_in_map)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct linked_list *skel;
	int ret;

	skel = linked_list__open_and_load();
	if (!ASSERT_OK_PTR(skel, "linked_list__open_and_load"))
		return;

	if (mode == LIST_IN_LIST)
		goto lil;
	if (mode == PUSH_POP_MULT)
		goto ppm;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_push_pop), &opts);
	ASSERT_OK(ret, "map_list_push_pop");
	ASSERT_OK(opts.retval, "map_list_push_pop retval");
	if (!leave_in_map)
		clear_fields(skel->maps.array_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.inner_map_list_push_pop), &opts);
	ASSERT_OK(ret, "inner_map_list_push_pop");
	ASSERT_OK(opts.retval, "inner_map_list_push_pop retval");
	if (!leave_in_map)
		clear_fields(skel->maps.inner_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop), &opts);
	ASSERT_OK(ret, "global_list_push_pop");
	ASSERT_OK(opts.retval, "global_list_push_pop retval");
	if (!leave_in_map)
		clear_fields(skel->maps.data_A);

	if (mode == PUSH_POP)
		goto end;

ppm:
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_push_pop_multiple), &opts);
	ASSERT_OK(ret, "map_list_push_pop_multiple");
	ASSERT_OK(opts.retval, "map_list_push_pop_multiple retval");
	if (!leave_in_map)
		clear_fields(skel->maps.array_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.inner_map_list_push_pop_multiple), &opts);
	ASSERT_OK(ret, "inner_map_list_push_pop_multiple");
	ASSERT_OK(opts.retval, "inner_map_list_push_pop_multiple retval");
	if (!leave_in_map)
		clear_fields(skel->maps.inner_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop_multiple), &opts);
	ASSERT_OK(ret, "global_list_push_pop_multiple");
	ASSERT_OK(opts.retval, "global_list_push_pop_multiple retval");
	if (!leave_in_map)
		clear_fields(skel->maps.data_A);

	if (mode == PUSH_POP_MULT)
		goto end;

lil:
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_in_list), &opts);
	ASSERT_OK(ret, "map_list_in_list");
	ASSERT_OK(opts.retval, "map_list_in_list retval");
	if (!leave_in_map)
		clear_fields(skel->maps.array_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.inner_map_list_in_list), &opts);
	ASSERT_OK(ret, "inner_map_list_in_list");
	ASSERT_OK(opts.retval, "inner_map_list_in_list retval");
	if (!leave_in_map)
		clear_fields(skel->maps.inner_map);

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_in_list), &opts);
	ASSERT_OK(ret, "global_list_in_list");
	ASSERT_OK(opts.retval, "global_list_in_list retval");
	if (!leave_in_map)
		clear_fields(skel->maps.data_A);
end:
	linked_list__destroy(skel);
}

/* struct bpf_spin_lock {
 *   int foo;
 * };
 * struct bpf_list_head {
 *   __u64 :64;
 *   __u64 :64;
 * } __attribute__((aligned(8)));
 * struct bpf_list_node {
 *   __u64 :64;
 *   __u64 :64;
 * } __attribute__((aligned(8)));
 */
static const char btf_str_sec[] = "\0bpf_spin_lock\0bpf_list_head\0bpf_list_node\0foo\0bar\0baz"
				  "\0contains:foo:foo\0contains:bar:bar\0contains:baz:baz\0bam"
				  "\0contains:bam:bam";

#define INIT_BTF_TILL_4							\
	/* int */							\
	BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */	\
	/* struct bpf_spin_lock */                      /* [2] */	\
	BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 4),	\
	BTF_MEMBER_ENC(43, 1, 0),					\
	/* struct bpf_list_head */                      /* [3] */	\
	BTF_TYPE_ENC(15, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 0), 16),	\
	/* struct bpf_list_node */                      /* [4] */	\
	BTF_TYPE_ENC(29, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 0), 16),

static void check_btf(u32 *types, u32 types_len, int error)
{
	LIBBPF_OPTS(bpf_btf_load_opts, opts,
		    .log_buf = log_buf,
		    .log_size = sizeof(log_buf),
	);
	struct btf_header hdr = {
		.magic = BTF_MAGIC,
		.version = BTF_VERSION,
		.hdr_len = sizeof(struct btf_header),
		.type_len = types_len,
		.str_off = types_len,
		.str_len = sizeof(btf_str_sec),
	};
	void *ptr, *raw_btf;
	int fd, ret;

	raw_btf = malloc(sizeof(hdr) + hdr.type_len + hdr.str_len);
	if (!ASSERT_OK_PTR(raw_btf, "malloc(raw_btf)"))
		return;

	ptr = raw_btf;
	memcpy(ptr, &hdr, sizeof(hdr));
	ptr += sizeof(hdr);
	memcpy(ptr, types, hdr.type_len);
	ptr += hdr.type_len;
	memcpy(ptr, btf_str_sec, hdr.str_len);
	ptr += hdr.str_len;

	fd = bpf_btf_load(raw_btf, ptr - raw_btf, &opts);
	ret = fd < 0 ? -errno : 0;
	if (fd >= 0)
		close(fd);
	if (error)
		ASSERT_LT(fd, 0, "bpf_btf_load");
	else
		ASSERT_GE(fd, 0, "bpf_btf_load");
	if (!ASSERT_EQ(ret, error, "-errno == error"))
		printf("BTF Log:\n%s\n", log_buf);
	free(raw_btf);
	return;
}

#define SPIN_LOCK 2
#define LIST_HEAD 3
#define LIST_NODE 4
#define FOO 43
#define BAR 47
#define BAZ 51
#define BAM 106
#define CONT_FOO_FOO 55
#define CONT_BAR_BAR 72
#define CONT_BAZ_BAZ 89
#define CONT_BAM_BAM 110

static void test_btf(void)
{
	if (test__start_subtest("btf: too many locks")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 24), /* [5] */
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
			BTF_MEMBER_ENC(FOO, SPIN_LOCK, 32),
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 64),
		};
		check_btf(types, sizeof(types), -E2BIG);
	}
	if (test__start_subtest("btf: missing lock")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 5, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16),
			BTF_MEMBER_ENC(BAZ, LIST_NODE, 0),
		};
		check_btf(types, sizeof(types), -EINVAL);
	}
	if (test__start_subtest("btf: bad offset")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 0),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
			BTF_DECL_TAG_ENC(CONT_FOO_FOO, 5, 0),
		};
		check_btf(types, sizeof(types), -EFAULT);
	}
	if (test__start_subtest("btf: missing contains:")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 24), /* [5] */
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 64),
		};
		check_btf(types, sizeof(types), -EINVAL);
	}
	if (test__start_subtest("btf: missing struct")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 24), /* [5] */
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 64),
			BTF_DECL_TAG_ENC(CONT_BAR_BAR, 5, 1),
		};
		check_btf(types, sizeof(types), -ENOENT);
	}
	if (test__start_subtest("btf: missing node")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 24), /* [5] */
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 64),
			BTF_DECL_TAG_ENC(CONT_FOO_FOO, 5, 1),
		};
		check_btf(types, sizeof(types), -ENOENT);
	}
	if (test__start_subtest("btf: node incorrect type")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 20), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, SPIN_LOCK, 128),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 5, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 4),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 0),
		};
		check_btf(types, sizeof(types), -EINVAL);
	}
	if (test__start_subtest("btf: multiple bpf_list_node with name foo")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 52), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 128),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 256),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 384),
			BTF_DECL_TAG_ENC(CONT_FOO_FOO, 5, 0),
		};
		check_btf(types, sizeof(types), -EINVAL);
	}
	if (test__start_subtest("btf: owning | owned AA cycle")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_FOO_FOO, 5, 0),
		};
		check_btf(types, sizeof(types), -ELOOP);
	}
	if (test__start_subtest("btf: owning | owned ABA cycle")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAR_BAR, 5, 0),			    /* [6] */
			BTF_TYPE_ENC(BAR, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [7] */
			BTF_MEMBER_ENC(FOO, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_FOO_FOO, 7, 0),
		};
		check_btf(types, sizeof(types), -ELOOP);
	}
	if (test__start_subtest("btf: owning -> owned")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 20), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, SPIN_LOCK, 128),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 5, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16),
			BTF_MEMBER_ENC(BAZ, LIST_NODE, 0),
		};
		check_btf(types, sizeof(types), 0);
	}
	if (test__start_subtest("btf: owning -> owning | owned -> owned")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 20), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 128),
			BTF_DECL_TAG_ENC(CONT_BAR_BAR, 5, 0),			    /* [6] */
			BTF_TYPE_ENC(BAR, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [7] */
			BTF_MEMBER_ENC(FOO, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 7, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16),
			BTF_MEMBER_ENC(BAZ, LIST_NODE, 0),
		};
		check_btf(types, sizeof(types), 0);
	}
	if (test__start_subtest("btf: owning | owned -> owning | owned -> owned")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(FOO, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAR_BAR, 5, 0),			    /* [6] */
			BTF_TYPE_ENC(BAR, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [7] */
			BTF_MEMBER_ENC(FOO, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 7, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16),
			BTF_MEMBER_ENC(BAZ, LIST_NODE, 0),
		};
		check_btf(types, sizeof(types), -ELOOP);
	}
	if (test__start_subtest("btf: owning -> owning | owned -> owning | owned -> owned")) {
		u32 types[] = {
			INIT_BTF_TILL_4
			BTF_TYPE_ENC(FOO, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 20), /* [5] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 128),
			BTF_DECL_TAG_ENC(CONT_BAR_BAR, 5, 0),			    /* [6] */
			BTF_TYPE_ENC(BAR, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [7] */
			BTF_MEMBER_ENC(FOO, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAR, LIST_NODE, 128),
			BTF_MEMBER_ENC(BAZ, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAZ_BAZ, 7, 0),
			BTF_TYPE_ENC(BAZ, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 3), 36), /* [9] */
			BTF_MEMBER_ENC(BAR, LIST_HEAD, 0),
			BTF_MEMBER_ENC(BAZ, LIST_NODE, 128),
			BTF_MEMBER_ENC(FOO, SPIN_LOCK, 256),
			BTF_DECL_TAG_ENC(CONT_BAM_BAM, 9, 0),
			BTF_TYPE_ENC(BAM, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 16),
			BTF_MEMBER_ENC(BAM, LIST_NODE, 0),
		};
		check_btf(types, sizeof(types), -ELOOP);
	}
}

void test_linked_list(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(linked_list_fail_tests); i++) {
		if (!test__start_subtest(linked_list_fail_tests[i].prog_name))
			continue;
		test_linked_list_fail_prog(linked_list_fail_tests[i].prog_name,
					   linked_list_fail_tests[i].err_msg);
	}
	test_btf();
	test_linked_list_success(PUSH_POP, false);
	test_linked_list_success(PUSH_POP, true);
	test_linked_list_success(PUSH_POP_MULT, false);
	test_linked_list_success(PUSH_POP_MULT, true);
	test_linked_list_success(LIST_IN_LIST, false);
	test_linked_list_success(LIST_IN_LIST, true);
	test_linked_list_success(TEST_ALL, false);
}
