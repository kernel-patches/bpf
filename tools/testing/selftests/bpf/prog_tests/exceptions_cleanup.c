// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "sysctl_helpers.h"

#include "exceptions_cleanup.skel.h"

/* The cookie the programs throw. */
#define THROWN		0xeB9F

/*
 * What a run of a program has to show: its return value, the number of
 * resources the program recorded acquiring, and the releases observed, in
 * order, as a string: a digit names the acquired resource released at that
 * point, 's' an RCU or preemption section, '?' any acquired resource not
 * named elsewhere. @param is a choice the program reads.
 */
struct expect {
	int retval;
	int acquired;
	const char *released;
	__u32 param;
};

static void check_releases(struct exceptions_cleanup *skel, const struct expect *e)
{
	bool matched[ARRAY_SIZE(skel->bss->acquired)] = {};
	int n = strlen(e->released), i, j;

	ASSERT_EQ(skel->bss->acquired_cnt, e->acquired, "acquired");
	if (!ASSERT_EQ(skel->bss->released_cnt, n, "released"))
		return;
	for (i = 0; i < n; i++) {
		__u64 handle = skel->bss->released[i];
		char c = e->released[i];

		if (c == 's') {
			ASSERT_TRUE(skel->bss->released_section[i], "section");
			continue;
		}
		if (!ASSERT_FALSE(skel->bss->released_section[i], "not a section"))
			continue;
		if (c == '?') {
			for (j = 0; j < e->acquired; j++)
				if (!matched[j] && handle == skel->bss->acquired[j])
					break;
			if (ASSERT_LT(j, e->acquired, "released an acquired resource"))
				matched[j] = true;
			continue;
		}
		j = c - '0';
		if (ASSERT_EQ(handle, skel->bss->acquired[j], "release order"))
			matched[j] = true;
	}
}

static void reset(struct exceptions_cleanup *skel, __u32 param)
{
	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	memset(skel->bss->acquired, 0, sizeof(skel->bss->acquired));
	memset(skel->bss->released, 0, sizeof(skel->bss->released));
	memset(skel->bss->released_section, 0, sizeof(skel->bss->released_section));
	skel->bss->param = param;
	skel->bss->test_pid = getpid();
}

/* Run @prog once and check what it returned and what was released against @e. */
static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog,
		     const struct expect *e)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ret;

	reset(skel, e->param);
	/* A syscall program runs on nothing: no input, and once, without a repeat count. */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_SYSCALL) {
		ropts.data_in = NULL;
		ropts.data_size_in = 0;
		ropts.repeat = 0;
	}
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
	if (!ASSERT_OK(ret, "test_run"))
		return;
	ASSERT_EQ(ropts.retval, e->retval, "retval");
	check_releases(skel, e);
}

/*
 * Register the struct_ops whose program throws: the kernel calls it with a
 * task reference in a __ref argument as it registers, see bpf_dummy_reg().
 */
static void run_struct_ops(struct exceptions_cleanup *skel, const struct expect *e)
{
	struct bpf_link *link;

	reset(skel, e->param);
	link = bpf_map__attach_struct_ops(skel->maps.throwing_ops);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		return;
	check_releases(skel, e);
	bpf_link__destroy(link);
}

/* Open a file, which runs the LSM program that throws with a file and a dynptr that reads it. */
static void run_file(struct exceptions_cleanup *skel, const struct expect *e)
{
	int fd;

	reset(skel, e->param);
	skel->bss->file_armed = 1;
	fd = open("/proc/self/exe", O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open"))
		return;
	close(fd);
	ASSERT_EQ(skel->bss->file_armed, 0, "program ran");
	check_releases(skel, e);
}

/* Run every program; @prefix names the pass in the subtest names. */
static void run_suite(const char *prefix)
{
	struct exceptions_cleanup *skel;
	int server = -1;
	char name[64];

	skel = exceptions_cleanup__open();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open"))
		return;
	/* registered by the subtests that run its program */
	bpf_map__set_autoattach(skel->maps.throwing_ops, false);
	if (!ASSERT_OK(exceptions_cleanup__load(skel), "exceptions_cleanup__load"))
		goto out;
	if (!ASSERT_OK(exceptions_cleanup__attach(skel), "attach"))
		goto out;
	/* The listener throw_sock_cast looks up, on an ephemeral port. */
	server = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_OK_FD(server, "start_server"))
		goto out;
	skel->bss->server_port = get_socket_local_port(server);

/* Run program @pname as subtest @sname, expecting @ret, @n acquisitions and the releases @rel. */
#define RUN_AS(pname, sname, ret, n, rel, ...) do {				\
	struct expect e = { .retval = ret, .acquired = n, .released = rel, ##__VA_ARGS__ }; \
										\
	snprintf(name, sizeof(name), "%s%s", prefix, sname);			\
	if (test__start_subtest(name))						\
		run_prog(skel, skel->progs.pname, &e);				\
} while (0)
#define RUN(pname, ret, n, rel, ...) RUN_AS(pname, #pname, ret, n, rel, ##__VA_ARGS__)
#define THROW(pname, n, rel, ...) RUN(pname, THROWN, n, rel, ##__VA_ARGS__)
	THROW(throw_obj_reg, 1, "0");
	THROW(throw_obj_two, 2, "??");
	THROW(throw_ringbuf, 1, "0");
	THROW(throw_task, 1, "0");
	THROW(throw_sock_cast, 1, "0");
	THROW(throw_iter, 1, "0");
	THROW(throw_obj_maybe, 1, "0");
	THROW(throw_obj_caller, 1, "0");
	THROW(throw_obj_callx_caller, 1, "0");
	THROW(throw_obj_origin_after_guard, 1, "0");
	THROW(throw_obj_unconditional, 1, "0");
	THROW(throw_obj_dead_caller, 1, "0");
	THROW(throw_obj_subprog, 1, "0");
	THROW(throw_obj_global_caller, 1, "0");
	/* Locks and IRQ flags go first, sections next, objects last. */
	THROW(throw_spin_lock, 2, "10");
	THROW(throw_rcu, 1, "s0");
	THROW(throw_irq, 1, "0s");
	THROW(throw_obj_after_caller_lock, 2, "01");
	THROW(throw_sleeping_dtor_after_section, 1, "s0");
	/* References the program keeps in different places on different paths, or nowhere. */
	THROW(throw_reg_conflict, 1, "0");
	THROW(throw_dead_reg, 1, "0");
	THROW(throw_lock_two_locations, 2, "01");
	RUN_AS(throw_shared_release, "throw_shared_release_first", THROWN, 2, "1",
	       .param = 0);
	RUN_AS(throw_shared_release, "throw_shared_release_second", THROWN, 2, "0",
	       .param = 1);
	RUN_AS(throw_refcount_shared_release, "throw_refcount_shared_release_first", THROWN, 1, "0",
	       .param = 0);
	RUN_AS(throw_refcount_shared_release, "throw_refcount_shared_release_second", THROWN, 1, "0",
	       .param = 1);
	/* A callee overwrites the caller's copy of the pointer: the object is released, once. */
	THROW(throw_callee_clobbers_slot, 1, "0");
	/* What is released through one call or on one path and not through another. */
	RUN_AS(throw_irq_order, "throw_irq_order_enabled_first", THROWN, 2, "10s", .param = 1);
	RUN_AS(throw_irq_order, "throw_irq_order_enabled_last", THROWN, 2, "01", .param = 0);
	/* A recursive subprog holding an object per frame: each frame owns its own. */
	THROW(throw_recursion_holding, 4, "3210");
	/* what the frames hold at call depth two */
	RUN_AS(throw_ringbuf_depth2_split, "throw_ringbuf_depth2_split_held", THROWN, 1, "0",
	       .param = 3);
	RUN_AS(throw_ringbuf_depth2_split, "throw_ringbuf_depth2_split_free", THROWN, 1, "",
	       .param = 1);
	/* a throw reached by paths of different stack depth */
	RUN_AS(throw_slot_unallocated, "throw_slot_unallocated_held", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_slot_unallocated, "throw_slot_unallocated_free", THROWN, 0, "", .param = 1);
	/* a reference that may be NULL when a callee throws */
	RUN_AS(throw_task_maybe_null, "throw_task_maybe_null_null", THROWN, 1, "", .param = 1);
	RUN_AS(throw_task_maybe_null, "throw_task_maybe_null_held", THROWN, 1, "0", .param = 3);
	/* a reference held as a pointer into the object */
	RUN_AS(throw_pop_null, "throw_pop_null_popped", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_pop_null, "throw_pop_null_empty", THROWN, 0, "", .param = 1);
	/* A spill the verifier removes is not where the unwinder looks. */
	RUN_AS(throw_fastcall_spill, "throw_fastcall_spill_throw", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_fastcall_spill, "throw_fastcall_spill_discard", 0, 1, "", .param = 1);
	/* A reference a subprog returns is the caller's from the call on. */
	THROW(throw_obj_returned, 1, "0");
	/* One call that takes the object on one path and NULL on the other. */
	RUN_AS(throw_xchg_maybe, "throw_xchg_maybe_kept", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_xchg_maybe, "throw_xchg_maybe_given", THROWN, 1, "", .param = 1);
	/* What the frames keep in their own stack at the throw is released from there. */
	THROW(throw_spilled, 1, "0");
	RUN_AS(throw_spilled_caller, "throw_spilled_caller_throw", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_spilled_caller, "throw_spilled_caller_return", 0, 1, "", .param = 1);
	RUN_AS(throw_spilled_node, "throw_spilled_node_popped", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_spilled_node, "throw_spilled_node_empty", THROWN, 0, "", .param = 1);
	RUN_AS(throw_spilled_some_paths, "throw_spilled_some_paths_reg", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_spilled_some_paths, "throw_spilled_some_paths_stack", THROWN, 1, "0",
	       .param = 1);
	/* The sections the frames are in, counted where the paths to a throw differ. */
	THROW(throw_callee_left_rcu, 1, "0");
	RUN_AS(throw_rcu_some_paths, "throw_rcu_some_paths_in", THROWN, 0, "s", .param = 1);
	RUN_AS(throw_rcu_some_paths, "throw_rcu_some_paths_out", THROWN, 0, "", .param = 0);
	/* What the frames keep in registers at the throw is released from them. */
	THROW(throw_regs_callers, 3, "201");
	THROW(throw_reg_caller_saved, 1, "0");
	RUN_AS(throw_reg_node, "throw_reg_node_popped", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_reg_node, "throw_reg_node_empty", THROWN, 0, "", .param = 1);
	/* A callee releases what its caller holds: a throw finds it held, or released. */
	RUN_AS(throw_callee_releases, "throw_callee_releases_before", THROWN, 1, "0", .param = 1);
	RUN_AS(throw_callee_releases, "throw_callee_releases_after", THROWN, 1, "", .param = 2);
	RUN_AS(throw_callee_releases, "throw_callee_releases_return", 0, 1, "", .param = 0);
	/* A callee that is handed what it releases holds it from the call on. */
	RUN_AS(throw_callee_consumes, "throw_callee_consumes_before", THROWN, 1, "0", .param = 1);
	RUN_AS(throw_callee_consumes, "throw_callee_consumes_after", THROWN, 1, "", .param = 2);
	RUN_AS(throw_callee_consumes, "throw_callee_consumes_return", 0, 1, "", .param = 0);
	/* the caller keeps it in a slot, which the call empties */
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_caller_r6", THROWN,
	       1, "0", .param = 3);
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_caller_r9", THROWN,
	       1, "0", .param = 11);
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_callee_r6", THROWN,
	       1, "0", .param = 1);
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_callee_r9", THROWN,
	       1, "0", .param = 9);
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_after", THROWN,
	       1, "", .param = 10);
	RUN_AS(throw_callee_consumes_from_slot, "throw_callee_consumes_from_slot_return", 0,
	       1, "", .param = 8);
	/* the callee has it nowhere at its throw and keeps it in a slot of its own */
	RUN_AS(throw_callee_consumes_slot, "throw_callee_consumes_slot_throw", THROWN, 1, "0",
	       .param = 1);
	RUN_AS(throw_callee_consumes_slot, "throw_callee_consumes_slot_return", 0, 1, "",
	       .param = 0);
	/* A lock a callee unlocks leaves the slot of the caller in front of the call. */
	RUN_AS(throw_callee_unlocks, "throw_callee_unlocks_before", THROWN, 1, "0", .param = 1);
	RUN_AS(throw_callee_unlocks, "throw_callee_unlocks_after", THROWN, 1, "", .param = 2);
	RUN_AS(throw_callee_unlocks, "throw_callee_unlocks_return", 0, 1, "", .param = 0);
	/* A file and the reader of its dynptr, which goes first. */
	snprintf(name, sizeof(name), "%sthrow_file_dynptr_held", prefix);
	if (test__start_subtest(name))
		run_file(skel, &(struct expect){ .acquired = 1, .released = "s0", .param = 0 });
	snprintf(name, sizeof(name), "%sthrow_file_dynptr_released", prefix);
	if (test__start_subtest(name))
		run_file(skel, &(struct expect){ .acquired = 1, .released = "", .param = 1 });
	/* A reference the kernel passed in a __ref argument, held at the throw or released before it. */
	snprintf(name, sizeof(name), "%sthrow_ops_ref_held", prefix);
	if (test__start_subtest(name))
		run_struct_ops(skel, &(struct expect){ .acquired = 1, .released = "0", .param = 0 });
	snprintf(name, sizeof(name), "%sthrow_ops_ref_released", prefix);
	if (test__start_subtest(name))
		run_struct_ops(skel, &(struct expect){ .acquired = 1, .released = "", .param = 1 });
#undef THROW
#undef RUN
#undef RUN_AS
out:
	if (server >= 0)
		close(server);
	exceptions_cleanup__destroy(skel);
}

/* Serial, because it sets bpf_jit_harden. */
void serial_test_exceptions_cleanup(void)
{
	const char *harden = "/proc/sys/net/core/bpf_jit_harden";
	char old[16] = {};

#if !defined(__x86_64__) && !defined(__aarch64__)
	/* elsewhere a program may not throw while it holds resources */
	test__skip();
	return;
#endif
	run_suite("");
	/*
	 * Constant blinding rewrites the program, with the insns that keep the
	 * slots in it, and moves the calls the sites are at.
	 */
	if (sysctl_set_or_fail(harden, old, "2"))
		return;
	run_suite("harden_");
	sysctl_set_or_fail(harden, NULL, old);
}
