// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "trace_helpers.h"
#include "fgraph_trampoline.skel.h"

#define TRACER_GRAPH	"function_graph"

#define FTRACE_NOTRACE	"*printk* *console* *wake* *serial* *lock*"
#define GRAPH_FUNCS	"bpf_prog_test*"

/* See test_run.c: we are overriding bpf_modify_return_test with a program
 * returning 5, but not bpf_modify_return_test2
 */
#define FMOD_EXPECTED_RETVAL ((1 << 16) | (5 + 1 + 3 + 3 + 4 + 5 + 6 + 7))

static int configure_tracer(struct tracefs_ctl *ftrace)
{
	int err;

	err = tracefs_ctl_filter_write(ftrace, "set_ftrace_filter", "");
	if (err)
		return err;
	err = tracefs_ctl_filter_write(ftrace, "set_ftrace_notrace",
				       FTRACE_NOTRACE);
	if (err)
		return err;
	err = tracefs_ctl_filter_write(ftrace, "set_graph_function", GRAPH_FUNCS);
	if (err)
		return err;
	err = tracefs_ctl_filter_write(ftrace, "set_graph_notrace", "");
	if (err)
		return err;
	err = tracefs_ctl_set(ftrace, "current_tracer", TRACER_GRAPH);
	if (err)
		return err;

	return err;
}

static int run_test_under_ftrace_graph(struct tracefs_ctl *ftrace,
				       struct bpf_program *prog, int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err, stop_err;

	err = tracefs_ctl_set(ftrace, "tracing_on", "1");
	if (err)
		return err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (retval)
		*retval = opts.retval;

	stop_err = tracefs_ctl_set(ftrace, "tracing_on", "0");
	if (!err)
		err = stop_err;

	return err;
}

void serial_test_fgraph_trampoline(void)
{
	struct fgraph_trampoline *skel = NULL;
	struct tracefs_ctl *ftrace;
	int retval;

	ftrace = tracefs_ctl_init();
	if (!ASSERT_OK_PTR(ftrace, "tracefs_ctl_init"))
		return;

	if (configure_tracer(ftrace)) {
		test__skip();
		tracefs_ctl_restore(ftrace);
		goto cleanup;
	}

	skel = fgraph_trampoline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fgraph_trampoline__open_and_load"))
		goto cleanup;

	if (test__start_subtest("no_trampoline")) {
		ASSERT_OK(run_test_under_ftrace_graph(ftrace,
						      skel->progs.fentry_test1,
						      NULL),
			  "run test no trampoline");
	}

	if (test__start_subtest("attach_fentry_fexit")) {
		skel->links.fentry_test1 =
			bpf_program__attach(skel->progs.fentry_test1);
		if (!ASSERT_OK_PTR(skel->links.fentry_test1, "attach_fentry"))
			goto destroy_cleanup;
		skel->links.fexit_test1 =
			bpf_program__attach(skel->progs.fexit_test1);
		if (!ASSERT_OK_PTR(skel->links.fexit_test1, "attach_fexit"))
			goto destroy_cleanup;

		memset(skel->bss, 0, sizeof(*skel->bss));
		ASSERT_OK(run_test_under_ftrace_graph(ftrace,
						      skel->progs.fentry_test1,
						      NULL),
			  "run test with fentry and fexit");

		ASSERT_EQ(skel->bss->fexit_result, 1, "fexit_result");

		fgraph_trampoline__detach(skel);
	}

	if (test__start_subtest("attach_fmod_ret")) {
		skel->links.fmod_ret_test =
			bpf_program__attach(skel->progs.fmod_ret_test);
		if (!ASSERT_OK_PTR(skel->links.fmod_ret_test, "attach_fmod_ret"))
			goto destroy_cleanup;

		ASSERT_OK(run_test_under_ftrace_graph(ftrace,
						      skel->progs.fmod_ret_test,
						      &retval),
			  "run test with fmod_ret");
		ASSERT_EQ(retval, FMOD_EXPECTED_RETVAL, "fmod return value");

		fgraph_trampoline__detach(skel);
	}

destroy_cleanup:
	fgraph_trampoline__destroy(skel);
cleanup:
	tracefs_ctl_restore(ftrace);
}
