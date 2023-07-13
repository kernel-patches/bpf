// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions.skel.h"
#include "exceptions_ext.skel.h"
#include "exceptions_fail.skel.h"

static char log_buf[1024 * 1024];

static void test_exceptions_failure(void)
{
	RUN_TESTS(exceptions_fail);
}

static void test_exceptions_success(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct exceptions_ext *eskel = NULL;
	struct exceptions *skel;
	int ret;

	skel = exceptions__open();
	if (!ASSERT_OK_PTR(skel, "exceptions__open"))
		return;

	ret = exceptions__load(skel);
	if (!ASSERT_OK(ret, "exceptions__load"))
		goto done;

	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.jmp_table), &(int){0},
					   &(int){bpf_program__fd(skel->progs.exception_tail_call_target)}, BPF_ANY),
		       "bpf_map_update_elem jmp_table"))
		goto done;

#define RUN_SUCCESS(_prog, return_val)						  \
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs._prog), &ropts); \
	ASSERT_OK(ret, #_prog " prog run ret");					  \
	ASSERT_EQ(ropts.retval, return_val, #_prog " prog run retval");

	RUN_SUCCESS(exception_throw_subprog, 16);
	RUN_SUCCESS(exception_throw, 0);
	RUN_SUCCESS(exception_throw_gfunc1, 1);
	RUN_SUCCESS(exception_throw_gfunc2, 0);
	RUN_SUCCESS(exception_throw_gfunc3, 1);
	RUN_SUCCESS(exception_throw_gfunc4, 0);
	RUN_SUCCESS(exception_throw_gfunc5, 1);
	RUN_SUCCESS(exception_throw_gfunc6, 16);
	RUN_SUCCESS(exception_throw_func1, 1);
	RUN_SUCCESS(exception_throw_func2, 0);
	RUN_SUCCESS(exception_throw_func3, 1);
	RUN_SUCCESS(exception_throw_func4, 0);
	RUN_SUCCESS(exception_throw_func5, 1);
	RUN_SUCCESS(exception_throw_func6, 16);
	RUN_SUCCESS(exception_tail_call, 50);
	RUN_SUCCESS(exception_ext, 5);
	RUN_SUCCESS(exception_throw_value, 60);
	RUN_SUCCESS(exception_assert_eq, 16);
	RUN_SUCCESS(exception_assert_ne, 16);
	RUN_SUCCESS(exception_assert_lt, 16);
	RUN_SUCCESS(exception_assert_gt, 16);
	RUN_SUCCESS(exception_assert_le, 16);
	RUN_SUCCESS(exception_assert_ge, 16);
	RUN_SUCCESS(exception_assert_eq_ok, 6);
	RUN_SUCCESS(exception_assert_ne_ok, 6);
	RUN_SUCCESS(exception_assert_lt_ok, 6);
	RUN_SUCCESS(exception_assert_gt_ok, 6);
	RUN_SUCCESS(exception_assert_le_ok, 6);
	RUN_SUCCESS(exception_assert_ge_ok, 6);
	RUN_SUCCESS(exception_assert_eq_value, 42);
	RUN_SUCCESS(exception_assert_ne_value, 42);
	RUN_SUCCESS(exception_assert_lt_value, 42);
	RUN_SUCCESS(exception_assert_gt_value, 42);
	RUN_SUCCESS(exception_assert_le_value, 42);
	RUN_SUCCESS(exception_assert_ge_value, 42);
	RUN_SUCCESS(exception_assert_eq_ok_value, 5);
	RUN_SUCCESS(exception_assert_ne_ok_value, 5);
	RUN_SUCCESS(exception_assert_lt_ok_value, 5);
	RUN_SUCCESS(exception_assert_gt_ok_value, 5);
	RUN_SUCCESS(exception_assert_le_ok_value, 5);
	RUN_SUCCESS(exception_assert_ge_ok_value, 5);

#define RUN_EXT(load_ret, attach_err, expr, msg, after_link)			  \
	{									  \
		LIBBPF_OPTS(bpf_object_open_opts, o, .kernel_log_buf = log_buf,		 \
						     .kernel_log_size = sizeof(log_buf), \
						     .kernel_log_level = 2);		 \
		exceptions_ext__destroy(eskel);					  \
		eskel = exceptions_ext__open_opts(&o);				  \
		struct bpf_program *prog = NULL;				  \
		struct bpf_link *link = NULL;					  \
		if (!ASSERT_OK_PTR(eskel, "exceptions_ext__open"))		  \
			goto done;						  \
		(expr);								  \
		ASSERT_OK_PTR(bpf_program__name(prog), bpf_program__name(prog));  \
		if (!ASSERT_EQ(exceptions_ext__load(eskel), load_ret,		  \
			       "exceptions_ext__load"))	{			  \
			printf("%s\n", log_buf);				  \
			goto done;						  \
		}								  \
		if (load_ret != 0) {						  \
			printf("%s\n", log_buf);				  \
			if (!ASSERT_OK_PTR(strstr(log_buf, msg), "strstr"))	  \
				goto done;					  \
		}								  \
		if (!load_ret && attach_err) {					  \
			if (!ASSERT_ERR_PTR(link = bpf_program__attach(prog), "attach err")) \
				goto done;					  \
		} else if (!load_ret) {						  \
			if (!ASSERT_OK_PTR(link = bpf_program__attach(prog), "attach ok"))  \
				goto done;					  \
			(void)(after_link);					  \
			bpf_link__destroy(link);				  \
		}								  \
	}

	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_ext),
			       "exception_ext_global"), "set_attach_target"))
			goto done;
	}), "", ({ RUN_SUCCESS(exception_ext, 0); }));

	/* non-throwing fexit -> non-throwing subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.pfexit;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* throwing fexit -> non-throwing subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_fexit;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* non-throwing fexit -> throwing subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.pfexit;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "throwing_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* throwing fexit -> throwing subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_fexit;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "throwing_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* fmod_ret not allowed for subprog - Check so we remember to handle its
	 * throwing specification compatibility with target when supported.
	 */
	RUN_EXT(-EINVAL, false, ({
		prog = eskel->progs.pfmod_ret;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "subprog"), "set_attach_target"))
			goto done;
	}), "can't modify return codes of BPF program", (void)0);

	/* fmod_ret not allowed for subprog - Check so we remember to handle its
	 * throwing specification compatibility with target when supported.
	 */
	RUN_EXT(-EINVAL, false, ({
		prog = eskel->progs.pfmod_ret;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "global_subprog"), "set_attach_target"))
			goto done;
	}), "can't modify return codes of BPF program", (void)0);

	/* non-throwing extension -> non-throwing subprog : BAD (!global) */
	RUN_EXT(-EINVAL, true, ({
		prog = eskel->progs.extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "subprog"), "set_attach_target"))
			goto done;
	}), "subprog() is not a global function", (void)0);

	/* non-throwing extension -> throwing subprog : BAD (!global) */
	RUN_EXT(-EINVAL, true, ({
		prog = eskel->progs.extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "throwing_subprog"), "set_attach_target"))
			goto done;
	}), "throwing_subprog() is not a global function", (void)0);

	/* non-throwing extension -> non-throwing global subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "global_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* non-throwing extension -> throwing global subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "throwing_global_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* throwing extension -> throwing global subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "throwing_global_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* throwing extension -> main subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "exception_throw_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);

	/* throwing extension -> non-throwing global subprog : OK */
	RUN_EXT(0, false, ({
		prog = eskel->progs.throwing_extension;
		bpf_program__set_autoload(prog, true);
		if (!ASSERT_OK(bpf_program__set_attach_target(prog,
			       bpf_program__fd(skel->progs.exception_throw_subprog),
			       "global_subprog"), "set_attach_target"))
			goto done;
	}), "", (void)0);
done:
	exceptions_ext__destroy(eskel);
	exceptions__destroy(skel);
}

void test_exceptions(void)
{
	test_exceptions_success();
	test_exceptions_failure();
}
