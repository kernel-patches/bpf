// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "unwind_drain.skel.h"

static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

static int submit(struct user_ring_buffer *rb)
{
	void *sample = user_ring_buffer__reserve(rb, 8);

	if (!ASSERT_OK_PTR(sample, "reserve"))
		return -1;
	user_ring_buffer__submit(rb, sample);
	return 0;
}

/*
 * The callback unwinds on the sample it is given, with r0 = 5. The pad after
 * the call of bpf_user_ringbuf_drain() returns the number of runs plus 5 plus
 * 41. The sample is consumed and the busy bit dropped on the way there: the
 * next drain finds an empty ring buffer, and the one after that another
 * sample.
 */
void test_unwind_drain(void)
{
	struct user_ring_buffer *rb = NULL;
	struct unwind_drain *skel;
	int err;

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}
	skel = unwind_drain__open_and_load();
	err = libbpf_get_error(skel);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		return;
	}
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	rb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);
	if (!ASSERT_OK_PTR(rb, "user_ring_buffer__new"))
		goto out;

	ASSERT_EQ(run(skel->progs.drain), 0, "empty");
	if (submit(rb))
		goto out;
	ASSERT_EQ(run(skel->progs.drain), 47, "unwinds");
	ASSERT_EQ(run(skel->progs.drain), 0, "consumed");
	if (submit(rb))
		goto out;
	ASSERT_EQ(run(skel->progs.drain), 48, "unwinds again");
out:
	user_ring_buffer__free(rb);
	unwind_drain__destroy(skel);
}
