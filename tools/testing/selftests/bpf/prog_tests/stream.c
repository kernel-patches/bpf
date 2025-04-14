// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>

#include "stream.skel.h"
#include "stream_fail.skel.h"

#include "stream_bpftool.skel.h"

void test_stream_failure(void)
{
	RUN_TESTS(stream_fail);
}

void test_stream_success(void)
{
	RUN_TESTS(stream);
	RUN_TESTS(stream_bpftool);
	return;
}

static int process_sample(void *ctx, void *data, size_t len)
{
	fprintf(stderr, "%s", (char *)data);
	return 0;
}

void test_stream_ringbuf_output(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct ring_buffer *ringbuf;
	struct stream_bpftool *skel;
	int fd, ret;

	skel = stream_bpftool__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream_bpftool_open_and_load"))
		return;

	fd = bpf_map__fd(skel->maps.ringbuf);

	ringbuf = ring_buffer__new(fd, process_sample, NULL, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ringbuf_new"))
		goto end;

	do {
		skel->bss->written_count = skel->bss->written_size = 0;
		ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.stream_bpftool_dump_prog_stream), &opts);
		ASSERT_EQ(ring_buffer__consume_n(ringbuf, skel->bss->written_count), skel->bss->written_count, "consume");
	} while (!ret && opts.retval == EAGAIN);

	ASSERT_OK(ret, "ret");
	ASSERT_EQ(opts.retval, 0, "retval");

end:
	stream_bpftool__destroy(skel);
}
