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

typedef int (*sample_cb_t)(void *, void *, size_t);

static void stream_ringbuf_output(int prog_id, sample_cb_t sample_cb)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct ring_buffer *ringbuf;
	struct stream_bpftool *skel;
	int fd, ret;

	skel = stream_bpftool__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream_bpftool_open_and_load"))
		return;

	fd = bpf_map__fd(skel->maps.ringbuf);

	ringbuf = ring_buffer__new(fd, sample_cb, NULL, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ringbuf_new"))
		goto end;

	skel->bss->prog_id = prog_id;
	skel->bss->stream_id = 1;
	do {
		skel->bss->written_count = skel->bss->written_size = 0;
		ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.bpftool_dump_prog_stream), &opts);
		if (ret)
			break;
		ret = ring_buffer__consume_n(ringbuf, skel->bss->written_count);
		if (!ASSERT_EQ(ret, skel->bss->written_count, "consume"))
			break;
		ret = 0;
	} while (opts.retval == EAGAIN);

	ASSERT_OK(ret, "ret");
	ASSERT_EQ(opts.retval, 0, "retval");

end:
	stream_bpftool__destroy(skel);
}

int cnt = 0;

static int process_sample(void *ctx, void *data, size_t len)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "num=%d\n", cnt++);
	ASSERT_TRUE(strcmp(buf, (char *)data) == 0, "sample strcmp");
	return 0;
}

void test_stream_output(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct stream *skel;
	int ret;

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.stream_test_output), &info, &info_len), "get info");
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.stream_test_output), &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");
	stream_ringbuf_output(info.id, process_sample);

	ASSERT_EQ(cnt, 1000, "cnt");

	stream__destroy(skel);
	return;
}
