// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/epoll.h>
#include "test_ringbuf_multi.skel.h"

static int duration = 0;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

static int process_sample(void *ctx, void *data, size_t len)
{
	int ring = (unsigned long)ctx;
	struct sample *s = data;

	switch (s->seq) {
	case 0:
		CHECK(ring != 1, "sample1_ring", "exp %d, got %d\n", 1, ring);
		CHECK(s->value != 333, "sample1_value", "exp %ld, got %ld\n",
		      333L, s->value);
		break;
	case 1:
		CHECK(ring != 2, "sample2_ring", "exp %d, got %d\n", 2, ring);
		CHECK(s->value != 777, "sample2_value", "exp %ld, got %ld\n",
		      777L, s->value);
		break;
	default:
		CHECK(true, "extra_sample", "unexpected sample seq %d, val %ld\n",
		      s->seq, s->value);
		return -1;
	}

	return 0;
}

static int process_sample_override(void *ctx, void *data, size_t len)
{
	struct sample *s = data;
	int *cnt = ctx;

	if (!ASSERT_LT(s->seq, 2, "override_sample_seq"))
		return -EINVAL;
	ASSERT_EQ(s->value, s->seq ? 777L : 333L, "override_sample_value");
	(*cnt)++;

	return 0;
}

static void trigger_samples(struct test_ringbuf_multi *skel)
{
	skel->bss->total = 0;
	skel->bss->target_ring = 0;
	skel->bss->value = 333;
	syscall(__NR_getpgid);
	skel->bss->target_ring = 2;
	skel->bss->value = 777;
	syscall(__NR_getpgid);
}

void test_ringbuf_multi(void)
{
	struct test_ringbuf_multi *skel;
	struct ring_buffer *ringbuf = NULL;
	struct ring *ring_old;
	struct ring *ring;
	int override_cnt = 0;
	int err;
	int page_size = getpagesize();
	int proto_fd = -1;

	skel = test_ringbuf_multi__open();
	if (CHECK(!skel, "skel_open", "skeleton open failed\n"))
		return;

	/* validate ringbuf size adjustment logic */
	ASSERT_EQ(bpf_map__max_entries(skel->maps.ringbuf1), page_size, "rb1_size_before");
	ASSERT_OK(bpf_map__set_max_entries(skel->maps.ringbuf1, page_size + 1), "rb1_resize");
	ASSERT_EQ(bpf_map__max_entries(skel->maps.ringbuf1), 2 * page_size, "rb1_size_after");
	ASSERT_OK(bpf_map__set_max_entries(skel->maps.ringbuf1, page_size), "rb1_reset");
	ASSERT_EQ(bpf_map__max_entries(skel->maps.ringbuf1), page_size, "rb1_size_final");

	proto_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, page_size, NULL);
	if (CHECK(proto_fd < 0, "bpf_map_create", "bpf_map_create failed\n"))
		goto cleanup;

	err = bpf_map__set_inner_map_fd(skel->maps.ringbuf_hash, proto_fd);
	if (CHECK(err != 0, "bpf_map__set_inner_map_fd", "bpf_map__set_inner_map_fd failed\n"))
		goto cleanup;

	err = test_ringbuf_multi__load(skel);
	if (CHECK(err != 0, "skel_load", "skeleton load failed\n"))
		goto cleanup;

	close(proto_fd);
	proto_fd = -1;

	/* make sure we can't resize ringbuf after object load */
	if (!ASSERT_ERR(bpf_map__set_max_entries(skel->maps.ringbuf1, 3 * page_size), "rb1_resize_after_load"))
		goto cleanup;

	/* only trigger BPF program for current process */
	skel->bss->pid = getpid();

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf1),
				   process_sample, (void *)(long)1, NULL);
	if (CHECK(!ringbuf, "ringbuf_create", "failed to create ringbuf\n"))
		goto cleanup;

	/* verify ring_buffer__ring returns expected results */
	ring = ring_buffer__ring(ringbuf, 0);
	if (!ASSERT_OK_PTR(ring, "ring_buffer__ring_idx_0"))
		goto cleanup;
	ring_old = ring;
	ring = ring_buffer__ring(ringbuf, 1);
	ASSERT_ERR_PTR(ring, "ring_buffer__ring_idx_1");

	err = ring_buffer__add(ringbuf, bpf_map__fd(skel->maps.ringbuf2),
			      process_sample, (void *)(long)2);
	if (CHECK(err, "ringbuf_add", "failed to add another ring\n"))
		goto cleanup;

	/* verify adding a new ring didn't invalidate our older pointer */
	ring = ring_buffer__ring(ringbuf, 0);
	if (!ASSERT_EQ(ring, ring_old, "ring_buffer__ring_again"))
		goto cleanup;

	err = test_ringbuf_multi__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attachment failed: %d\n", err))
		goto cleanup;

	/* trigger few samples, some will be skipped */
	skel->bss->target_ring = 0;
	skel->bss->value = 333;
	syscall(__NR_getpgid);

	/* skipped, no ringbuf in slot 1 */
	skel->bss->target_ring = 1;
	skel->bss->value = 555;
	syscall(__NR_getpgid);

	skel->bss->target_ring = 2;
	skel->bss->value = 777;
	syscall(__NR_getpgid);

	/* poll for samples, should get 2 ringbufs back */
	err = ring_buffer__poll(ringbuf, -1);
	if (CHECK(err != 2, "poll_res", "expected 2 records, got %d\n", err))
		goto cleanup;

	/* expect extra polling to return nothing */
	err = ring_buffer__poll(ringbuf, 0);
	if (CHECK(err < 0, "extra_samples", "poll result: %d\n", err))
		goto cleanup;

	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->skipped != 1, "err_skipped", "exp %ld, got %ld\n",
	      1L, skel->bss->skipped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);

	trigger_samples(skel);
	err = ring_buffer__consume_n(ringbuf, 0);
	if (!ASSERT_EQ(err, 0, "ringbuf_consume_zero_stored_cb"))
		goto cleanup;
	err = ring_buffer__consume_n_cb(ringbuf, NULL, NULL, 0);
	if (!ASSERT_EQ(err, -EINVAL, "ringbuf_consume_null_cb"))
		goto cleanup;
	err = ring_buffer__consume_n_cb(ringbuf, process_sample_override,
					&override_cnt, 0);
	if (!ASSERT_EQ(err, 0, "ringbuf_consume_zero"))
		goto cleanup;
	if (!ASSERT_EQ(override_cnt, 0, "ringbuf_zero_callback_count"))
		goto cleanup;
	err = ring_buffer__consume_n_cb(ringbuf, process_sample_override,
					&override_cnt, 1);
	if (!ASSERT_EQ(err, 1, "ringbuf_consume_n_cb_1"))
		goto cleanup;
	err = ring_buffer__consume_n_cb(ringbuf, process_sample_override,
					&override_cnt, 1);
	if (!ASSERT_EQ(err, 1, "ringbuf_consume_n_cb_2"))
		goto cleanup;
	if (!ASSERT_EQ(override_cnt, 2, "ringbuf_callback_count"))
		goto cleanup;

	trigger_samples(skel);
	err = ring_buffer__consume_n(ringbuf, 2);
	if (!ASSERT_EQ(err, 2, "ringbuf_consume_stored_cb"))
		goto cleanup;
	if (!ASSERT_EQ(override_cnt, 2, "ringbuf_override_not_stored"))
		goto cleanup;

	trigger_samples(skel);
	ring = ring_buffer__ring(ringbuf, 0);
	if (!ASSERT_OK_PTR(ring, "ring_buffer__ring_idx_0_cb"))
		goto cleanup;
	err = ring__consume_n(ring, 0);
	if (!ASSERT_EQ(err, 0, "ring1_consume_zero_stored_cb"))
		goto cleanup;
	err = ring__consume_n_cb(ring, NULL, NULL, 0);
	if (!ASSERT_EQ(err, -EINVAL, "ring1_consume_null_cb"))
		goto cleanup;
	err = ring__consume_n_cb(ring, process_sample_override, &override_cnt,
				 0);
	if (!ASSERT_EQ(err, 0, "ring1_consume_zero"))
		goto cleanup;
	if (!ASSERT_EQ(override_cnt, 2, "ring1_zero_callback_count"))
		goto cleanup;
	err = ring__consume_n_cb(ring, process_sample_override, &override_cnt,
				 1);
	if (!ASSERT_EQ(err, 1, "ring1_consume_n_cb"))
		goto cleanup;

	ring = ring_buffer__ring(ringbuf, 1);
	if (!ASSERT_OK_PTR(ring, "ring_buffer__ring_idx_1_cb"))
		goto cleanup;
	err = ring__consume_n_cb(ring, process_sample_override, &override_cnt,
				 1);
	if (!ASSERT_EQ(err, 1, "ring2_consume_n_cb"))
		goto cleanup;
	if (!ASSERT_EQ(override_cnt, 4, "ring_callback_count"))
		goto cleanup;

	trigger_samples(skel);
	err = ring_buffer__consume_n(ringbuf, 2);
	ASSERT_EQ(err, 2, "ring_consume_stored_cb");
	ASSERT_EQ(override_cnt, 4, "ring_override_not_stored");

cleanup:
	if (proto_fd >= 0)
		close(proto_fd);
	ring_buffer__free(ringbuf);
	test_ringbuf_multi__destroy(skel);
}
