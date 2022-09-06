// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <linux/compiler.h>
#include <asm/barrier.h>
#include <test_progs.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>
#include "test_ringbuf_overwritable.lskel.h"

struct sample {
	int count;
	/*
	 * filler size will be computed to have 8 samples in a 4096 bytes long
	 * buffer.
	 */
	char filler[4096 / 8 - sizeof(int) - 8];
};

struct ring {
	ring_buffer_sample_fn sample_cb;
	__u8 overwritable: 1,
	     __reserved:   7;
	void *ctx;
	void *data;
	unsigned long *consumer_pos;
	unsigned long *producer_pos;
	unsigned long mask;
	int map_fd;
};

struct ring_buffer {
	struct epoll_event *events;
	struct ring *rings;
	size_t page_size;
	int epoll_fd;
	int ring_cnt;
};

static int duration;
static struct test_ringbuf_overwritable_lskel *skel;

void test_ringbuf_overwritable(void)
{
	const size_t rec_sz = BPF_RINGBUF_HDR_SZ + sizeof(struct sample);
	int page_size = getpagesize();
	int sample_cnt = 0, sample_read = 0;
	unsigned long mask = page_size - 1;
	struct ring_buffer *ringbuf;
	int err, *len_ptr, len;
	struct sample *sample;
	long read_pos;
	void *data_ptr;

	skel = test_ringbuf_overwritable_lskel__open();
	if (CHECK(!skel, "skel_open", "skeleton open failed\n"))
		return;

	skel->maps.ringbuf.max_entries = page_size;

	err = test_ringbuf_overwritable_lskel__load(skel);
	if (CHECK(err != 0, "skel_load", "skeleton load failed\n"))
		goto cleanup;

	/* only trigger BPF program for current process */
	skel->bss->pid = getpid();

	ringbuf = ring_buffer__new(skel->maps.ringbuf.map_fd, NULL, NULL, NULL);
	if (CHECK(!ringbuf, "ringbuf_create", "failed to create ringbuf\n"))
		goto cleanup;

	/* There is only one ring in this ringbuf. */
	data_ptr = ringbuf->rings[0].data;

	err = test_ringbuf_overwritable_lskel__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attachment failed: %d\n", err))
		goto cleanup;

	/* Trigger one sample. */
	syscall(__NR_getpgid);
	sample_cnt++;

	CHECK(skel->bss->avail_data != -EINVAL,
	      "err_avail_size", "exp %d, got %ld\n",
	      -EINVAL, skel->bss->avail_data);
	CHECK(skel->bss->ring_size != page_size,
	      "err_ring_size", "exp %ld, got %ld\n",
	      (long)page_size, skel->bss->ring_size);
	CHECK(skel->bss->cons_pos != -EINVAL,
	      "err_cons_pos", "exp %d, got %ld\n",
	      -EINVAL, skel->bss->cons_pos);
	CHECK(skel->bss->prod_pos != sample_cnt * -rec_sz,
	      "err_prod_pos", "exp %ld, got %ld\n",
	      sample_cnt * -rec_sz, skel->bss->prod_pos);

	len_ptr = data_ptr + (skel->bss->prod_pos & mask);
	len = smp_load_acquire(len_ptr);

	CHECK(len != sizeof(struct sample),
	      "err_sample_len", "exp %ld, got %d\n",
	      sizeof(struct sample), len);

	sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;

	CHECK(sample->count != sample_cnt,
	      "err_sample_cnt", "exp %d, got %d",
	      sample_cnt, sample->count);

	/* Trigger many samples, so we overwrite data */
	for (int i = 0; i < 16; i++) {
		syscall(__NR_getpgid);
		sample_cnt++;
	}

	CHECK(skel->bss->avail_data != -EINVAL,
	      "err_avail_size", "exp %d, got %ld\n",
	      -EINVAL, skel->bss->avail_data);
	CHECK(skel->bss->ring_size != page_size,
	      "err_ring_size", "exp %ld, got %ld\n",
	      (long)page_size, skel->bss->ring_size);
	CHECK(skel->bss->cons_pos != -EINVAL,
	      "err_cons_pos", "exp %d, got %ld\n",
	      -EINVAL, skel->bss->cons_pos);
	CHECK(skel->bss->prod_pos != sample_cnt * -rec_sz,
	      "err_prod_pos", "exp %ld, got %ld\n",
	      sample_cnt * -rec_sz, skel->bss->prod_pos);

	read_pos = skel->bss->prod_pos;
	sample_read = 0;
	while (read_pos - skel->bss->prod_pos < mask) {
		len_ptr = data_ptr + (read_pos & mask);
		len = smp_load_acquire(len_ptr);

		sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;

		CHECK(sample->count != sample_cnt - sample_read,
		      "err_sample_cnt", "exp %d, got %d",
		      sample_cnt - sample_read, sample->count);

		sample_read++;
		read_pos += round_up(len + BPF_RINGBUF_HDR_SZ, 8);
	}

	CHECK(sample_read != page_size / rec_sz,
	      "err_sample_read", "exp %ld, got %d",
	      page_size / rec_sz, sample_read);

	test_ringbuf_overwritable_lskel__detach(skel);
cleanup:
	ring_buffer__free(ringbuf);
	test_ringbuf_overwritable_lskel__destroy(skel);
}
