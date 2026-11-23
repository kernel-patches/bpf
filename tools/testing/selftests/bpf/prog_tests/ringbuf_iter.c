// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/epoll.h>
#include <pthread.h>
#include "test_ringbuf_iter.skel.h"

/* Mirrors the context of the producer programs. */
struct produce_args {
	__u64 seq;
	__u32 count;
	__u32 size;
	__u32 discard_mod;
	__u32 flags;
	__u32 produced;
};

static int page_size;

static int produce(int prog_fd, struct produce_args *args)
{
	/* Syscall programs copy the context back into ctx_in. */
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = args,
		.ctx_size_in = sizeof(*args),
	);
	int err;

	args->produced = 0;
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "produce_run") || !ASSERT_OK(opts.retval, "produce_retval") ||
	    !ASSERT_EQ(args->produced, args->count, "produced"))
		return -1;
	return 0;
}

/*
 * Produce `count` records of `size` bytes. Every 8-byte word of a record holds
 * its sequence number, and sequence numbers start at `seq`.
 */
static int produce_n(int prog_fd, __u64 seq, __u32 count, __u32 size)
{
	struct produce_args args = { .seq = seq, .count = count, .size = size };

	return produce(prog_fd, &args);
}

/* Check that every 8-byte word of a record holds `seq`. */
static bool record_ok(const void *data, __u32 len, __u64 seq)
{
	const __u64 *w = data;
	__u32 i;

	if (len % 8)
		return false;
	for (i = 0; i < len / 8; i++) {
		if (w[i] != seq)
			return false;
	}
	return true;
}

/* ASSERT_OK_PTR() passes for NULL when errno is 0, and an empty ring doesn't set errno */
static const struct ring_rec *next_rec(struct ring *r, const char *name)
{
	const struct ring_rec *rec = ring__next(r);

	ASSERT_TRUE(rec != NULL, name);
	return rec;
}

static int count_cb(void *ctx, void *data, size_t len)
{
	(*(int *)ctx)++;
	return 0;
}

static struct test_ringbuf_iter *open_load(size_t normal_sz, size_t overwrite_sz)
{
	struct test_ringbuf_iter *skel;
	int err;

	skel = test_ringbuf_iter__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return NULL;
	bpf_map__set_max_entries(skel->maps.ringbuf, normal_sz);
	bpf_map__set_max_entries(skel->maps.ringbuf_ow, overwrite_sz);
	err = test_ringbuf_iter__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		test_ringbuf_iter__destroy(skel);
		return NULL;
	}
	return skel;
}

static void subtest_basic(void)
{
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring_rec first = {};
	struct ring_buffer *rb;
	unsigned long cons;
	struct ring *r;
	int prog_fd, i;

	skel = open_load(4 * page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	r = ring_buffer__ring(rb, 0);

	/* Nothing to consume in an empty ring, and that is not an error. */
	errno = 0;
	ASSERT_NULL(ring__next(r), "next_empty");
	ASSERT_EQ(errno, 0, "next_empty_errno");
	ASSERT_EQ(ring__release(r), 0, "release_empty");

	/* Records of different sizes, including empty ones. */
	if (produce_n(prog_fd, 0, 10, 8) || produce_n(prog_fd, 10, 10, 0) ||
	    produce_n(prog_fd, 20, 10, 120) || produce_n(prog_fd, 30, 10, 256))
		goto out_rb;

	cons = ring__consumer_pos(r);
	for (i = 0; i < 40; i++) {
		rec = next_rec(r, "next");
		if (!rec)
			goto out_rb;
		ASSERT_EQ(rec->len, i < 10 ? 8 : i < 20 ? 0 : i < 30 ? 120 : 256, "rec_len");
		ASSERT_TRUE(record_ok(rec->data, rec->len, i), "rec_data");
		if (i == 0)
			first = *rec;
	}
	ASSERT_NULL(ring__next(r), "next_drained");
	/* Records are not consumed until they are released, and stay valid until then. */
	ASSERT_EQ(ring__consumer_pos(r), cons, "cons_unchanged");
	ASSERT_EQ(first.pos, cons, "first_rec_pos");
	ASSERT_TRUE(record_ok(first.data, first.len, 0), "first_rec_data");
	/* Records of a regular ring are never overwritten. */
	ASSERT_FALSE(ring__invalidated(r), "invalidated");

	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

	/* ring__release() consumes only the returned records, and tells if there are more. */
	if (produce_n(prog_fd, 40, 2, 16))
		goto out_rb;
	rec = next_rec(r, "next_partial");
	if (!rec)
		goto out_rb;
	ASSERT_EQ(ring__release(r), 1, "release_partial");
	ASSERT_EQ(ring__consumer_pos(r), rec->pos + BPF_RINGBUF_HDR_SZ + 16, "cons_partial");
	rec = next_rec(r, "next_rest");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 41), "rest_data");
	ASSERT_NULL(ring__next(r), "next_rest_end");
	ASSERT_EQ(ring__release(r), 0, "release_rest");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_rewind_discard(void)
{
	struct produce_args args = { .seq = 0, .count = 20, .size = 32, .discard_mod = 4 };
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring_buffer *rb;
	struct ring *r;
	int prog_fd, i;
	__u64 seq;

	skel = open_load(4 * page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	r = ring_buffer__ring(rb, 0);

	/* Every 4th record is discarded: seq 0, 4, 8, 12, 16 never show up. */
	if (produce(prog_fd, &args))
		goto out_rb;

	/* Rewind after three records, and get all records from the first one again. */
	for (i = 0; i < 3; i++)
		ASSERT_TRUE(ring__next(r) != NULL, "next_before_rewind");
	ring__rewind(r);
	for (seq = 1; seq < 20; seq++) {
		if (seq % 4 == 0)
			continue;
		rec = next_rec(r, "next");
		if (!rec)
			goto out_rb;
		ASSERT_TRUE(record_ok(rec->data, rec->len, seq), "rec_data");
	}
	ASSERT_NULL(ring__next(r), "next_end");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

	/* A discarded record at the end is skipped and consumed as well. */
	args.seq = 20;
	args.count = 1;
	args.discard_mod = 1;
	if (produce(prog_fd, &args))
		goto out_rb;
	ASSERT_NULL(ring__next(r), "next_only_discarded");
	ASSERT_EQ(ring__release(r), 0, "release_discarded");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_past_discarded");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Wait with ring_buffer__wait() and consume with ring__next(). */
static void subtest_manager(void)
{
	struct test_ringbuf_iter *skel;
	struct ring_buffer *rb;
	struct ring *r_cb, *r_ow;
	int normal_fd, ow_fd, cb_cnt = 0;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	normal_fd = bpf_program__fd(skel->progs.produce_normal);
	ow_fd = bpf_program__fd(skel->progs.produce_overwrite);

	/* The regular ring has a callback, the overwritable one doesn't. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), count_cb, &cb_cnt, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	if (!ASSERT_OK(ring_buffer__add(rb, bpf_map__fd(skel->maps.ringbuf_ow), NULL, NULL),
		       "ring_buffer__add"))
		goto out_rb;
	r_cb = ring_buffer__ring(rb, 0);
	r_ow = ring_buffer__ring(rb, 1);

	/* A ring with a callback can't be used with ring__next(). */
	errno = 0;
	ASSERT_NULL(ring__next(r_cb), "next_cb_ring");
	ASSERT_EQ(errno, EINVAL, "next_cb_ring_errno");
	ASSERT_EQ(ring__release(r_cb), -EINVAL, "release_cb_ring");

	/* ring__free() only warns for a ring that is owned by a manager; r_ow is used below. */
	ring__free(r_ow);

	/* ring_buffer__wait() returns the number of rings with data and consumes nothing. */
	ASSERT_EQ(ring_buffer__wait(rb, 0), 0, "wait_empty");
	if (produce_n(ow_fd, 0, 2, 16))
		goto out_rb;
	ASSERT_EQ(ring_buffer__wait(rb, 1000), 1, "wait_one");
	if (produce_n(normal_fd, 0, 3, 16))
		goto out_rb;
	ASSERT_EQ(ring_buffer__wait(rb, 1000), 2, "wait_both");
	ASSERT_EQ(cb_cnt, 0, "wait_cb_not_called");

	/* The data is consumed afterwards, through the callback or with ring__next(). */
	ASSERT_EQ(ring__consume(r_cb), 3, "consume");
	ASSERT_EQ(cb_cnt, 3, "consume_cb");
	ASSERT_TRUE(ring__next(r_ow) != NULL, "next1");
	ASSERT_TRUE(ring__next(r_ow) != NULL, "next2");
	ASSERT_NULL(ring__next(r_ow), "next_end");
	/* A ring has data until its records are released. */
	ASSERT_EQ(ring_buffer__wait(rb, 0), 1, "wait_unreleased");
	ASSERT_EQ(ring__release(r_ow), 0, "release");
	ASSERT_EQ(ring_buffer__wait(rb, 0), 0, "wait_released");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_standalone(void)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	int prog_fd, epfd, arr_fd;
	struct ring *r, *bad;
	__u64 seq = 0;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	/* ring__new() only takes ring buffer maps. */
	arr_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(arr_fd, "array_create"))
		goto out;
	bad = ring__new(arr_fd, NULL);
	ASSERT_ERR_PTR(bad, "ring__new_array");
	ASSERT_EQ(errno, EINVAL, "ring__new_array_errno");
	close(arr_fd);

	r = ring__new(bpf_map__fd(skel->maps.ringbuf), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	/* Wait with edge-triggered epoll on the map fd. */
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (!ASSERT_OK_FD(epfd, "epoll_create1"))
		goto out_ring;
	if (!ASSERT_OK(epoll_ctl(epfd, EPOLL_CTL_ADD, ring__map_fd(r), &ev), "epoll_ctl"))
		goto out_epoll;

	if (produce_n(prog_fd, 0, 5, 16))
		goto out_epoll;
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 1000), 1, "epoll_ready");
	do {
		while ((rec = ring__next(r)))
			ASSERT_TRUE(record_ok(rec->data, rec->len, seq++), "rec_data");
	} while (ring__release(r) > 0);
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

	/* The records were released, so the next record wakes us up again. */
	if (produce_n(prog_fd, 5, 1, 16))
		goto out_epoll;
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 1000), 1, "epoll_ready_again");

out_epoll:
	close(epfd);
out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Only the most recent records are left in an overwritable ring. */
static void subtest_overwrite_basic(void)
{
	__u32 size = 120, rec_sz = size + BPF_RINGBUF_HDR_SZ, per_ring = page_size / rec_sz;
	struct test_ringbuf_iter *skel;
	unsigned long next_pos, lost;
	const struct ring_rec *rec;
	struct ring *r;
	int prog_fd, n = 0;
	__u64 seq = 0;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	/* Fill the ring 3 times over. */
	if (produce_n(prog_fd, 0, 3 * per_ring, size))
		goto out_ring;
	ASSERT_LE(ring__avail_data_size(r), page_size, "avail_data_size");

	next_pos = ring__consumer_pos(r);
	while ((rec = ring__next(r))) {
		/*
		 * The API doesn't report how many bytes were overwritten before a
		 * record. It is the distance from the end of the previous record.
		 */
		lost = rec->pos - next_pos;
		next_pos = rec->pos + rec_sz;
		/* All records before the first one that is left were overwritten. */
		if (n++ == 0)
			seq = lost / rec_sz;
		else
			ASSERT_EQ(lost, 0, "lost_bytes");
		ASSERT_TRUE(record_ok(rec->data, rec->len, seq++), "rec_data");
	}
	/* The ring holds at most per_ring records, and the last one is the newest. */
	ASSERT_GT(n, 0, "records");
	ASSERT_LE(n, per_ring, "records_in_ring");
	ASSERT_EQ(seq, 3 * per_ring, "newest_record");
	ASSERT_FALSE(ring__invalidated(r), "invalidated");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/*
 * ring__invalidated() covers all records returned since the last release or
 * rewind. Records take 64 bytes. The kernel keeps less than a ring size of
 * records, so the ring is full with per_ring of them, and every new record
 * overwrites the oldest one.
 */
static void subtest_overwrite_batch(void)
{
	__u32 size = 56, rec_sz = size + BPF_RINGBUF_HDR_SZ, per_ring = page_size / rec_sz - 1;
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	__u64 seq, next_seq;
	struct ring *r;
	int prog_fd, i;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	if (produce_n(prog_fd, 0, per_ring, size))
		goto out_ring;
	seq = per_ring;

	/* No records were returned yet. */
	ASSERT_FALSE(ring__invalidated(r), "invalidated_nothing");

	for (i = 0; i < 4; i++)
		ASSERT_TRUE(ring__next(r) != NULL, "batch1_next");
	ASSERT_FALSE(ring__invalidated(r), "batch1_invalidated");

	/* Records 0 and 1 get overwritten. Getting more records doesn't change the result. */
	if (produce_n(prog_fd, seq, 2, size))
		goto out_ring;
	seq += 2;
	ASSERT_TRUE(ring__invalidated(r), "batch1_overwritten");
	for (i = 4; i < 8; i++)
		ASSERT_TRUE(ring__next(r) != NULL, "batch1_next_more");
	ASSERT_TRUE(ring__invalidated(r), "batch1_still_overwritten");

	/* Records returned before a release are not checked anymore. */
	ASSERT_EQ(ring__release(r), 1, "release");
	ASSERT_FALSE(ring__invalidated(r), "invalidated_after_release");
	for (i = 8; i < 10; i++)
		ASSERT_TRUE(ring__next(r) != NULL, "batch2_next");
	ASSERT_FALSE(ring__invalidated(r), "batch2_invalidated");

	/* Records 2 to 10 get overwritten, which includes the two returned last. */
	if (produce_n(prog_fd, seq, 9, size))
		goto out_ring;
	seq += 9;
	ASSERT_TRUE(ring__invalidated(r), "batch2_overwritten");

	/* After a rewind ring__next() continues from the oldest record that is left. */
	ring__rewind(r);
	ASSERT_FALSE(ring__invalidated(r), "invalidated_after_rewind");
	next_seq = 11;
	while ((rec = ring__next(r))) {
		ASSERT_EQ(rec->pos, next_seq * rec_sz, "batch3_pos");
		ASSERT_TRUE(record_ok(rec->data, rec->len, next_seq), "batch3_data");
		next_seq++;
	}
	ASSERT_EQ(next_seq, seq, "batch3_all_records");
	ASSERT_FALSE(ring__invalidated(r), "batch3_invalidated");
	ASSERT_EQ(ring__release(r), 0, "release_end");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

struct race_ctx {
	int prog_fd;
	volatile bool stop;
};

static void *race_producer(void *arg)
{
	static const __u32 sizes[] = { 8, 24, 64, 120, 256, 16 };
	struct race_ctx *ctx = arg;
	struct produce_args args = { .count = 16, .flags = BPF_RB_NO_WAKEUP };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int i = 0;

	while (!ctx->stop) {
		args.size = sizes[i++ % ARRAY_SIZE(sizes)];
		if (bpf_prog_test_run_opts(ctx->prog_fd, &opts))
			break;
	}
	return NULL;
}

#define RACE_BATCH	8
#define RACE_MAX_LEN	256

/*
 * Consume an overwritable ring while a thread keeps producing into it. Records
 * that were not overwritten must have valid data and increasing sequence
 * numbers. The length of a record must be valid even if it was overwritten.
 *
 * The checks run for every record, so they don't use ASSERT_*(), which logs
 * every pass.
 */
static void subtest_overwrite_race(void)
{
	__u64 copy[RACE_BATCH][RACE_MAX_LEN / 8];
	__u64 end, pause, iter, seq, next_seq = 0;
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct race_ctx ctx = {};
	__u32 len[RACE_BATCH];
	pthread_t thread;
	struct ring *r;
	int i, n;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	ctx.prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	if (!ASSERT_OK(pthread_create(&thread, NULL, race_producer, &ctx), "pthread_create"))
		goto out_ring;

	end = get_time_ns() + 1500000000ULL;
	for (iter = 0; get_time_ns() < end; iter++) {
		/* Copy a batch of records, then check that none of them was overwritten. */
		for (n = 0; n < RACE_BATCH && (rec = ring__next(r)); n++) {
			if (rec->len < 8 || rec->len > RACE_MAX_LEN || rec->len % 8) {
				PRINT_FAIL("record at %lu has length %u\n", rec->pos, rec->len);
				goto out_thread;
			}
			memcpy(copy[n], rec->data, rec->len);
			len[n] = rec->len;
		}
		/* Sometimes wait before the check, so that the producer laps us. */
		if (iter % 32 == 0) {
			pause = get_time_ns() + 50000;
			while (get_time_ns() < pause)
				;
		}
		if (ring__invalidated(r))
			n = 0;
		for (i = 0; i < n; i++) {
			seq = copy[i][0];
			if (!record_ok(copy[i], len[i], seq) || seq < next_seq) {
				PRINT_FAIL("bad record %llu, expected %llu or more\n",
					   seq, next_seq);
				goto out_thread;
			}
			next_seq = seq + 1;
		}
		ring__release(r);
	}

out_thread:
	ctx.stop = true;
	pthread_join(thread, NULL);
	ASSERT_GT(next_seq, 0, "valid_records");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

void test_ringbuf_iter(void)
{
	page_size = getpagesize();

	if (test__start_subtest("basic"))
		subtest_basic();
	if (test__start_subtest("rewind_discard"))
		subtest_rewind_discard();
	if (test__start_subtest("manager"))
		subtest_manager();
	if (test__start_subtest("standalone"))
		subtest_standalone();
	if (test__start_subtest("overwrite_basic"))
		subtest_overwrite_basic();
	if (test__start_subtest("overwrite_batch"))
		subtest_overwrite_batch();
	if (test__start_subtest("overwrite_race"))
		subtest_overwrite_race();
}
