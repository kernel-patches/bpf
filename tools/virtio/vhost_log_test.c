// SPDX-License-Identifier: GPL-2.0-only
/* Exercise vhost used-ring dirty logging through /dev/vhost-test. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/vhost.h>
#include <linux/virtio_ring.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../../drivers/vhost/test.h"

#define RING_NUM 128
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define PAGE_BYTES VHOST_PAGE_SIZE
#define CHECK(c) do { \
	if (!(c)) { \
		fprintf(stderr, "FAIL line %d: %s (errno=%d: %s)\n", \
			__LINE__, #c, errno, strerror(errno)); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

struct queue {
	int fd;
	int kick;
	int call;
	void *ring;
	void *data;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint16_t index;
};

static void *map_pages(size_t size)
{
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	CHECK(p != MAP_FAILED);
	return p;
}

static void log_base(struct queue *q, void *base)
{
	uint64_t addr = (uintptr_t)base;

	CHECK(!ioctl(q->fd, VHOST_SET_LOG_BASE, &addr));
}

static void queue_init_at(struct queue *q, void *bitmap, uint64_t log_addr,
			  bool logging)
{
	struct vhost_vring_state state = { .index = 0, .num = RING_NUM };
	struct vhost_vring_file file = { .index = 0 };
	struct vhost_vring_addr addr = { .index = 0 };
	struct vhost_memory *mem;
	uint64_t features = 0;
	unsigned char *scratch;
	int i, run = 1;

	memset(q, 0, sizeof(*q));
	q->fd = open("/dev/vhost-test", O_RDWR);
	CHECK(q->fd >= 0);
	CHECK(!ioctl(q->fd, VHOST_SET_OWNER, NULL));
	CHECK(!ioctl(q->fd, VHOST_SET_FEATURES, &features));
	q->kick = eventfd(0, EFD_NONBLOCK);
	q->call = eventfd(0, EFD_NONBLOCK);
	CHECK(q->kick >= 0 && q->call >= 0);
	q->ring = map_pages(3 * PAGE_BYTES);
	q->data = map_pages(PAGE_BYTES);
	q->desc = q->ring;
	q->avail = q->ring + PAGE_BYTES;
	q->used = q->ring + 2 * PAGE_BYTES;
	mem = calloc(1, sizeof(*mem) + sizeof(mem->regions[0]));
	CHECK(mem);
	mem->nregions = 1;
	mem->regions[0].guest_phys_addr = 0;
	mem->regions[0].userspace_addr = (uintptr_t)q->data;
	mem->regions[0].memory_size = PAGE_BYTES;
	CHECK(!ioctl(q->fd, VHOST_SET_MEM_TABLE, mem));
	free(mem);
	for (i = 0; i < RING_NUM; i++) {
		q->desc[i].addr = 0;
		q->desc[i].len = 1;
	}
	CHECK(!ioctl(q->fd, VHOST_SET_VRING_NUM, &state));
	state.num = 0;
	CHECK(!ioctl(q->fd, VHOST_SET_VRING_BASE, &state));
	addr.desc_user_addr = (uintptr_t)q->desc;
	addr.avail_user_addr = (uintptr_t)q->avail;
	addr.used_user_addr = (uintptr_t)q->used;
	addr.flags = logging ? 1U << VHOST_VRING_F_LOG : 0;
	addr.log_guest_addr = log_addr;
	CHECK(!ioctl(q->fd, VHOST_SET_VRING_ADDR, &addr));
	file.fd = q->kick;
	CHECK(!ioctl(q->fd, VHOST_SET_VRING_KICK, &file));
	file.fd = q->call;
	CHECK(!ioctl(q->fd, VHOST_SET_VRING_CALL, &file));
	/* Starting a queue logs its flags; keep the tested mapping untouched. */
	scratch = map_pages(PAGE_BYTES);
	log_base(q, scratch);
	CHECK(!ioctl(q->fd, VHOST_TEST_RUN, &run));
	log_base(q, bitmap);
	CHECK(!munmap(scratch, PAGE_BYTES));
}

static void queue_init(struct queue *q, void *bitmap, unsigned int bit,
		       bool logging)
{
	queue_init_at(q, bitmap, (uint64_t)bit * PAGE_BYTES, logging);
}

static void queue_submit(struct queue *q, unsigned int count)
{
	uint64_t kick = 1;
	unsigned int i;

	CHECK(count <= RING_NUM);
	for (i = 0; i < count; i++)
		q->avail->ring[(q->index + i) % RING_NUM] = i;
	q->index += count;
	__atomic_store_n(&q->avail->idx, q->index, __ATOMIC_RELEASE);
	CHECK(write(q->kick, &kick, sizeof(kick)) == sizeof(kick));
}

static void queue_wait(struct queue *q)
{
	struct pollfd pfd = { .fd = q->call, .events = POLLIN };
	uint64_t events;

	/* Completion notification follows the dirty-log stores. */
	do {
		CHECK(poll(&pfd, 1, 5000) == 1);
		CHECK(read(q->call, &events, sizeof(events)) == sizeof(events));
	} while (__atomic_load_n(&q->used->idx, __ATOMIC_ACQUIRE) != q->index);
}

static void queue_destroy(struct queue *q)
{
	/* Release flushes the worker before freeing any userspace mappings. */
	CHECK(!close(q->fd));
	CHECK(!close(q->kick));
	CHECK(!close(q->call));
	CHECK(!munmap(q->ring, 3 * PAGE_BYTES));
	CHECK(!munmap(q->data, PAGE_BYTES));
}

static void exercise(void *bitmap, unsigned int bit, unsigned int count)
{
	struct queue q;

	queue_init(&q, bitmap, bit, true);
	queue_submit(&q, count);
	queue_wait(&q);
	queue_destroy(&q);
}

static void basic_test(void)
{
	unsigned char *p = map_pages(2 * PAGE_BYTES);
	unsigned int offsets[] = { 0, 1, 7, 63, PAGE_BYTES - 1 };
	unsigned int i, bit;

	CHECK(!mprotect(p + PAGE_BYTES, PAGE_BYTES, PROT_NONE));
	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		for (bit = 0; bit < 8; bit++) {
			memset(p, 0, PAGE_BYTES);
			exercise(p + offsets[i], bit, RING_NUM);
			CHECK(p[offsets[i]] == (1U << bit));
			if (offsets[i])
				CHECK(!p[offsets[i] - 1]);
			if (offsets[i] + 1 < PAGE_BYTES)
				CHECK(!p[offsets[i] + 1]);
			p[offsets[i]] = 0xa5;
			exercise(p + offsets[i], bit, 1);
			CHECK(p[offsets[i]] == (0xa5 | (1U << bit)));
		}
	}
	CHECK(!munmap(p, 2 * PAGE_BYTES));
	puts("PASS bits 0..7, repeated sets, unaligned and guarded page end");
}

static void cross_page_test(void)
{
	unsigned int pages[] = { 1, 8 };
	unsigned char *p = map_pages(PAGE_BYTES);
	unsigned char want[2];
	unsigned int i, n;
	struct queue q;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		n = pages[i];
		memset(p, 0, 2);
		/* used->ring[0] is at offset 4, so it covers pages n - 1 and n. */
		queue_init_at(&q, p, (uint64_t)n * PAGE_BYTES - 8, true);
		queue_submit(&q, 1);
		queue_wait(&q);
		queue_destroy(&q);
		memset(want, 0, sizeof(want));
		want[(n - 1) / 8] |= 1U << ((n - 1) % 8);
		want[n / 8] |= 1U << (n % 8);
		if (p[0] != want[0] || p[1] != want[1]) {
			fprintf(stderr,
				"FAIL log pages %u/%u: got %02x %02x, want %02x %02x\n",
				n - 1, n, (unsigned int)p[0], (unsigned int)p[1],
				(unsigned int)want[0], (unsigned int)want[1]);
			exit(EXIT_FAILURE);
		}
	}
	CHECK(!munmap(p, PAGE_BYTES));
	puts("PASS used ring write spanning two log pages");
}

static void fault_test(void)
{
	unsigned char *p = map_pages(PAGE_BYTES);
	unsigned char resident;
	struct queue q;

	queue_init(&q, p, 3, true);
	CHECK(!mincore(p, PAGE_BYTES, &resident));
	CHECK(!(resident & 1));
	queue_submit(&q, 1);
	queue_wait(&q);
	queue_destroy(&q);
	CHECK(*p == 8);
	*p = 0;
	CHECK(!mprotect(p, PAGE_BYTES, PROT_READ));
	exercise(p, 2, 1);
	CHECK(!*p);
	CHECK(!mprotect(p, PAGE_BYTES, PROT_NONE));
	exercise(p, 2, 1);
	CHECK(!mprotect(p, PAGE_BYTES, PROT_READ | PROT_WRITE));
	exercise(p, 4, 1);
	CHECK(*p == 16);
	queue_init(&q, p, 2, true);
	CHECK(!munmap(p, PAGE_BYTES));
	queue_submit(&q, 1);
	queue_wait(&q);
	queue_destroy(&q);
	/* Used-ring logging ignores errors; check survival and no bad write. */
	puts("PASS first touch, readonly, PROT_NONE, unmapped, recovery");
}

static void file_test(const char *path)
{
	unsigned char *p;
	unsigned char byte;
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);

	CHECK(fd >= 0);
	CHECK(!ftruncate(fd, PAGE_BYTES));
	p = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	CHECK(p != MAP_FAILED);
	CHECK(!*p);
	exercise(p, 5, 1);
	CHECK(*p == 32);
	CHECK(pread(fd, &byte, 1, 0) == 1);
	CHECK(!byte);
	CHECK(!munmap(p, PAGE_BYTES));
	p = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p != MAP_FAILED);
	*p = 0;
	CHECK(!msync(p, PAGE_BYTES, MS_SYNC));
	exercise(p, 6, 1);
	CHECK(*p == 64);
	CHECK(!msync(p, PAGE_BYTES, MS_SYNC));
	CHECK(!munmap(p, PAGE_BYTES));
	CHECK(!fsync(fd));
	CHECK(!posix_fadvise(fd, 0, PAGE_BYTES, POSIX_FADV_DONTNEED));
	CHECK(pread(fd, &byte, 1, 0) == 1);
	CHECK(byte == 64);
	CHECK(!close(fd));
	CHECK(!unlink(path));
	puts("PASS private file COW and shared file sync/re-read");
}

struct collector {
	unsigned char *bitmap;
	bool stop;
	unsigned char seen;
};

static void *collect(void *arg)
{
	struct collector *c = arg;

	while (!__atomic_load_n(&c->stop, __ATOMIC_ACQUIRE))
		c->seen |= __atomic_exchange_n(c->bitmap, 0, __ATOMIC_SEQ_CST);
	return NULL;
}

static void concurrent_test(void)
{
	unsigned char *p = map_pages(PAGE_BYTES);
	struct queue q[8];
	struct collector c = { .bitmap = p };
	pthread_t thread;
	unsigned int bit, round;

	for (bit = 0; bit < 8; bit++)
		queue_init(&q[bit], p, bit, true);
	for (round = 0; round < 1000; round++) {
		__atomic_store_n(p, 0, __ATOMIC_SEQ_CST);
		for (bit = 0; bit < 8; bit++)
			queue_submit(&q[bit], 1);
		for (bit = 0; bit < 8; bit++)
			queue_wait(&q[bit]);
		CHECK(__atomic_load_n(p, __ATOMIC_SEQ_CST) == 255);
	}
	for (round = 0; round < 1000; round++) {
		__atomic_store_n(p, 0, __ATOMIC_SEQ_CST);
		c.stop = false;
		c.seen = 0;
		CHECK(!pthread_create(&thread, NULL, collect, &c));
		for (bit = 0; bit < 8; bit++)
			queue_submit(&q[bit], RING_NUM);
		for (bit = 0; bit < 8; bit++)
			queue_wait(&q[bit]);
		__atomic_store_n(&c.stop, true, __ATOMIC_RELEASE);
		CHECK(!pthread_join(thread, NULL));
		c.seen |= __atomic_exchange_n(p, 0, __ATOMIC_SEQ_CST);
		CHECK(c.seen == 255);
	}
	for (bit = 0; bit < 8; bit++)
		queue_destroy(&q[bit]);
	CHECK(!munmap(p, PAGE_BYTES));
	puts("PASS eight workers sharing a byte, concurrent atomic collection");
}

static void alias_test(const char *path)
{
	unsigned char *p, *alias;
	struct queue q[8];
	unsigned int bit, round;
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);

	CHECK(fd >= 0);
	CHECK(!ftruncate(fd, PAGE_BYTES));
	p = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	alias = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
		     fd, 0);
	CHECK(p != MAP_FAILED && alias != MAP_FAILED);
	for (bit = 0; bit < 8; bit++)
		queue_init(&q[bit], bit & 1 ? alias : p, bit, true);
	for (round = 0; round < 1000; round++) {
		__atomic_store_n(p, 0, __ATOMIC_SEQ_CST);
		/* Keep one alias writable, and force faults through the other. */
		CHECK(!madvise(alias, PAGE_BYTES, MADV_DONTNEED));
		for (bit = 0; bit < 8; bit++)
			queue_submit(&q[bit], 1);
		for (bit = 0; bit < 8; bit++)
			queue_wait(&q[bit]);
		CHECK(__atomic_load_n(p, __ATOMIC_SEQ_CST) == 255);
	}
	for (bit = 0; bit < 8; bit++)
		queue_destroy(&q[bit]);
	CHECK(!munmap(p, PAGE_BYTES));
	CHECK(!munmap(alias, PAGE_BYTES));
	CHECK(!close(fd));
	CHECK(!unlink(path));
	puts("PASS shared-file aliases with repeated PTE faults");
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts));
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void benchmark(bool logging, unsigned int batches)
{
	unsigned char *p = map_pages(PAGE_BYTES);
	struct queue q;
	uint64_t start, elapsed;
	unsigned int i;

	*p = 0;
	queue_init(&q, p, 0, logging);
	for (i = 0; i < 100; i++) {
		queue_submit(&q, RING_NUM);
		queue_wait(&q);
	}
	start = now_ns();
	for (i = 0; i < batches; i++) {
		queue_submit(&q, RING_NUM);
		queue_wait(&q);
	}
	elapsed = now_ns() - start;
	queue_destroy(&q);
	CHECK(*p == (logging ? 1 : 0));
	printf("BENCH logging=%u descriptors=%u elapsed_ns=%" PRIu64
	       " ns_per_desc=%.2f\n", logging, batches * RING_NUM,
	       elapsed, (double)elapsed / (batches * RING_NUM));
	CHECK(!munmap(p, PAGE_BYTES));
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/tmp/vhost-log-test";

	CHECK(sysconf(_SC_PAGESIZE) == PAGE_BYTES);
	if (argc == 2 && !strcmp(argv[1], "--bench")) {
		benchmark(false, 10000);
		benchmark(true, 10000);
		return 0;
	}
	basic_test();
	cross_page_test();
	fault_test();
	file_test(path);
	concurrent_test();
	alias_test(path);
	puts("PASS vhost dirty-log regression suite");
	return 0;
}
