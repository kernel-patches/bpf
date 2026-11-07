// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <pthread.h>

#define ENTRIES 64
#define VALUE_SIZE 4000

static int create_map(__u32 entries)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_NO_PREALLOC,
		.map_extra = entries);
	char value[VALUE_SIZE] = {};
	__u64 key;
	int fd;

	fd = bpf_map_create(BPF_MAP_TYPE_RHASH, "rhash_batch", sizeof(key),
			    sizeof(value), entries, &opts);
	if (!ASSERT_OK_FD(fd, "map_create"))
		return -1;
	for (key = 0; key < entries; key++) {
		if (!ASSERT_OK(bpf_map_update_elem(fd, &key, value, BPF_ANY), "map_update")) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

static int lookup_batch(int fd, void *in, void *out, void *keys,
			void *values, __u32 *count, bool delete)
{
	if (delete)
		return bpf_map_lookup_and_delete_batch(fd, in, out, keys, values, count, NULL);
	return bpf_map_lookup_batch(fd, in, out, keys, values, count, NULL);
}

static void test_batch(bool delete, bool lost_cursor)
{
	__u64 key, cursor, seen = 0;
	char value[VALUE_SIZE];
	__u32 count;
	int fd, err;
	void *in = NULL;

	/* Two entries fit in the minimum table, including while deleting. */
	fd = create_map(2);
	if (fd < 0)
		return;
	if (lost_cursor) {
		count = 1;
		err = lookup_batch(fd, NULL, &cursor, &key, value, &count, delete);
		if (!ASSERT_OK(err, "first_batch") || !ASSERT_EQ(count, 1, "first_count") ||
		    !ASSERT_OK(bpf_map_delete_elem(fd, &cursor), "delete_cursor"))
			goto out;
		count = 1;
		err = lookup_batch(fd, &cursor, &cursor, &key, value, &count, delete);
		ASSERT_EQ(err, -EAGAIN, "lost_cursor");
		ASSERT_EQ(count, 0, "lost_count");
		goto out;
	}
	do {
		count = 1;
		err = lookup_batch(fd, in, &cursor, &key, value, &count, delete);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "batch_result") ||
		    !ASSERT_EQ(count, 1, "batch_count") ||
		    !ASSERT_LT(key, 2, "key_range") ||
		    !ASSERT_EQ(seen & (1ULL << key), 0, "unique_key"))
			goto out;
		seen |= 1ULL << key;
		in = &cursor;
	} while (!err);
	ASSERT_EQ(seen, 3, "all_keys");
	if (delete) {
		ASSERT_EQ(bpf_map_get_next_key(fd, NULL, &cursor), -ENOENT, "empty_map");
		count = 1;
		err = lookup_batch(fd, NULL, &cursor, &key, value, &count, true);
		ASSERT_EQ(err, -ENOENT, "empty_batch");
		ASSERT_EQ(count, 0, "empty_count");
	}
out:
	close(fd);
}

struct race_ctx {
	int fd;
	__u64 key;
	bool stop;
	int err;
	unsigned int updates;
};

static void *update_key(void *arg)
{
	struct race_ctx *ctx = arg;
	char value[VALUE_SIZE] = {};

	while (!__atomic_load_n(&ctx->stop, __ATOMIC_RELAXED)) {
		ctx->err = bpf_map_delete_elem(ctx->fd, &ctx->key);
		if (ctx->err)
			break;
		ctx->err = bpf_map_update_elem(ctx->fd, &ctx->key, value, BPF_ANY);
		if (ctx->err)
			break;
		ctx->updates++;
	}
	return NULL;
}

static void test_concurrent_delete(void)
{
	struct race_ctx ctx = {};
	__u64 keys[ENTRIES], cursor, seen = 0, expected;
	unsigned int completed = 0, attempt;
	__u32 count, i;
	void *in = NULL, *values;
	pthread_t thread;
	int err;

	ctx.fd = create_map(ENTRIES);
	if (ctx.fd < 0)
		return;
	values = malloc(ENTRIES * VALUE_SIZE);
	if (!ASSERT_OK_PTR(values, "values"))
		goto close;
	if (!ASSERT_OK(bpf_map_get_next_key(ctx.fd, NULL, &ctx.key), "first_key"))
		goto out;
	expected = ~(1ULL << ctx.key);
	if (!ASSERT_OK(pthread_create(&thread, NULL, update_key, &ctx), "thread_create"))
		goto out;
	/* Only the first key changes; no resize is needed at this load. */
	for (attempt = 0; attempt < 5000; attempt++) {
		count = ENTRIES;
		err = bpf_map_lookup_batch(ctx.fd, in, &cursor, keys, values, &count, NULL);
		if (err == -EAGAIN) {
			in = NULL;
			seen = 0;
			continue;
		}
		if (!ASSERT_TRUE(!err || err == -ENOENT, "batch_result"))
			break;
		for (i = 0; i < count; i++) {
			if (!ASSERT_LT(keys[i], ENTRIES, "key_range"))
				goto stop;
			seen |= 1ULL << keys[i];
		}
		if (err == -ENOENT) {
			if (!ASSERT_EQ(seen & expected, expected, "persistent_keys"))
				break;
			completed++;
			in = NULL;
			seen = 0;
		} else {
			in = &cursor;
		}
	}
stop:
	__atomic_store_n(&ctx.stop, true, __ATOMIC_RELAXED);
	pthread_join(thread, NULL);
	ASSERT_OK(ctx.err, "writer_result");
	ASSERT_GT(ctx.updates, 0, "concurrent_updates");
	ASSERT_GT(completed, 0, "completed_walks");
out:
	free(values);
close:
	close(ctx.fd);
}

void test_rhash_batch(void)
{
	if (test__start_subtest("lookup"))
		test_batch(false, false);
	if (test__start_subtest("lookup_delete"))
		test_batch(true, false);
	if (test__start_subtest("lost_lookup_cursor"))
		test_batch(false, true);
	if (test__start_subtest("lost_delete_cursor"))
		test_batch(true, true);
	if (test__start_subtest("concurrent_delete"))
		test_concurrent_delete();
}
