// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <test_progs.h>
#include <unpriv_helpers.h>
#include "kasan.skel.h"

#define SUBTEST_NAME_MAX_LEN	128

#define MAX_LOG_SIZE		(8*1024)
#define READ_CHUNK_SIZE		256

#define KASAN_PATTERN_SLAB_UAF "BUG: KASAN: slab-use-after-free " \
	"in bpf_prog_%02x%02x%02x%02x%02x%02x%02x%02x_%s"
#define KASAN_PATTERN_REPORT "%s of size %d at addr"

static char klog_buffer[MAX_LOG_SIZE];

struct test_spec {
	char *prog_type;
	bool is_write;
	bool only_32_or_64;
	bool check_load_acq_store_rel_supported;
};

struct kasan_write_val {
	__u8 data_1;
	__u16 data_2;
	__u32 data_4;
	__u64 data_8;
};


struct test_ctx {
	__u8  prog_tag[BPF_TAG_SIZE];
	struct kasan *skel;
	struct bpf_program *prog;
	char prog_name[SUBTEST_NAME_MAX_LEN];
	int klog_fd;
};

static int open_kernel_logs(void)
{
	int fd;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);

	return fd;
}

static void skip_kernel_logs(int fd)
{
	lseek(fd, 0, SEEK_END);
}

static int read_kernel_logs(int fd, char *buf, size_t max_len)
{
	char record[512];
	size_t total = 0;
	ssize_t n;

	buf[0] = '\0';
	while (1) {
		char *msg, *eol;
		size_t len;

		n = read(fd, record, sizeof(record) - 1);
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			return n;
		}
		record[n] = '\0';

		/* Each kmsg record starts with some metadata, separated
		 * from the actual content by a semi-colon
		 */
		msg = strchr(record, ';');
		if (!msg)
			continue;
		msg++;
		eol = strchr(msg, '\n');
		if (eol)
			*eol = '\0';

		len = strlen(msg);
		if (total + len + 2 > max_len)
			break;
		memcpy(buf + total, msg, len);
		total += len;
		buf[total++] = '\n';
		buf[total] = '\0';
	}

	return total;
}

static int check_kasan_report_in_kernel_logs(char *buf,
						  struct test_ctx *ctx,
						  bool is_write, int size)
{
	char *access_desc_start, *access_desc_end, *tmp;
	char access_log[READ_CHUNK_SIZE];
	char *kasan_report_start;
	int hsize, nsize;

	snprintf(access_log, READ_CHUNK_SIZE, KASAN_PATTERN_SLAB_UAF,
		 ctx->prog_tag[0], ctx->prog_tag[1], ctx->prog_tag[2],
		 ctx->prog_tag[3], ctx->prog_tag[4], ctx->prog_tag[5],
		 ctx->prog_tag[6], ctx->prog_tag[7], ctx->prog_name);
	/* Searched kasan report is valid if
	 * - it contains the expected kasan pattern
	 * - the next line is the description of the faulty access
	 * - faulty access properties match the tested type and size
	 */
	kasan_report_start = strstr(buf, access_log);

	if (!kasan_report_start) {
		fprintf(stderr, "Failed to find %s\n", access_log);
		return 1;
	}

	/* Find next line */
	access_desc_start = strchr(kasan_report_start, '\n');
	if (!access_desc_start)
		return 1;
	access_desc_start++;

	access_desc_end = strchr(access_desc_start, '\n');
	if (!access_desc_end)
		return 1;

	nsize = snprintf(access_log, READ_CHUNK_SIZE, KASAN_PATTERN_REPORT,
		 is_write ? "Write" : "Read", size);

	hsize = access_desc_end - access_desc_start;
	tmp = memmem(access_desc_start, hsize, access_log, nsize);

	if (!tmp) {
		fprintf(stderr, "Failed to find %s\n", access_log);
		return 1;
	}

	return 0;
}

static void run_subtest_with_size(struct test_ctx *ctx, struct test_spec *test,
				  int access_size)
{
	char subtest_name[SUBTEST_NAME_MAX_LEN];
	struct bpf_prog_info info;
	uint8_t buf[ETH_HLEN];
	__u32 info_len;
	int ret;

	snprintf(subtest_name, SUBTEST_NAME_MAX_LEN, "%s_%d", test->prog_type,
		 access_size);

	if (!test__start_subtest(subtest_name))
		return;

	if (test->check_load_acq_store_rel_supported &&
	    ctx->skel->data->skip_load_acq_store_rel_tests) {
		test__skip();
		return;
	}

	ctx->prog = bpf_object__find_program_by_name(ctx->skel->obj,
						     test->prog_type);
	if (!ASSERT_OK_PTR(ctx->prog, "find test prog"))
		return;

	info_len = sizeof(info);
	memset(&info, 0, info_len);
	ret = bpf_prog_get_info_by_fd(bpf_program__fd(ctx->prog), &info,
				      &info_len);
	if (!ASSERT_OK(ret, "fetch loaded program info"))
		return;
	memcpy(ctx->prog_tag, info.tag, BPF_TAG_SIZE);

	skip_kernel_logs(ctx->klog_fd);

	LIBBPF_OPTS(bpf_test_run_opts, topts);
	topts.sz = sizeof(struct bpf_test_run_opts);
	topts.data_size_in = ETH_HLEN;
	topts.data_in = buf;
	ctx->skel->bss->access_size = access_size;
	ret = bpf_prog_test_run_opts(bpf_program__fd(ctx->prog),
				     &topts);
	if (!ASSERT_OK(ret, "run prog"))
		return;

	ret = read_kernel_logs(ctx->klog_fd, klog_buffer, MAX_LOG_SIZE);

	if (ASSERT_GE(ret, 0, "read kernel logs")) {
		ret = check_kasan_report_in_kernel_logs(
			klog_buffer, ctx, test->is_write, access_size);
		ASSERT_OK(ret, "check_report");
	}
}

static void run_subtest(struct test_ctx *ctx, struct test_spec *test)
{
	if (!test->only_32_or_64) {
		run_subtest_with_size(ctx, test, 1);
		run_subtest_with_size(ctx, test, 2);
	}
	run_subtest_with_size(ctx, test, 4);
	run_subtest_with_size(ctx, test, 8);
}

static struct test_spec tests[] = {
	{
		.prog_type = "st",
		.is_write = true
	},
	{
		.prog_type = "stx",
		.is_write = true
	},
	{
		.prog_type = "ldx",
		.is_write = false
	},
	{
		.prog_type = "simple_atomic",
		.is_write = false,
		.only_32_or_64 = true
	},
	{
		.prog_type = "load_acquire",
		.is_write = false,
		.check_load_acq_store_rel_supported = true
	},
	{
		.prog_type = "store_release",
		.is_write = true,
		.check_load_acq_store_rel_supported = true
	}
};

void test_kasan(void)
{
	struct kasan_write_val val;
	struct test_spec *test;
	struct test_ctx *ctx;
	__u32 key = 0;
	int i, ret;

	ctx = calloc(1, sizeof(struct test_ctx));
	if (!ASSERT_OK_PTR(ctx, "alloc test ctx"))
		return;

	if (!is_jit_enabled() || !get_kasan_jit_enabled()) {
		test__skip();
		goto end;
	}

	ctx->skel = kasan__open_and_load();
	if (!ASSERT_OK_PTR(ctx->skel, "open and load prog"))
		goto end;

	ctx->klog_fd = open_kernel_logs();
	if (!ASSERT_OK_FD(ctx->klog_fd, "open kernel logs"))
		goto destroy;

	/* Fill map with recognizable values */
	ret = bpf_map__lookup_elem(ctx->skel->maps.test_map, &key, sizeof(key), &val, sizeof(val), 0);
	if (!ASSERT_OK(ret, "get map"))
		goto close;
	val.data_1 = 0xAA;
	val.data_2 = 0xBB;
	val.data_4 = 0xCC;
	val.data_8 = 0xDD;
	ret = bpf_map__update_elem(ctx->skel->maps.test_map, &key, sizeof(key), &val, sizeof(val), 0);
	if (!ASSERT_OK(ret, "get map"))
		goto close;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		test = &tests[i];
		run_subtest(ctx, test);
	}

close:
	if (ctx->klog_fd >= 0)
		close(ctx->klog_fd);
destroy:
	kasan__destroy(ctx->skel);
end:
	free(ctx);
}
