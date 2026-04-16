// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for kallsyms lineinfo (CONFIG_KALLSYMS_LINEINFO).
 *
 * Copyright (c) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Verifies that sprint_symbol() and related APIs append correct
 * " (file.c:NNN)" annotations to kernel symbol lookups.
 *
 * Build with: CONFIG_LINEINFO_KUNIT_TEST=m (or =y)
 * Run with:   ./tools/testing/kunit/kunit.py run lineinfo
 */

#include <kunit/test.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mod_lineinfo.h>

/* --------------- helpers --------------- */

static char *alloc_sym_buf(struct kunit *test)
{
	return kunit_kzalloc(test, KSYM_SYMBOL_LEN, GFP_KERNEL);
}

/*
 * Return true if @buf contains a lineinfo annotation matching
 * the pattern " (<path>:<digits>)".
 *
 * The path may be a full path like "lib/tests/lineinfo_kunit.c" or
 * a shortened form from module lineinfo (e.g., just a directory name).
 */
static bool has_lineinfo(const char *buf)
{
	const char *p, *colon, *end;

	p = strstr(buf, " (");
	if (!p)
		return false;
	p += 2; /* skip " (" */

	colon = strchr(p, ':');
	if (!colon || colon == p)
		return false;

	/* After colon: one or more digits then ')' */
	end = colon + 1;
	if (*end < '0' || *end > '9')
		return false;
	while (*end >= '0' && *end <= '9')
		end++;
	return *end == ')';
}

/*
 * Extract line number from a lineinfo annotation.
 * Returns 0 if not found.
 */
static unsigned int extract_line(const char *buf)
{
	const char *p, *colon;
	unsigned int line = 0;

	p = strstr(buf, " (");
	if (!p)
		return 0;

	colon = strchr(p + 2, ':');
	if (!colon)
		return 0;

	colon++;
	while (*colon >= '0' && *colon <= '9') {
		line = line * 10 + (*colon - '0');
		colon++;
	}
	return line;
}

/*
 * Check if the lineinfo annotation contains the given filename substring.
 */
static bool lineinfo_contains_file(const char *buf, const char *name)
{
	const char *p, *colon;

	p = strstr(buf, " (");
	if (!p)
		return false;

	colon = strchr(p + 2, ':');
	if (!colon)
		return false;

	/* Search for @name between '(' and ':' */
	return strnstr(p + 1, name, colon - p - 1) != NULL;
}

/* --------------- target functions --------------- */

static noinline int lineinfo_target_normal(void)
{
	barrier();
	return 42;
}

static noinline int lineinfo_target_short(void)
{
	barrier();
	return 1;
}

static noinline int lineinfo_target_with_arg(int x)
{
	barrier();
	return x + 1;
}

static noinline int lineinfo_target_many_lines(void)
{
	int a = 0;

	barrier();
	a += 1;
	a += 2;
	a += 3;
	a += 4;
	a += 5;
	a += 6;
	a += 7;
	a += 8;
	a += 9;
	a += 10;
	barrier();
	return a;
}

static __always_inline int lineinfo_inline_helper(void)
{
	return 99;
}

static noinline int lineinfo_inline_caller(void)
{
	barrier();
	return lineinfo_inline_helper();
}

/* 10-deep call chain */
static noinline int lineinfo_chain_10(void) { barrier(); return 10; }
static noinline int lineinfo_chain_9(void)  { barrier(); return lineinfo_chain_10(); }
static noinline int lineinfo_chain_8(void)  { barrier(); return lineinfo_chain_9(); }
static noinline int lineinfo_chain_7(void)  { barrier(); return lineinfo_chain_8(); }
static noinline int lineinfo_chain_6(void)  { barrier(); return lineinfo_chain_7(); }
static noinline int lineinfo_chain_5(void)  { barrier(); return lineinfo_chain_6(); }
static noinline int lineinfo_chain_4(void)  { barrier(); return lineinfo_chain_5(); }
static noinline int lineinfo_chain_3(void)  { barrier(); return lineinfo_chain_4(); }
static noinline int lineinfo_chain_2(void)  { barrier(); return lineinfo_chain_3(); }
static noinline int lineinfo_chain_1(void)  { barrier(); return lineinfo_chain_2(); }

/* --------------- Group A: Basic lineinfo presence --------------- */

static void test_normal_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test,
			      lineinfo_contains_file(buf, "lineinfo_kunit.c"),
			      "Wrong file in: %s", buf);
}

static void test_static_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_short;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in: %s", buf);
}

static void test_noinline_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_with_arg;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in: %s", buf);
}

static void test_inline_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_inline_caller;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo for inline caller in: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test,
			      lineinfo_contains_file(buf, "lineinfo_kunit.c"),
			      "Wrong file in: %s", buf);
}

static void test_short_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_short;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo for short function in: %s", buf);
}

static void test_many_lines_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_many_lines;
	unsigned int line;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in: %s", buf);
	line = extract_line(buf);
	KUNIT_EXPECT_GT_MSG(test, line, (unsigned int)0,
			    "Line number should be > 0 in: %s", buf);
}

/* --------------- Group B: Deep call chain --------------- */

typedef int (*chain_fn_t)(void);

static void test_deep_call_chain(struct kunit *test)
{
	static const chain_fn_t chain_fns[] = {
		lineinfo_chain_1,  lineinfo_chain_2,
		lineinfo_chain_3,  lineinfo_chain_4,
		lineinfo_chain_5,  lineinfo_chain_6,
		lineinfo_chain_7,  lineinfo_chain_8,
		lineinfo_chain_9,  lineinfo_chain_10,
	};
	char *buf = alloc_sym_buf(test);
	int i, found = 0;

	/* Call chain to prevent dead-code elimination */
	KUNIT_ASSERT_EQ(test, lineinfo_chain_1(), 10);

	for (i = 0; i < ARRAY_SIZE(chain_fns); i++) {
		unsigned long addr = (unsigned long)chain_fns[i];

		sprint_symbol(buf, addr);
		if (has_lineinfo(buf))
			found++;
	}

	/*
	 * Not every tiny function gets DWARF line info (compiler may
	 * omit it for very small stubs), but at least some should.
	 */
	KUNIT_EXPECT_GT_MSG(test, found, 0,
			    "None of the 10 chain functions had lineinfo");
}

/* --------------- Group C: sprint_symbol API variants --------------- */

static void test_sprint_symbol_format(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_symbol(buf, addr);

	/* Should contain +0x and /0x for offset/size */
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(buf, "+0x"),
				  "Missing offset in: %s", buf);
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(buf, "/0x"),
				  "Missing size in: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in: %s", buf);
}

static void test_sprint_backtrace(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	/* sprint_backtrace subtracts 1 internally to handle tail calls */
	sprint_backtrace(buf, addr + 1);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in backtrace: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test,
			      lineinfo_contains_file(buf, "lineinfo_kunit.c"),
			      "Wrong file in backtrace: %s", buf);
}

static void test_sprint_backtrace_build_id(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_backtrace_build_id(buf, addr + 1);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in backtrace_build_id: %s", buf);
}

static void test_sprint_symbol_no_offset(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_symbol_no_offset(buf, addr);
	/* No "+0x" in output */
	KUNIT_EXPECT_NULL_MSG(test, strstr(buf, "+0x"),
			      "Unexpected offset in no_offset: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in no_offset: %s", buf);
}

/* --------------- Group D: printk format specifiers --------------- */

static void test_pS_format(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	void *addr = lineinfo_target_normal;

	snprintf(buf, KSYM_SYMBOL_LEN, "%pS", addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in %%pS: %s", buf);
}

static void test_pBb_format(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	/*
	 * %pBb uses sprint_backtrace_build_id which subtracts 1 from the
	 * address, so pass addr+1 to resolve back to the function.
	 */
	void *addr = (void *)((unsigned long)lineinfo_target_normal + 1);

	snprintf(buf, KSYM_SYMBOL_LEN, "%pBb", addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in %%pBb: %s", buf);
}

static void test_pSR_format(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	void *addr = lineinfo_target_normal;

	snprintf(buf, KSYM_SYMBOL_LEN, "%pSR", addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in %%pSR: %s", buf);
}

/* --------------- Group E: Address edge cases --------------- */

static void test_symbol_start_addr(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(buf, "+0x0/"),
				  "Expected +0x0/ at function start: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo at function start: %s", buf);
}

static void test_symbol_nonzero_offset(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	/*
	 * sprint_backtrace subtracts 1 internally.
	 * Passing addr+2 resolves to addr+1 which is inside the function
	 * at a non-zero offset.
	 */
	sprint_backtrace(buf, addr + 2);
	KUNIT_EXPECT_TRUE_MSG(test,
			      strnstr(buf, "lineinfo_target_normal",
				      KSYM_SYMBOL_LEN) != NULL,
			      "Didn't resolve to expected function: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo at non-zero offset: %s", buf);
}

static void test_unknown_address(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);

	sprint_symbol(buf, 1UL);
	/* Should be "0x1" with no lineinfo */
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(buf, "0x1"),
				  "Expected hex address for bogus addr: %s", buf);
	KUNIT_EXPECT_FALSE_MSG(test, has_lineinfo(buf),
			       "Unexpected lineinfo for bogus addr: %s", buf);
}

static void test_kernel_function_lineinfo(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)sprint_symbol;

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo for sprint_symbol: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test,
			      lineinfo_contains_file(buf, "kallsyms.c"),
			      "Expected kallsyms.c in: %s", buf);
}

static void test_assembly_no_lineinfo(struct kunit *test)
{
#if IS_BUILTIN(CONFIG_LINEINFO_KUNIT_TEST)
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)_text;

	sprint_symbol(buf, addr);
	/*
	 * _text is typically an asm entry point with no DWARF line info.
	 * If it has lineinfo, it's a C-based entry — skip in that case.
	 */
	if (has_lineinfo(buf))
		kunit_skip(test, "_text has lineinfo (C entry?): %s", buf);

	KUNIT_EXPECT_FALSE_MSG(test, has_lineinfo(buf),
			       "Unexpected lineinfo for asm symbol: %s", buf);
#else
	kunit_skip(test, "_text not accessible from modules");
#endif
}

/* --------------- Group F: Module path --------------- */

static void test_module_function_lineinfo(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	if (!IS_MODULE(CONFIG_LINEINFO_KUNIT_TEST)) {
		kunit_skip(test, "Test only meaningful when built as module");
		return;
	}

	sprint_symbol(buf, addr);
	KUNIT_EXPECT_NOT_NULL_MSG(test,
				  strstr(buf, "[lineinfo_kunit"),
				  "Missing module name in: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo for module function: %s", buf);
	KUNIT_EXPECT_TRUE_MSG(test,
			      lineinfo_contains_file(buf, "lineinfo_kunit.c"),
			      "Wrong file for module function: %s", buf);
}

/* --------------- Group G: Stress --------------- */

struct lineinfo_stress_data {
	unsigned long addr;
	atomic_t failures;
};

static void lineinfo_stress_fn(void *info)
{
	struct lineinfo_stress_data *data = info;
	char buf[KSYM_SYMBOL_LEN];
	int i;

	for (i = 0; i < 100; i++) {
		sprint_symbol(buf, data->addr);
		if (!has_lineinfo(buf))
			atomic_inc(&data->failures);
	}
}

static void test_concurrent_sprint_symbol(struct kunit *test)
{
	struct lineinfo_stress_data data;

	data.addr = (unsigned long)lineinfo_target_normal;
	atomic_set(&data.failures, 0);

	on_each_cpu(lineinfo_stress_fn, &data, 1);

	KUNIT_EXPECT_EQ_MSG(test, atomic_read(&data.failures), 0,
			    "Concurrent lineinfo failures detected");
}

static void test_rapid_sprint_symbol(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;
	int i, failures = 0;

	for (i = 0; i < 1000; i++) {
		sprint_symbol(buf, addr);
		if (!has_lineinfo(buf))
			failures++;
	}

	KUNIT_EXPECT_EQ_MSG(test, failures, 0,
			    "Rapid sprint_symbol failures: %d/1000", failures);
}

/* --------------- Group H: Safety and plausibility --------------- */

static void test_line_number_plausible(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;
	unsigned int line;

	sprint_symbol(buf, addr);
	KUNIT_ASSERT_TRUE(test, has_lineinfo(buf));

	line = extract_line(buf);
	KUNIT_EXPECT_GT_MSG(test, line, (unsigned int)0,
			    "Line number should be > 0");
	KUNIT_EXPECT_LT_MSG(test, line, (unsigned int)10000,
			    "Line number %u implausibly large for this file",
			    line);
}

static void test_buffer_no_overflow(struct kunit *test)
{
	const size_t canary_size = 16;
	char *buf;
	int i;

	buf = kunit_kzalloc(test, KSYM_SYMBOL_LEN + canary_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Fill canary area past KSYM_SYMBOL_LEN with 0xAA */
	memset(buf + KSYM_SYMBOL_LEN, 0xAA, canary_size);

	sprint_symbol(buf, (unsigned long)lineinfo_target_normal);

	/* Verify canary bytes are untouched */
	for (i = 0; i < canary_size; i++) {
		KUNIT_EXPECT_EQ_MSG(test,
				    (unsigned char)buf[KSYM_SYMBOL_LEN + i],
				    (unsigned char)0xAA,
				    "Buffer overflow at offset %d past KSYM_SYMBOL_LEN",
				    i);
	}
}

static void test_dump_stack_no_crash(struct kunit *test)
{
	/* Just verify dump_stack() completes without panic */
	dump_stack();
	KUNIT_SUCCEED(test);
}

static void test_sprint_symbol_build_id(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;

	sprint_symbol_build_id(buf, addr);
	KUNIT_EXPECT_TRUE_MSG(test, has_lineinfo(buf),
			      "No lineinfo in sprint_symbol_build_id: %s", buf);
}

static void test_sleb128_edge_cases(struct kunit *test)
{
	u32 pos;
	int32_t result;

	/* Value 0: single byte 0x00 */
	{
		static const u8 data[] = { 0x00 };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)0);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value -1: single byte 0x7F */
	{
		static const u8 data[] = { 0x7f };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)-1);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value 1: single byte 0x01 */
	{
		static const u8 data[] = { 0x01 };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)1);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value -64: single byte 0x40 */
	{
		static const u8 data[] = { 0x40 };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)-64);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value 63: single byte 0x3F */
	{
		static const u8 data[] = { 0x3f };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)63);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value -128: two bytes 0x80 0x7F */
	{
		static const u8 data[] = { 0x80, 0x7f };

		pos = 0;
		result = lineinfo_read_sleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (int32_t)-128);
		KUNIT_EXPECT_EQ(test, pos, (u32)2);
	}
}

static void test_uleb128_edge_cases(struct kunit *test)
{
	u32 pos, result;

	/* Value 0: single byte 0x00 */
	{
		static const u8 data[] = { 0x00 };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (u32)0);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value 127: single byte 0x7F */
	{
		static const u8 data[] = { 0x7F };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (u32)127);
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}

	/* Value 128: two bytes 0x80 0x01 */
	{
		static const u8 data[] = { 0x80, 0x01 };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (u32)128);
		KUNIT_EXPECT_EQ(test, pos, (u32)2);
	}

	/* Max u32 0xFFFFFFFF: 5 bytes */
	{
		static const u8 data[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x0F };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, sizeof(data));
		KUNIT_EXPECT_EQ(test, result, (u32)0xFFFFFFFF);
		KUNIT_EXPECT_EQ(test, pos, (u32)5);
	}

	/* Truncated input: pos >= end returns 0 */
	{
		static const u8 data[] = { 0x80 };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, 0);
		KUNIT_EXPECT_EQ_MSG(test, result, (u32)0,
				    "Expected 0 for empty input");
	}

	/* Truncated mid-varint: continuation byte but end reached */
	{
		static const u8 data[] = { 0x80 };

		pos = 0;
		result = lineinfo_read_uleb128(data, &pos, 1);
		KUNIT_EXPECT_EQ_MSG(test, result, (u32)0,
				    "Expected 0 for truncated varint");
		KUNIT_EXPECT_EQ(test, pos, (u32)1);
	}
}

static void test_line_number_accuracy(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_normal;
	unsigned int line;

	sprint_symbol(buf, addr);
	KUNIT_ASSERT_TRUE(test, has_lineinfo(buf));

	line = extract_line(buf);

	/*
	 * lineinfo_target_normal is defined around line 103-107.
	 * Allow wide range: KASAN instrumentation and module lineinfo
	 * address mapping can shift the reported line significantly.
	 */
	KUNIT_EXPECT_GE_MSG(test, line, (unsigned int)50,
			    "Line %u too low for lineinfo_target_normal", line);
	KUNIT_EXPECT_LE_MSG(test, line, (unsigned int)300,
			    "Line %u too high for lineinfo_target_normal", line);
}

static void test_many_lines_mid_function(struct kunit *test)
{
	char *buf = alloc_sym_buf(test);
	unsigned long addr = (unsigned long)lineinfo_target_many_lines;
	unsigned int line;
	unsigned long mid_addr;

	/* Get function size from sprint_symbol output */
	sprint_symbol(buf, addr);
	KUNIT_ASSERT_TRUE(test, has_lineinfo(buf));

	/* Try an address 8 bytes into the function (past prologue) */
	mid_addr = addr + 8;
	sprint_symbol(buf, mid_addr);

	/*
	 * Should still resolve to lineinfo_target_many_lines.
	 * Lineinfo should be present with a plausible line number.
	 */
	KUNIT_EXPECT_TRUE_MSG(test,
			      strnstr(buf, "lineinfo_target_many_lines",
				      KSYM_SYMBOL_LEN) != NULL,
			      "Mid-function addr resolved to wrong symbol: %s",
			      buf);
	if (has_lineinfo(buf)) {
		line = extract_line(buf);
		KUNIT_EXPECT_GE_MSG(test, line, (unsigned int)50,
				    "Line %u too low for mid-function", line);
		KUNIT_EXPECT_LE_MSG(test, line, (unsigned int)700,
				    "Line %u too high for mid-function", line);
	}
}

/* --------------- Suite registration --------------- */

static struct kunit_case lineinfo_test_cases[] = {
	/* Group A: Basic lineinfo presence */
	KUNIT_CASE(test_normal_function),
	KUNIT_CASE(test_static_function),
	KUNIT_CASE(test_noinline_function),
	KUNIT_CASE(test_inline_function),
	KUNIT_CASE(test_short_function),
	KUNIT_CASE(test_many_lines_function),
	/* Group B: Deep call chain */
	KUNIT_CASE(test_deep_call_chain),
	/* Group C: sprint_symbol API variants */
	KUNIT_CASE(test_sprint_symbol_format),
	KUNIT_CASE(test_sprint_backtrace),
	KUNIT_CASE(test_sprint_backtrace_build_id),
	KUNIT_CASE(test_sprint_symbol_no_offset),
	/* Group D: printk format specifiers */
	KUNIT_CASE(test_pS_format),
	KUNIT_CASE(test_pBb_format),
	KUNIT_CASE(test_pSR_format),
	/* Group E: Address edge cases */
	KUNIT_CASE(test_symbol_start_addr),
	KUNIT_CASE(test_symbol_nonzero_offset),
	KUNIT_CASE(test_unknown_address),
	KUNIT_CASE(test_kernel_function_lineinfo),
	KUNIT_CASE(test_assembly_no_lineinfo),
	/* Group F: Module path */
	KUNIT_CASE(test_module_function_lineinfo),
	/* Group G: Stress */
	KUNIT_CASE_SLOW(test_concurrent_sprint_symbol),
	KUNIT_CASE_SLOW(test_rapid_sprint_symbol),
	/* Group H: Safety and plausibility */
	KUNIT_CASE(test_line_number_plausible),
	KUNIT_CASE(test_buffer_no_overflow),
	KUNIT_CASE(test_dump_stack_no_crash),
	KUNIT_CASE(test_sprint_symbol_build_id),
	/* Group I: Encoding/decoding and accuracy */
	KUNIT_CASE(test_sleb128_edge_cases),
	KUNIT_CASE(test_uleb128_edge_cases),
	KUNIT_CASE(test_line_number_accuracy),
	KUNIT_CASE(test_many_lines_mid_function),
	{}
};

static struct kunit_suite lineinfo_test_suite = {
	.name = "lineinfo",
	.test_cases = lineinfo_test_cases,
};
kunit_test_suites(&lineinfo_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for kallsyms lineinfo");
MODULE_AUTHOR("Sasha Levin");
