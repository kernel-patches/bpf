// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KUnit synthetic performance benchmark for VM statistics.
 *
 * (C) 2009 Linux Foundation, Christoph Lameter <cl@gentwo.org>
 * (C) 2026 Google LLC, David Rientjes <rientjes@google.com>
 */
#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/timex.h>
#include <linux/ktime.h>
#include <linux/math64.h>

#define TEST_COUNT 10000

static void vmstat_test_free_page(void *arg)
{
	__free_page((struct page *)arg);
}

/*
 * Test 1: Sequential inc_zone_page_state() followed by dec_zone_page_state().
 * Net change to zone counters is 0.
 */
static void vmstat_test_inc_dec_zone_page_state(struct kunit *test)
{
	struct page *page;
	cycles_t time1, time2, time;
	u64 t1_ns, t2_ns;
	u64 inc_cycles, dec_cycles;
	u64 inc_ns, dec_ns;
	unsigned int i;

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, vmstat_test_free_page, page), 0);

	/* Benchmark inc_zone_page_state() */
	time1 = get_cycles();
	t1_ns = ktime_get_ns();
	for (i = 0; i < TEST_COUNT; i++)
		inc_zone_page_state(page, NR_MLOCK);
	t2_ns = ktime_get_ns();
	time2 = get_cycles();

	time = time2 - time1;
	inc_cycles = div_u64(time, TEST_COUNT);
	inc_ns = div_u64(t2_ns - t1_ns, TEST_COUNT);

	/* Benchmark dec_zone_page_state() */
	time1 = get_cycles();
	t1_ns = ktime_get_ns();
	for (i = 0; i < TEST_COUNT; i++)
		dec_zone_page_state(page, NR_MLOCK);
	t2_ns = ktime_get_ns();
	time2 = get_cycles();

	time = time2 - time1;
	dec_cycles = div_u64(time, TEST_COUNT);
	dec_ns = div_u64(t2_ns - t1_ns, TEST_COUNT);

	if (inc_cycles || dec_cycles)
		kunit_info(test, "%u ops: inc_zone_page_state -> %llu cycles (%llu ns/op), dec_zone_page_state -> %llu cycles (%llu ns/op)\n",
			   TEST_COUNT, inc_cycles, inc_ns, dec_cycles, dec_ns);
	else
		kunit_info(test, "%u ops: inc_zone_page_state -> %llu ns/op, dec_zone_page_state -> %llu ns/op\n",
			   TEST_COUNT, inc_ns, dec_ns);
}

/*
 * Test 2: Paired inc_zone_page_state() and dec_zone_page_state().
 * Net change to zone counters is 0.
 */
static void vmstat_test_interleaved_zone_page_state(struct kunit *test)
{
	struct page *page;
	cycles_t time1, time2, time;
	u64 t1_ns, t2_ns;
	u64 avg_cycles, avg_ns;
	unsigned int i;

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, vmstat_test_free_page, page), 0);

	time1 = get_cycles();
	t1_ns = ktime_get_ns();
	for (i = 0; i < TEST_COUNT; i++) {
		inc_zone_page_state(page, NR_MLOCK);
		dec_zone_page_state(page, NR_MLOCK);
	}
	t2_ns = ktime_get_ns();
	time2 = get_cycles();

	time = time2 - time1;
	avg_cycles = div_u64(time, TEST_COUNT);
	avg_ns = div_u64(t2_ns - t1_ns, TEST_COUNT);

	if (avg_cycles)
		kunit_info(test, "%u ops: inc/dec pair -> %llu cycles (%llu ns/op)\n",
			   TEST_COUNT, avg_cycles, avg_ns);
	else
		kunit_info(test, "%u ops: inc/dec pair -> %llu ns/op\n",
			   TEST_COUNT, avg_ns);
}

/*
 * Test 3: count_vm_event() benchmark.
 * Restores counter balance with count_vm_events(item, -TEST_COUNT).
 */
static void vmstat_test_count_vm_event(struct kunit *test)
{
	cycles_t time1, time2, time;
	u64 t1_ns, t2_ns;
	u64 avg_cycles, avg_ns;
	unsigned int i;

	time1 = get_cycles();
	t1_ns = ktime_get_ns();
	for (i = 0; i < TEST_COUNT; i++)
		count_vm_event(SLABS_SCANNED);
	t2_ns = ktime_get_ns();
	time2 = get_cycles();

	/* Restore balance */
	count_vm_events(SLABS_SCANNED, -TEST_COUNT);

	time = time2 - time1;
	avg_cycles = div_u64(time, TEST_COUNT);
	avg_ns = div_u64(t2_ns - t1_ns, TEST_COUNT);

	if (avg_cycles)
		kunit_info(test, "%u ops: count_vm_event -> %llu cycles (%llu ns/op)\n",
			   TEST_COUNT, avg_cycles, avg_ns);
	else
		kunit_info(test, "%u ops: count_vm_event -> %llu ns/op\n",
			   TEST_COUNT, avg_ns);
}

static struct kunit_case vmstat_test_cases[] = {
	KUNIT_CASE(vmstat_test_inc_dec_zone_page_state),
	KUNIT_CASE(vmstat_test_interleaved_zone_page_state),
	KUNIT_CASE(vmstat_test_count_vm_event),
	{}
};

static struct kunit_suite vmstat_test_suite = {
	.name = "vmstat",
	.test_cases = vmstat_test_cases,
};
kunit_test_suite(vmstat_test_suite);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christoph Lameter <cl@gentwo.org>");
MODULE_AUTHOR("David Rientjes <rientjes@google.com>");
MODULE_DESCRIPTION("KUnit benchmark test for VM statistics");
