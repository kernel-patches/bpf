// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf_atomic.h>
#include <bpf/bpf_helpers.h>
#include <bpf_experimental.h>

#define EDEADLK		35
#define EBUSY		16
#define ETIMEDOUT	110
#define CONCTEST_HIST_BUCKETS 28

int nr_cpus;
__u32 delay_seed;

enum conctest_stat_id {
	CONCTEST_STAT_SYSCALL = 0,
	CONCTEST_STAT_NMI,
	CONCTEST_STAT_MAX,
};

struct conctest_op_stats {
	__u64 count;
	__u64 success;
	__u64 failure;
	__u64 unexpected;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
	__u64 hist[CONCTEST_HIST_BUCKETS];
};

struct conctest_op_state {
	__s64 expect_ret;
	__u64 delay_thresh_ns;
	__u64 failed_print_once;
	__u64 delay_print_once;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CONCTEST_STAT_MAX);
	__type(key, int);
	__type(value, struct conctest_op_stats);
} perf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CONCTEST_STAT_MAX);
	__type(key, int);
	__type(value, struct conctest_op_state);
} state_map SEC(".maps");

enum ctx_level {
	CTX_TASK = 0,
	CTX_SOFTIRQ,
	CTX_HARDIRQ,
	CTX_NMI,
	CTX_MAX,
};

struct ctx_time {
	__u64 accumulated_ns[CTX_MAX];
	__u64 start_ns[CTX_MAX];
	__u64 snapshot[CTX_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ctx_time);
} ctx_time_map SEC(".maps");

static __always_inline enum ctx_level get_ctx_level(void)
{
	int pcnt = get_preempt_count();

	if (pcnt & NMI_MASK)
		return CTX_NMI;
	if (pcnt & HARDIRQ_MASK)
		return CTX_HARDIRQ;
	if (pcnt & SOFTIRQ_MASK)
		return CTX_SOFTIRQ;
	return CTX_TASK;
}

static __always_inline __u64 ctx_higher_sum(struct ctx_time *ct, enum ctx_level level)
{
	__u64 sum = 0;
	int i;

	for (i = level + 1; i < CTX_MAX; i++)
		sum += ct->accumulated_ns[i];
	return sum;
}

static __always_inline void conctest_begin(void)
{
	struct ctx_time *ct;
	enum ctx_level level;
	int key = 0;

	ct = bpf_map_lookup_elem(&ctx_time_map, &key);
	if (!ct)
		return;

	level = get_ctx_level();
	ct->snapshot[level] = ctx_higher_sum(ct, level);
	ct->start_ns[level] = bpf_ktime_get_ns();
}

/*
 *   0: [0, 1µs)           1: [1µs, 100µs)
 *   2: [100µs, 200µs) ... 10: [900µs, 1ms)
 *  11: [1ms, 10ms)        12: [10ms, 20ms) ... 20: [90ms, 100ms)
 *  21: [100ms, 150ms)     22: [150ms, 200ms)   23: [200ms, 250ms)
 *  24: [250ms, 500ms)     25: [500ms, 750ms)   26: [750ms, 1s)
 *  27: [1s, inf)
 */
static __always_inline __u32 hist_bucket(__u64 ns)
{
	if (ns < 1000)
		return 0;
	if (ns < 100000)
		return 1;
	if (ns < 1000000)
		return 2 + (ns - 100000) / 100000;
	if (ns < 10000000)
		return 11;
	if (ns < 100000000)
		return 12 + (ns - 10000000) / 10000000;
	if (ns < 250000000)
		return 21 + (ns - 100000000) / 50000000;
	if (ns < 1000000000)
		return 24 + (ns - 250000000) / 250000000;
	return 27;
}

static __always_inline void conctest_record(int stat_id, __s64 ret, bool ctx_adjust)
{
	__u64 raw, higher_ns, duration_ns;
	struct conctest_op_state *state;
	struct conctest_op_stats *stats;
	struct ctx_time *ct;
	enum ctx_level level;
	__u32 bucket;
	int key = 0;

	ct = bpf_map_lookup_elem(&ctx_time_map, &key);
	if (!ct)
		return;

	level = get_ctx_level();
	raw = bpf_ktime_get_ns() - ct->start_ns[level];

	if (ctx_adjust) {
		higher_ns = ctx_higher_sum(ct, level) - ct->snapshot[level];
		duration_ns = raw > higher_ns ? raw - higher_ns : 0;

		ct->accumulated_ns[level] += raw;
	} else {
		duration_ns = raw;
	}

	stats = bpf_map_lookup_elem(&perf_map, &stat_id);
	if (!stats)
		return;

	state = bpf_map_lookup_elem(&state_map, &stat_id);
	if (!state)
		return;

	if (stats->count == 0 || duration_ns < stats->min_ns)
		stats->min_ns = duration_ns;
	if (duration_ns > stats->max_ns)
		stats->max_ns = duration_ns;

	stats->count++;
	stats->total_ns += duration_ns;

	bucket = hist_bucket(duration_ns);
	if (bucket < CONCTEST_HIST_BUCKETS)
		stats->hist[bucket]++;

	if (ret == 0) {
		stats->success++;
	} else if (!state->expect_ret || ret == state->expect_ret) {
		stats->failure++;
	} else {
		stats->failure++;
		stats->unexpected++;
		if (!cmpxchg(&state->failed_print_once, 0, 1)) {
			bpf_stream_printk(BPF_STDOUT,
					  "UNEXPECTED ERROR: stat %d expected %lld got %lld\n",
					  stat_id, state->expect_ret, ret);
			bpf_stream_print_stack(BPF_STDOUT);
		}
	}

	u64 delay_thresh_ns = state->delay_thresh_ns;
	if (!delay_thresh_ns)
		delay_thresh_ns = 10000000; /* 10ms */
	if (delay_thresh_ns && duration_ns > delay_thresh_ns && !cmpxchg(&state->delay_print_once, 0, 1)) {
		const char *unit = duration_ns >= 1000000 ? "ms" : "ns";
		bpf_stream_printk(BPF_STDOUT,
				  "DELAY EXCEEDED: stat %d duration %llu %s > threshold %llu %s\n",
				  stat_id, duration_ns / 1000000, unit, delay_thresh_ns / 1000000,
				  unit);
		bpf_stream_print_stack(BPF_STDOUT);
	}
}

static __always_inline void bpf_udelay(__u32 us)
{
	__u64 target = bpf_ktime_get_ns() + (__u64)us * 1000;

	while (bpf_ktime_get_ns() < target && can_loop)
		;
}

struct lock_val {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, struct lock_val);
} lock_map SEC(".maps");

SEC("?syscall")
int conctest_rqspinlock_task(void *ctx)
{
	struct lock_val *e;
	__u32 key;
	int ret;

	key = bpf_get_smp_processor_id();
	key %= (__u32)nr_cpus;
	e = bpf_map_lookup_elem(&lock_map, &key);
	if (!e)
		return 0;

	conctest_begin();
	ret = bpf_res_spin_lock(&e->lock);
	if (ret == 0) {
		bpf_udelay(delay_seed);
		bpf_res_spin_unlock(&e->lock);
	}
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);

	return 0;
}

static int __conctest_rqspinlock_nmi(int start)
{
	struct lock_val *e;
	__u32 key = start;
	int ret;

	key += bpf_get_smp_processor_id();
	key %= (__u32)nr_cpus;
	e = bpf_map_lookup_elem(&lock_map, &key);
	if (!e)
		return 0;

	conctest_begin();
	ret = bpf_res_spin_lock(&e->lock);
	if (ret == 0)
		bpf_res_spin_unlock(&e->lock);
	conctest_record(CONCTEST_STAT_NMI, ret, true);

	return 0;
}

SEC("?perf_event")
int conctest_rqspinlock_nmi(void *ctx)
{
	return __conctest_rqspinlock_nmi(0);
}

SEC("?perf_event")
int conctest_rqspinlock_nmi_shift(void *ctx)
{
	return __conctest_rqspinlock_nmi(1);
}

#define CLOCK_MONOTONIC	    1
#define BPF_F_TIMER_CPU_PIN (1ULL << 1)

struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_elem);
} timer_map SEC(".maps");

static int timer_callback(void *map, int *key, struct timer_elem *val)
{
	bpf_timer_start(&val->timer, 0, BPF_F_TIMER_CPU_PIN);
	return 0;
}

SEC("?syscall")
int conctest_timer_init(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	ret = bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
	if (ret && ret != -EBUSY)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, timer_callback);
	if (ret)
		return ret;

	return bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
}

SEC("?syscall")
int conctest_timer_task_reinit(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_timer_nmi_reinit(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_timer_task_start(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_timer_task_cancel(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_cancel(&elem->timer);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_timer_task_cancel_async(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_cancel_async(&elem->timer);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_timer_task_set_cb(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_set_callback(&elem->timer, timer_callback);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_timer_task_delete(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	/* Delete the element (cancels + frees timer) */
	conctest_begin();
	ret = bpf_map_delete_elem(&timer_map, &key);
	if (ret == 0) {
		/* Re-init so subsequent ops still work */
		elem = bpf_map_lookup_elem(&timer_map, &key);
		if (elem) {
			bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&elem->timer, timer_callback);
			bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
		}
	}
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_timer_nmi_start(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_timer_nmi_cancel_async(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_cancel_async(&elem->timer);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_timer_nmi_set_cb(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_timer_set_callback(&elem->timer, timer_callback);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_timer_nmi_delete(void *ctx)
{
	struct timer_elem *elem;
	int key = 0, ret;

	conctest_begin();
	ret = bpf_map_delete_elem(&timer_map, &key);
	if (ret == 0) {
		elem = bpf_map_lookup_elem(&timer_map, &key);
		if (elem) {
			bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&elem->timer, timer_callback);
			bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
		}
	}
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

struct wq_elem {
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static int wq_callback(void *map, int *key, void *val)
{
	return 0;
}

SEC("?syscall")
int conctest_wq_init(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		return ret;

	return bpf_wq_set_callback(&elem->work, wq_callback, 0);
}

SEC("?syscall")
int conctest_wq_task_start(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_wq_start(&elem->work, 0);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_wq_task_set_cb(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_wq_set_callback(&elem->work, wq_callback, 0);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_wq_nmi_start(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_wq_start(&elem->work, 0);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_wq_nmi_set_cb(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_wq_set_callback(&elem->work, wq_callback, 0);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_wq_task_delete(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	conctest_begin();
	ret = bpf_map_delete_elem(&wq_map, &key);
	if (ret == 0) {
		elem = bpf_map_lookup_elem(&wq_map, &key);
		if (elem) {
			bpf_wq_init(&elem->work, &wq_map, 0);
			bpf_wq_set_callback(&elem->work, wq_callback, 0);
		}
	}
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_wq_nmi_delete(void *ctx)
{
	struct wq_elem *elem;
	int key = 0, ret;

	conctest_begin();
	ret = bpf_map_delete_elem(&wq_map, &key);
	if (ret == 0) {
		elem = bpf_map_lookup_elem(&wq_map, &key);
		if (elem) {
			bpf_wq_init(&elem->work, &wq_map, 0);
			bpf_wq_set_callback(&elem->work, wq_callback, 0);
		}
	}
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

struct tw_elem {
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct tw_elem);
} tw_map SEC(".maps");

static int tw_callback(struct bpf_map *map, void *key, void *value)
{
	return 0;
}

SEC("?syscall")
int conctest_tw_task_signal(void *ctx)
{
	struct tw_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_task_work_schedule_signal(bpf_get_current_task_btf(),
					    &elem->tw, &tw_map, tw_callback);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_tw_task_resume(void *ctx)
{
	struct tw_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_task_work_schedule_resume(bpf_get_current_task_btf(),
					    &elem->tw, &tw_map, tw_callback);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_tw_nmi_signal(void *ctx)
{
	struct tw_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_task_work_schedule_signal(bpf_get_current_task_btf(),
					    &elem->tw, &tw_map, tw_callback);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_tw_nmi_resume(void *ctx)
{
	struct tw_elem *elem;
	int key = 0, ret;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;

	conctest_begin();
	ret = bpf_task_work_schedule_resume(bpf_get_current_task_btf(),
					    &elem->tw, &tw_map, tw_callback);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

SEC("?syscall")
int conctest_tw_task_delete(void *ctx)
{
	int key = 0, ret;

	conctest_begin();
	ret = bpf_map_delete_elem(&tw_map, &key);
	conctest_record(CONCTEST_STAT_SYSCALL, ret, true);
	return 0;
}

SEC("?perf_event")
int conctest_tw_nmi_delete(void *ctx)
{
	int key = 0, ret;

	conctest_begin();
	ret = bpf_map_delete_elem(&tw_map, &key);
	conctest_record(CONCTEST_STAT_NMI, ret, true);
	return 0;
}

char _license[] SEC("license") = "GPL";
