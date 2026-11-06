/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_tickbug: keep a task runnable on a CPU that is in the idle loop.
 *
 * This scheduler exists to hold one state for a controllable length of time:
 * the idle task running on a CPU whose run queue is not empty.
 *
 * enqueue_task_scx() raises rq->nr_running before it calls ops.enqueue(), so a
 * BPF scheduler that stashes the task somewhere of its own - here a BPF queue
 * map - leaves it runnable and accounted on that CPU with nothing for the CPU
 * to pick. The CPU enters the idle loop and stays there. In that state
 * idle_cpu() is false, because idle_rq() tests rq->nr_running, while
 * is_idle_task(current) is true.
 *
 * tick_irq_exit() used to ask idle_cpu(), so every interrupt taken in that
 * idle loop skipped tick_nohz_irq_exit(). Each skip leaves TS_FLAG_IDLE_ACTIVE
 * clear, and the next exit from the idle loop then also skips
 * sched_clock_idle_wakeup_event(), so with an unstable sched_clock the CPU's
 * clock is never resynchronized: the task picked next starts with a stale
 * exec_start and the next tick charges it the whole idle stretch.
 *
 * The in-tree example schedulers can reach this state but not hold it.
 * scx_central stashes a task in a BPF queue exactly like this, then
 * immediately calls scx_bpf_kick_cpu(), so the window is microseconds wide and
 * nothing measurable accumulates. Here the only thing that releases a held
 * task is a periodic timer, so the window is hold_ns wide and can be swept.
 *
 * Only tasks named by @tag_comm are held; everything else runs through a
 * shared DSQ so the machine stays usable while the test runs. @target_cpu does
 * not pull from that shared DSQ while it is holding something: shared work
 * running there would take the CPU out of the state under test and make the
 * hold this scheduler reports an overestimate.
 *
 * Copyright (c) 2026 Radu Toader
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

enum {
	SHARED_DSQ	= 0,
	MS_TO_NS	= 1000LLU * 1000,
};

/* CPU whose run queue holds the tagged task while the CPU idles. */
const volatile s32 target_cpu;
/* CPU the release timer is pinned to. Must not be @target_cpu. */
const volatile s32 timer_cpu = 1;
/* How long a tagged task is held before it is allowed to run. */
const volatile u64 hold_ns = 10 * MS_TO_NS;
const volatile u64 slice_ns;

bool timer_pinned = true;
bool timer_started;

/*
 * Set by the release timer, consumed by ops.dispatch() on @target_cpu. Without
 * it ops.dispatch() would hand the held task straight back out, because the
 * core calls ops.dispatch() whenever the CPU is about to go idle.
 */
bool release_now;

u64 nr_enq, nr_held, nr_released, nr_timers;
u64 nr_passthru, nr_locals, nr_lost, nr_other_cpu, nr_overflow, nr_requeue;
u64 nr_last, nr_dup, nr_stale, nr_undone;
/*
 * How many tagged tasks are held right now. The release timer only kicks when
 * this is non-zero: a kick with nothing held would preempt whatever is running
 * on @target_cpu, and since that is normally the task just released, the task
 * would lose most of its CPU to its own release mechanism. The first version of
 * this scheduler did exactly that and reported half the usage it should.
 */
u64 nr_held_now;
/* Proof that the hold actually happened, and how wide it was. */
u64 total_held_ns, max_held_ns;

UEI_DEFINE(uei);

/*
 * One queued hold. The timestamp travels with the pid: a single global would
 * be overwritten by the second task to be held and would then mismeasure both.
 */
struct hold_entry {
	s32	pid;
	u64	at;
};

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct hold_entry);
} hold_q SEC(".maps");

/*
 * Whether this task's pid is parked in @hold_q. @hold_q cannot be searched or
 * amended, so this flag is the authority on whether a queued entry is still
 * live: ops.dequeue() clears it when the task leaves BPF custody behind the
 * scheduler's back, and release_one() then drops the entry it finds.
 */
struct task_ctx {
	bool	held;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct tickbug_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tickbug_timer);
} release_timer SEC(".maps");

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		scx_bpf_error("no task_ctx for %d (%s)", p->pid, p->comm);
	return tctx;
}

/*
 * The load generator is called "spin". Compare 5 bytes so the terminating NUL
 * has to match too and a longer name starting with "spin" is not held.
 */
static bool is_tagged(struct task_struct *p)
{
	return !bpf_strncmp(p->comm, 5, "spin");
}

s32 BPF_STRUCT_OPS(tickbug_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	if (is_tagged(p))
		return target_cpu;
	return prev_cpu;
}

/*
 * Deal with a tagged task: park it on @target_cpu's run queue, or decide that
 * it cannot be held. Returns true if @p has been taken care of and must not go
 * on to the shared DSQ.
 */
static bool handle_tagged(struct task_struct *p, struct task_ctx *tctx,
			  u64 enq_flags)
{
	struct hold_entry ent = { .pid = p->pid };

	if (scx_bpf_task_cpu(p) != target_cpu) {
		/*
		 * ops.select_cpu() is only a hint and is not called on every
		 * path. Counted rather than forced: a run with a non-zero
		 * count here did not test what it meant to.
		 */
		__sync_fetch_and_add(&nr_other_cpu, 1);
		return false;
	}

	if (tctx->held) {
		/*
		 * Already parked. Pushing the pid again would hold one task
		 * twice and leave an entry behind for the release timer to
		 * trip over.
		 */
		__sync_fetch_and_add(&nr_dup, 1);
		return true;
	}

	if (!(enq_flags & SCX_ENQ_LAST) && scx_bpf_task_running(p)) {
		/*
		 * Re-enqueued while it is the current scheduling context, e.g.
		 * after a kthread preempted it. Holding it here would take CPU
		 * away from work already in progress, which is not the state
		 * under test: the hold belongs at the start of a run, not in
		 * the middle of one. Put it straight back so it carries on.
		 *
		 * %SCX_ENQ_LAST is excluded because it is not that case. It
		 * arrives from put_prev_task_scx(), where rq->donor is still
		 * @p - put_prev_set_next_task() asserts as much - so
		 * scx_bpf_task_running() is true for every enqueue on that
		 * path, while the CPU is in fact about to go idle with @p as
		 * the only runnable task. That is what has to be held.
		 */
		__sync_fetch_and_add(&nr_requeue, 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return true;
	}

	ent.at = scx_bpf_now() ?: 1;
	if (bpf_map_push_elem(&hold_q, &ent, 0)) {
		__sync_fetch_and_add(&nr_overflow, 1);
		return false;
	}

	/*
	 * This is the whole scheduler. The task is already in target_cpu's
	 * rq->nr_running; parking its pid here and deliberately not kicking
	 * the CPU leaves it in the idle loop with a runnable task queued.
	 */
	tctx->held = true;
	__sync_fetch_and_add(&nr_held, 1);
	__sync_fetch_and_add(&nr_held_now, 1);
	return true;
}

void BPF_STRUCT_OPS(tickbug_enqueue, struct task_struct *p, u64 enq_flags)
{
	bool last = enq_flags & SCX_ENQ_LAST;
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_enq, 1);
	if (last)
		__sync_fetch_and_add(&nr_last, 1);

	/*
	 * ops.init() kicks @timer_cpu so that ops.dispatch() runs there and
	 * arms the timer, but a kick does not guarantee an ops.dispatch()
	 * call: dispatch_one() keeps a @prev that still has slice left, and
	 * takes the local DSQ when it is not empty, without asking the
	 * scheduler. Retry from here, because a hold taken before the timer is
	 * up would never be released.
	 */
	if (unlikely(!timer_started))
		scx_bpf_kick_cpu(timer_cpu, SCX_KICK_PREEMPT);

	/*
	 * Per-CPU kthreads go to the head of their own CPU's local DSQ with
	 * preemption. The release timer runs from a softirq, so if a kthread
	 * such as ksoftirqd were starved behind a user task the held task
	 * would never be released.
	 */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		__sync_fetch_and_add(&nr_locals, 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (is_tagged(p) && handle_tagged(p, tctx, enq_flags))
		return;

	__sync_fetch_and_add(&nr_passthru, 1);

	/*
	 * A %SCX_ENQ_LAST task stays on its own CPU. put_prev_task_scx() sets
	 * need_resched on the incoming idle task only if the enqueue landed on
	 * the local DSQ, so a task left in a shared DSQ here would sit there
	 * until some other CPU happened to drain it.
	 */
	if (last)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
	else
		scx_bpf_dsq_insert(p, SHARED_DSQ, slice_ns, enq_flags);
}

void BPF_STRUCT_OPS(tickbug_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx || !tctx->held)
		return;

	/*
	 * A parked task is leaving BPF custody without going through
	 * release_one(): an affinity or property change, a class change, or
	 * exit. Give up the hold now. Its entry stays in @hold_q, where
	 * release_one() recognises it by this flag and drops it.
	 */
	tctx->held = false;
	__sync_fetch_and_add(&nr_undone, 1);
	__sync_fetch_and_sub(&nr_held_now, 1);
}

/* Let one held task run on the CPU we are dispatching for. */
static bool release_one(void)
{
	struct hold_entry ent;
	struct task_ctx *tctx;
	struct task_struct *p;

	bpf_repeat(BPF_MAX_LOOPS) {
		u64 now;

		if (bpf_map_pop_elem(&hold_q, &ent))
			return false;

		/*
		 * Gone, or the pid belongs to someone else by now.
		 * ops.dequeue() has already accounted the hold.
		 */
		p = bpf_task_from_pid(ent.pid);
		if (!p) {
			__sync_fetch_and_add(&nr_lost, 1);
			continue;
		}

		tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (!tctx || !tctx->held) {
			__sync_fetch_and_add(&nr_stale, 1);
			bpf_task_release(p);
			continue;
		}

		tctx->held = false;
		__sync_fetch_and_sub(&nr_held_now, 1);

		/*
		 * Affinity may have changed while the task sat in the queue.
		 * Such a task goes to the shared DSQ instead of being pinned
		 * to a CPU it is no longer allowed on.
		 */
		if (!bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr) ||
		    is_migration_disabled(p)) {
			scx_bpf_dsq_insert(p, SHARED_DSQ, slice_ns, 0);
			bpf_task_release(p);
			if (!scx_bpf_dispatch_nr_slots())
				return false;
			continue;
		}

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		bpf_task_release(p);

		now = scx_bpf_now();
		if (ent.at && now > ent.at) {
			u64 d = now - ent.at;

			__sync_fetch_and_add(&total_held_ns, d);
			if (d > max_held_ns)
				max_held_ns = d;
		}

		__sync_fetch_and_add(&nr_released, 1);
		return true;
	}

	return false;
}

static void start_release_timer(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int ret;

	if (likely(timer_started))
		return;

	/*
	 * BPF_F_TIMER_CPU_PIN pins to the CPU running bpf_timer_start(), which
	 * is not necessarily the CPU ops.dispatch() was called for: under core
	 * scheduling a pick runs for every SMT sibling from one CPU. Arming it
	 * from the wrong CPU could pin the timer to @target_cpu, which is the
	 * one CPU the release path cannot run on.
	 */
	if (bpf_get_smp_processor_id() != timer_cpu)
		return;

	timer = bpf_map_lookup_elem(&release_timer, &key);
	if (!timer) {
		scx_bpf_error("failed to look up the release timer");
		return;
	}

	ret = bpf_timer_start(timer, hold_ns, BPF_F_TIMER_CPU_PIN);
	if (ret == -EINVAL) {
		/* BPF_F_TIMER_CPU_PIN needs >= 6.7 */
		timer_pinned = false;
		ret = bpf_timer_start(timer, hold_ns, 0);
	}
	if (ret) {
		scx_bpf_error("bpf_timer_start failed (%d)", ret);
		return;
	}

	timer_started = true;
}

void BPF_STRUCT_OPS(tickbug_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Arm the timer from the CPU it must be pinned to. ops.init() runs in
	 * whatever context loaded the scheduler, which is the wrong CPU.
	 */
	if (cpu == timer_cpu)
		start_release_timer();

	if (cpu == target_cpu) {
		if (release_now) {
			release_now = false;
			if (release_one())
				return;
		}

		/*
		 * Leave @target_cpu in the idle loop for as long as it is
		 * holding something. Taking shared work here would end the
		 * idle stretch under test, and the hold reported for the task
		 * would cover time the CPU spent running.
		 */
		if (nr_held_now)
			return;
	}

	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

static int release_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 curr_cpu = bpf_get_smp_processor_id();
	int ret;

	if (timer_pinned && curr_cpu != timer_cpu) {
		scx_bpf_error("release timer ran on CPU %d, not timer CPU %d",
			      curr_cpu, timer_cpu);
		return 0;
	}

	/*
	 * Nothing held means @target_cpu is either idle with an empty run
	 * queue or busy with the task released last time. Kicking in either
	 * case is at best pointless and at worst preempts that task.
	 */
	if (!nr_held_now)
		goto rearm;

	/*
	 * Allow one held task through and make @target_cpu notice.
	 * SCX_KICK_PREEMPT sends a reschedule IPI, which does not go through
	 * irq_enter() and so does not run tick_irq_exit() itself: it only ends
	 * the idle stretch whose bookkeeping the mis-gated interrupts dropped.
	 */
	release_now = true;
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);

rearm:

	__sync_fetch_and_add(&nr_timers, 1);

	ret = bpf_timer_start(timer, hold_ns,
			      timer_pinned ? BPF_F_TIMER_CPU_PIN : 0);
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);
	return 0;
}

s32 BPF_STRUCT_OPS(tickbug_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	/* Sleepable, so this allocation can use GFP_KERNEL. */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->held = false;

	return 0;
}

int BPF_STRUCT_OPS_SLEEPABLE(tickbug_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int ret;

	if (target_cpu == timer_cpu) {
		scx_bpf_error("target and timer CPU must differ (both %d)",
			      target_cpu);
		return -EINVAL;
	}

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret) {
		scx_bpf_error("scx_bpf_create_dsq failed (%d)", ret);
		return ret;
	}

	timer = bpf_map_lookup_elem(&release_timer, &key);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &release_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, release_timerfn);

	/* Get ops.dispatch() to run on @timer_cpu so it arms the timer. */
	scx_bpf_kick_cpu(timer_cpu, 0);

	return 0;
}

void BPF_STRUCT_OPS(tickbug_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(tickbug_ops,
	       /*
		* The last runnable task on a CPU has to come through
		* ops.enqueue() too, otherwise the tagged task would simply
		* keep running on @target_cpu and never be held.
		*/
	       .flags			= SCX_OPS_ENQ_LAST,

	       .select_cpu		= (void *)tickbug_select_cpu,
	       .enqueue			= (void *)tickbug_enqueue,
	       .dequeue			= (void *)tickbug_dequeue,
	       .dispatch		= (void *)tickbug_dispatch,
	       .init_task		= (void *)tickbug_init_task,
	       .init			= (void *)tickbug_init,
	       .exit			= (void *)tickbug_exit,
	       /*
		* A held task is runnable and not running, which is what the
		* watchdog looks for. Keep the timeout well above any hold.
		*/
	       .timeout_ms		= 5000U,
	       .name			= "tickbug");
