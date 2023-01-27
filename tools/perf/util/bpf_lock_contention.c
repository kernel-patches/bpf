// SPDX-License-Identifier: GPL-2.0
#include "util/debug.h"
#include "util/evlist.h"
#include "util/machine.h"
#include "util/map.h"
#include "util/symbol.h"
#include "util/target.h"
#include "util/thread.h"
#include "util/thread_map.h"
#include "util/lock-contention.h"
#include <linux/zalloc.h>
#include <linux/string.h>
#include <bpf/bpf.h>

#include "bpf_skel/lock_contention.skel.h"
#include "bpf_skel/lock_data.h"

static struct lock_contention_bpf *skel;

int lock_contention_prepare(struct lock_contention *con)
{
	int i, fd;
	int ncpus = 1, ntasks = 1, ntypes = 1, naddrs = 1;
	struct evlist *evlist = con->evlist;
	struct target *target = con->target;

	skel = lock_contention_bpf__open();
	if (!skel) {
		pr_err("Failed to open lock-contention BPF skeleton\n");
		return -1;
	}

	bpf_map__set_value_size(skel->maps.stacks, con->max_stack * sizeof(u64));
	bpf_map__set_max_entries(skel->maps.lock_stat, con->map_nr_entries);
	bpf_map__set_max_entries(skel->maps.tstamp, con->map_nr_entries);

	if (con->aggr_mode == LOCK_AGGR_TASK) {
		bpf_map__set_max_entries(skel->maps.task_data, con->map_nr_entries);
		bpf_map__set_max_entries(skel->maps.stacks, 1);
	} else {
		bpf_map__set_max_entries(skel->maps.task_data, 1);
		bpf_map__set_max_entries(skel->maps.stacks, con->map_nr_entries);
	}

	if (target__has_cpu(target))
		ncpus = perf_cpu_map__nr(evlist->core.user_requested_cpus);
	if (target__has_task(target))
		ntasks = perf_thread_map__nr(evlist->core.threads);
	if (con->filters->nr_types)
		ntypes = con->filters->nr_types;

	/* resolve lock name filters to addr */
	if (con->filters->nr_syms) {
		struct symbol *sym;
		struct map *kmap;
		unsigned long *addrs;

		for (i = 0; i < con->filters->nr_syms; i++) {
			sym = machine__find_kernel_symbol_by_name(con->machine,
								  con->filters->syms[i],
								  &kmap);
			if (sym == NULL) {
				pr_warning("ignore unknown symbol: %s\n",
					   con->filters->syms[i]);
				continue;
			}

			addrs = realloc(con->filters->addrs,
					(con->filters->nr_addrs + 1) * sizeof(*addrs));
			if (addrs == NULL) {
				pr_warning("memory allocation failure\n");
				continue;
			}

			addrs[con->filters->nr_addrs++] = kmap->unmap_ip(kmap, sym->start);
			con->filters->addrs = addrs;
		}
		naddrs = con->filters->nr_addrs;
	}

	bpf_map__set_max_entries(skel->maps.cpu_filter, ncpus);
	bpf_map__set_max_entries(skel->maps.task_filter, ntasks);
	bpf_map__set_max_entries(skel->maps.type_filter, ntypes);
	bpf_map__set_max_entries(skel->maps.addr_filter, naddrs);

	if (lock_contention_bpf__load(skel) < 0) {
		pr_err("Failed to load lock-contention BPF skeleton\n");
		return -1;
	}

	if (target__has_cpu(target)) {
		u32 cpu;
		u8 val = 1;

		skel->bss->has_cpu = 1;
		fd = bpf_map__fd(skel->maps.cpu_filter);

		for (i = 0; i < ncpus; i++) {
			cpu = perf_cpu_map__cpu(evlist->core.user_requested_cpus, i).cpu;
			bpf_map_update_elem(fd, &cpu, &val, BPF_ANY);
		}
	}

	if (target__has_task(target)) {
		u32 pid;
		u8 val = 1;

		skel->bss->has_task = 1;
		fd = bpf_map__fd(skel->maps.task_filter);

		for (i = 0; i < ntasks; i++) {
			pid = perf_thread_map__pid(evlist->core.threads, i);
			bpf_map_update_elem(fd, &pid, &val, BPF_ANY);
		}
	}

	if (target__none(target) && evlist->workload.pid > 0) {
		u32 pid = evlist->workload.pid;
		u8 val = 1;

		skel->bss->has_task = 1;
		fd = bpf_map__fd(skel->maps.task_filter);
		bpf_map_update_elem(fd, &pid, &val, BPF_ANY);
	}

	if (con->filters->nr_types) {
		u8 val = 1;

		skel->bss->has_type = 1;
		fd = bpf_map__fd(skel->maps.type_filter);

		for (i = 0; i < con->filters->nr_types; i++)
			bpf_map_update_elem(fd, &con->filters->types[i], &val, BPF_ANY);
	}

	if (con->filters->nr_addrs) {
		u8 val = 1;

		skel->bss->has_addr = 1;
		fd = bpf_map__fd(skel->maps.addr_filter);

		for (i = 0; i < con->filters->nr_addrs; i++)
			bpf_map_update_elem(fd, &con->filters->addrs[i], &val, BPF_ANY);
	}

	/* these don't work well if in the rodata section */
	skel->bss->stack_skip = con->stack_skip;
	skel->bss->aggr_mode = con->aggr_mode;

	lock_contention_bpf__attach(skel);
	return 0;
}

int lock_contention_start(void)
{
	skel->bss->enabled = 1;
	return 0;
}

int lock_contention_stop(void)
{
	skel->bss->enabled = 0;
	return 0;
}

int lock_contention_read(struct lock_contention *con)
{
	int fd, stack, task_fd, err = 0;
	struct contention_key *prev_key, key;
	struct contention_data data = {};
	struct lock_stat *st = NULL;
	struct machine *machine = con->machine;
	u64 *stack_trace;
	size_t stack_size = con->max_stack * sizeof(*stack_trace);

	fd = bpf_map__fd(skel->maps.lock_stat);
	stack = bpf_map__fd(skel->maps.stacks);
	task_fd = bpf_map__fd(skel->maps.task_data);

	con->lost = skel->bss->lost;

	stack_trace = zalloc(stack_size);
	if (stack_trace == NULL)
		return -1;

	if (con->aggr_mode == LOCK_AGGR_TASK) {
		struct thread *idle = __machine__findnew_thread(machine,
								/*pid=*/0,
								/*tid=*/0);
		thread__set_comm(idle, "swapper", /*timestamp=*/0);
	}

	/* make sure it loads the kernel map */
	map__load(maps__first(machine->kmaps));

	prev_key = NULL;
	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		struct map *kmap;
		struct symbol *sym;
		int idx = 0;
		s32 stack_id;

		/* to handle errors in the loop body */
		err = -1;

		bpf_map_lookup_elem(fd, &key, &data);
		st = zalloc(sizeof(*st));
		if (st == NULL)
			break;

		st->nr_contended = data.count;
		st->wait_time_total = data.total_time;
		st->wait_time_max = data.max_time;
		st->wait_time_min = data.min_time;

		if (data.count)
			st->avg_wait_time = data.total_time / data.count;

		st->flags = data.flags;
		st->addr = key.aggr_key;

		if (con->aggr_mode == LOCK_AGGR_TASK) {
			struct contention_task_data task;
			struct thread *t;
			int pid = key.aggr_key;

			/* do not update idle comm which contains CPU number */
			if (st->addr) {
				bpf_map_lookup_elem(task_fd, &pid, &task);
				t = __machine__findnew_thread(machine, /*pid=*/-1, pid);
				thread__set_comm(t, task.comm, /*timestamp=*/0);
			}
			goto next;
		}

		if (con->aggr_mode == LOCK_AGGR_ADDR) {
			sym = machine__find_kernel_symbol(machine, st->addr, &kmap);
			if (sym)
				st->name = strdup(sym->name);
			goto next;
		}

		stack_id = key.aggr_key;
		bpf_map_lookup_elem(stack, &stack_id, stack_trace);

		/* skip lock internal functions */
		while (machine__is_lock_function(machine, stack_trace[idx]) &&
		       idx < con->max_stack - 1)
			idx++;

		st->addr = stack_trace[idx];
		sym = machine__find_kernel_symbol(machine, st->addr, &kmap);

		if (sym) {
			unsigned long offset;
			int ret = 0;

			offset = kmap->map_ip(kmap, st->addr) - sym->start;

			if (offset)
				ret = asprintf(&st->name, "%s+%#lx", sym->name, offset);
			else
				st->name = strdup(sym->name);

			if (ret < 0 || st->name == NULL)
				break;
		} else if (asprintf(&st->name, "%#lx", (unsigned long)st->addr) < 0) {
			break;
		}

		if (con->save_callstack) {
			st->callstack = memdup(stack_trace, stack_size);
			if (st->callstack == NULL)
				break;
		}
next:
		hlist_add_head(&st->hash_entry, con->result);
		prev_key = &key;

		/* we're fine now, reset the values */
		st = NULL;
		err = 0;
	}

	free(stack_trace);
	if (st) {
		free(st->name);
		free(st);
	}

	return err;
}

int lock_contention_finish(void)
{
	if (skel) {
		skel->bss->enabled = 0;
		lock_contention_bpf__destroy(skel);
	}

	return 0;
}
