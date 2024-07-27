// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <perf/evsel.h>
#include <perf/cpumap.h>
#include <perf/threadmap.h>
#include <linux/list.h>
#include <internal/evsel.h>
#include <linux/zalloc.h>
#include <stdlib.h>
#include <internal/xyarray.h>
#include <internal/cpumap.h>
#include <internal/mmap.h>
#include <internal/threadmap.h>
#include <internal/lib.h>
#include <linux/string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <asm/bug.h>
#include <tools/opts.h>
#include "internal.h"

void perf_evsel__init(struct perf_evsel *evsel, struct perf_event_attr *attr,
		      int idx)
{
	INIT_LIST_HEAD(&evsel->node);
	evsel->attr = *attr;
	evsel->idx  = idx;
	evsel->leader = evsel;
	evsel->open_flags = 0;
}

struct perf_evsel *perf_evsel__new(struct perf_event_attr *attr)
{
	struct perf_evsel *evsel = zalloc(sizeof(*evsel));

	if (evsel != NULL)
		perf_evsel__init(evsel, attr, 0);

	return evsel;
}

void perf_evsel__delete(struct perf_evsel *evsel)
{
	free(evsel);
}

#define FD(_evsel, _cpu_map_idx, _thread)				\
	((int *)xyarray__entry(_evsel->fd, _cpu_map_idx, _thread))
#define MMAP(_evsel, _cpu_map_idx, _thread)				\
	(_evsel->mmap ? ((struct perf_mmap *) xyarray__entry(_evsel->mmap, _cpu_map_idx, _thread)) \
		      : NULL)

int perf_evsel__alloc_fd(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	evsel->fd = xyarray__new(ncpus, nthreads, sizeof(int));

	if (evsel->fd) {
		int idx, thread;

		for (idx = 0; idx < ncpus; idx++) {
			for (thread = 0; thread < nthreads; thread++) {
				int *fd = FD(evsel, idx, thread);

				if (fd)
					*fd = -1;
			}
		}
	}

	return evsel->fd != NULL ? 0 : -ENOMEM;
}

static int perf_evsel__alloc_mmap(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	evsel->mmap = xyarray__new(ncpus, nthreads, sizeof(struct perf_mmap));

	return evsel->mmap != NULL ? 0 : -ENOMEM;
}

static int
sys_perf_event_open(struct perf_event_attr *attr,
		    pid_t pid, struct perf_cpu cpu, int group_fd,
		    unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu.cpu, group_fd, flags);
}

static int get_group_fd(struct perf_evsel *evsel, int cpu_map_idx, int thread, int *group_fd)
{
	struct perf_evsel *leader = evsel->leader;
	int *fd;

	if (evsel == leader) {
		*group_fd = -1;
		return 0;
	}

	/*
	 * Leader must be already processed/open,
	 * if not it's a bug.
	 */
	if (!leader->fd)
		return -ENOTCONN;

	fd = FD(leader, cpu_map_idx, thread);
	if (fd == NULL || *fd == -1)
		return -EBADF;

	*group_fd = *fd;

	return 0;
}

int perf_evsel__open(struct perf_evsel *evsel, struct perf_cpu_map *cpus,
		     struct perf_thread_map *threads)
{
	struct perf_cpu cpu;
	int idx, thread, err = 0;

	if (cpus == NULL) {
		static struct perf_cpu_map *empty_cpu_map;

		if (empty_cpu_map == NULL) {
			empty_cpu_map = perf_cpu_map__new_any_cpu();
			if (empty_cpu_map == NULL)
				return -ENOMEM;
		}

		cpus = empty_cpu_map;
	}

	if (threads == NULL) {
		static struct perf_thread_map *empty_thread_map;

		if (empty_thread_map == NULL) {
			empty_thread_map = perf_thread_map__new_dummy();
			if (empty_thread_map == NULL)
				return -ENOMEM;
		}

		threads = empty_thread_map;
	}

	if (evsel->fd == NULL &&
	    perf_evsel__alloc_fd(evsel, perf_cpu_map__nr(cpus), threads->nr) < 0)
		return -ENOMEM;

	perf_cpu_map__for_each_cpu(cpu, idx, cpus) {
		for (thread = 0; thread < threads->nr; thread++) {
			int fd, group_fd, *evsel_fd;

			evsel_fd = FD(evsel, idx, thread);
			if (evsel_fd == NULL) {
				err = -EINVAL;
				goto out;
			}

			err = get_group_fd(evsel, idx, thread, &group_fd);
			if (err < 0)
				goto out;

			fd = sys_perf_event_open(&evsel->attr,
						 threads->map[thread].pid,
						 cpu, group_fd, evsel->open_flags);

			if (fd < 0) {
				err = -errno;
				goto out;
			}

			*evsel_fd = fd;
		}
	}
out:
	if (err)
		perf_evsel__close(evsel);

	return err;
}

static void perf_evsel__close_fd_cpu(struct perf_evsel *evsel, int cpu_map_idx)
{
	int thread;

	for (thread = 0; thread < xyarray__max_y(evsel->fd); ++thread) {
		int *fd = FD(evsel, cpu_map_idx, thread);

		if (fd && *fd >= 0) {
			close(*fd);
			*fd = -1;
		}
	}
}

void perf_evsel__close_fd(struct perf_evsel *evsel)
{
	for (int idx = 0; idx < xyarray__max_x(evsel->fd); idx++)
		perf_evsel__close_fd_cpu(evsel, idx);
}

void perf_evsel__free_fd(struct perf_evsel *evsel)
{
	xyarray__delete(evsel->fd);
	evsel->fd = NULL;
}

void perf_evsel__close(struct perf_evsel *evsel)
{
	if (evsel->fd == NULL)
		return;

	perf_evsel__close_fd(evsel);
	perf_evsel__free_fd(evsel);
}

void perf_evsel__close_cpu(struct perf_evsel *evsel, int cpu_map_idx)
{
	if (evsel->fd == NULL)
		return;

	perf_evsel__close_fd_cpu(evsel, cpu_map_idx);
}

void perf_evsel__munmap(struct perf_evsel *evsel)
{
	int idx, thread;

	if (evsel->fd == NULL || evsel->mmap == NULL)
		return;

	for (idx = 0; idx < xyarray__max_x(evsel->fd); idx++) {
		for (thread = 0; thread < xyarray__max_y(evsel->fd); thread++) {
			int *fd = FD(evsel, idx, thread);

			if (fd == NULL || *fd < 0)
				continue;

			perf_mmap__munmap(MMAP(evsel, idx, thread));
		}
	}

	xyarray__delete(evsel->mmap);
	evsel->mmap = NULL;
}

int perf_evsel__mmap(struct perf_evsel *evsel, int pages)
{
	int ret, idx, thread;
	struct perf_mmap_param mp = {
		.prot = PROT_READ | PROT_WRITE,
		.mask = (pages * page_size) - 1,
	};

	if (evsel->fd == NULL || evsel->mmap)
		return -EINVAL;

	if (perf_evsel__alloc_mmap(evsel, xyarray__max_x(evsel->fd), xyarray__max_y(evsel->fd)) < 0)
		return -ENOMEM;

	for (idx = 0; idx < xyarray__max_x(evsel->fd); idx++) {
		for (thread = 0; thread < xyarray__max_y(evsel->fd); thread++) {
			int *fd = FD(evsel, idx, thread);
			struct perf_mmap *map;
			struct perf_cpu cpu = perf_cpu_map__cpu(evsel->cpus, idx);

			if (fd == NULL || *fd < 0)
				continue;

			map = MMAP(evsel, idx, thread);
			perf_mmap__init(map, NULL, false, NULL);

			ret = perf_mmap__mmap(map, &mp, *fd, cpu);
			if (ret) {
				perf_evsel__munmap(evsel);
				return ret;
			}
		}
	}

	return 0;
}

void *perf_evsel__mmap_base(struct perf_evsel *evsel, int cpu_map_idx, int thread)
{
	int *fd = FD(evsel, cpu_map_idx, thread);

	if (fd == NULL || *fd < 0 || MMAP(evsel, cpu_map_idx, thread) == NULL)
		return NULL;

	return MMAP(evsel, cpu_map_idx, thread)->base;
}

int perf_evsel__read_size(struct perf_evsel *evsel)
{
	u64 read_format = evsel->attr.read_format;
	int entry = sizeof(u64); /* value */
	int size = 0;
	int nr = 1;

	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		size += sizeof(u64);

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		size += sizeof(u64);

	if (read_format & PERF_FORMAT_ID)
		entry += sizeof(u64);

	if (read_format & PERF_FORMAT_LOST)
		entry += sizeof(u64);

	if (read_format & PERF_FORMAT_GROUP) {
		nr = evsel->nr_members;
		size += sizeof(u64);
	}

	size += entry * nr;
	return size;
}

/* This only reads values for the leader */
static int perf_evsel__read_group(struct perf_evsel *evsel, int cpu_map_idx,
				  int thread, struct perf_counts_values *count)
{
	size_t size = perf_evsel__read_size(evsel);
	int *fd = FD(evsel, cpu_map_idx, thread);
	u64 read_format = evsel->attr.read_format;
	u64 *data;
	int idx = 1;

	if (fd == NULL || *fd < 0)
		return -EINVAL;

	data = calloc(1, size);
	if (data == NULL)
		return -ENOMEM;

	if (readn(*fd, data, size) <= 0) {
		free(data);
		return -errno;
	}

	/*
	 * This reads only the leader event intentionally since we don't have
	 * perf counts values for sibling events.
	 */
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		count->ena = data[idx++];
	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		count->run = data[idx++];

	/* value is always available */
	count->val = data[idx++];
	if (read_format & PERF_FORMAT_ID)
		count->id = data[idx++];
	if (read_format & PERF_FORMAT_LOST)
		count->lost = data[idx++];

	free(data);
	return 0;
}

/*
 * The perf read format is very flexible.  It needs to set the proper
 * values according to the read format.
 */
static void perf_evsel__adjust_values(struct perf_evsel *evsel, u64 *buf,
				      struct perf_counts_values *count)
{
	u64 read_format = evsel->attr.read_format;
	int n = 0;

	count->val = buf[n++];

	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		count->ena = buf[n++];

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		count->run = buf[n++];

	if (read_format & PERF_FORMAT_ID)
		count->id = buf[n++];

	if (read_format & PERF_FORMAT_LOST)
		count->lost = buf[n++];
}

int perf_evsel__read(struct perf_evsel *evsel, int cpu_map_idx, int thread,
		     struct perf_counts_values *count)
{
	size_t size = perf_evsel__read_size(evsel);
	int *fd = FD(evsel, cpu_map_idx, thread);
	u64 read_format = evsel->attr.read_format;
	struct perf_counts_values buf;

	memset(count, 0, sizeof(*count));

	if (fd == NULL || *fd < 0)
		return -EINVAL;

	if (read_format & PERF_FORMAT_GROUP)
		return perf_evsel__read_group(evsel, cpu_map_idx, thread, count);

	if (MMAP(evsel, cpu_map_idx, thread) &&
	    !(read_format & (PERF_FORMAT_ID | PERF_FORMAT_LOST)) &&
	    !perf_mmap__read_self(MMAP(evsel, cpu_map_idx, thread), count))
		return 0;

	if (readn(*fd, buf.values, size) <= 0)
		return -errno;

	perf_evsel__adjust_values(evsel, buf.values, count);
	return 0;
}

static int perf_evsel__ioctl(struct perf_evsel *evsel, int ioc, unsigned long arg,
			     int cpu_map_idx, int thread)
{
	int *fd = FD(evsel, cpu_map_idx, thread);

	if (fd == NULL || *fd < 0)
		return -1;

	return ioctl(*fd, ioc, arg);
}

static int perf_evsel__run_ioctl(struct perf_evsel *evsel,
				 int ioc, unsigned long arg,
				 int cpu_map_idx)
{
	int thread;

	for (thread = 0; thread < xyarray__max_y(evsel->fd); thread++) {
		int err = perf_evsel__ioctl(evsel, ioc, arg, cpu_map_idx, thread);

		if (err)
			return err;
	}

	return 0;
}

int perf_evsel__enable_cpu(struct perf_evsel *evsel, int cpu_map_idx)
{
	return perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_ENABLE, 0, cpu_map_idx);
}

int perf_evsel__enable_thread(struct perf_evsel *evsel, int thread)
{
	struct perf_cpu cpu __maybe_unused;
	int idx;
	int err;

	perf_cpu_map__for_each_cpu(cpu, idx, evsel->cpus) {
		err = perf_evsel__ioctl(evsel, PERF_EVENT_IOC_ENABLE, 0, idx, thread);
		if (err)
			return err;
	}

	return 0;
}

int perf_evsel__enable(struct perf_evsel *evsel)
{
	int i;
	int err = 0;

	for (i = 0; i < xyarray__max_x(evsel->fd) && !err; i++)
		err = perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_ENABLE, 0, i);
	return err;
}

int perf_evsel__disable_cpu(struct perf_evsel *evsel, int cpu_map_idx)
{
	return perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_DISABLE, 0, cpu_map_idx);
}

int perf_evsel__disable(struct perf_evsel *evsel)
{
	int i;
	int err = 0;

	for (i = 0; i < xyarray__max_x(evsel->fd) && !err; i++)
		err = perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_DISABLE, 0, i);
	return err;
}

int perf_evsel__refresh(struct perf_evsel *evsel, int refresh)
{
	int i;
	int err = 0;

	for (i = 0; i < xyarray__max_x(evsel->fd) && !err; i++)
		err = perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_REFRESH, refresh, i);
	return err;
}

int perf_evsel__period(struct perf_evsel *evsel, __u64 period)
{
	struct perf_event_attr *attr;
	int i;
	int err = 0;

	attr = perf_evsel__attr(evsel);

	for (i = 0; i < xyarray__max_x(evsel->fd); i++) {
		err = perf_evsel__run_ioctl(evsel, PERF_EVENT_IOC_PERIOD,
					    (unsigned long)&period, i);
		if (err)
			return err;
	}

	attr->sample_period = period;

	return err;
}

int perf_evsel__apply_filter(struct perf_evsel *evsel, const char *filter)
{
	int err = 0, i;

	for (i = 0; i < perf_cpu_map__nr(evsel->cpus) && !err; i++)
		err = perf_evsel__run_ioctl(evsel,
				     PERF_EVENT_IOC_SET_FILTER,
				     (unsigned long)filter, i);
	return err;
}

struct perf_cpu_map *perf_evsel__cpus(struct perf_evsel *evsel)
{
	return evsel->cpus;
}

struct perf_thread_map *perf_evsel__threads(struct perf_evsel *evsel)
{
	return evsel->threads;
}

struct perf_event_attr *perf_evsel__attr(struct perf_evsel *evsel)
{
	return &evsel->attr;
}

int perf_evsel__alloc_id(struct perf_evsel *evsel, int ncpus, int nthreads)
{
	if (ncpus == 0 || nthreads == 0)
		return 0;

	evsel->sample_id = xyarray__new(ncpus, nthreads, sizeof(struct perf_sample_id));
	if (evsel->sample_id == NULL)
		return -ENOMEM;

	evsel->id = zalloc(ncpus * nthreads * sizeof(u64));
	if (evsel->id == NULL) {
		xyarray__delete(evsel->sample_id);
		evsel->sample_id = NULL;
		return -ENOMEM;
	}

	return 0;
}

void perf_evsel__free_id(struct perf_evsel *evsel)
{
	xyarray__delete(evsel->sample_id);
	evsel->sample_id = NULL;
	zfree(&evsel->id);
	evsel->ids = 0;
}

void perf_counts_values__scale(struct perf_counts_values *count,
			       bool scale, __s8 *pscaled)
{
	s8 scaled = 0;

	if (scale) {
		if (count->run == 0) {
			scaled = -1;
			count->val = 0;
		} else if (count->run < count->ena) {
			scaled = 1;
			count->val = (u64)((double)count->val * count->ena / count->run);
		}
	}

	if (pscaled)
		*pscaled = scaled;
}

static int perf_evsel__run_fcntl(struct perf_evsel *evsel,
				 unsigned int cmd, unsigned long arg,
				 int cpu_map_idx)
{
	int thread;

	for (thread = 0; thread < xyarray__max_y(evsel->fd); thread++) {
		int err;
		int *fd = FD(evsel, cpu_map_idx, thread);

		if (!fd || *fd < 0)
			return -1;

		err = fcntl(*fd, cmd, arg);
		if (err)
			return err;
	}

	return 0;
}

static int perf_evsel__set_signal_handler(struct perf_evsel *evsel,
					  struct perf_evsel_open_opts *opts)
{
	unsigned int fcntl_flags;
	unsigned int signal;
	struct f_owner_ex owner;
	struct sigaction *sigact;
	int cpu_map_idx;
	int err = 0;

	fcntl_flags = OPTS_GET(opts, fcntl_flags, (O_RDWR | O_NONBLOCK | O_ASYNC));
	signal = OPTS_GET(opts, signal, SIGIO);
	owner.type = OPTS_GET(opts, owner_type, F_OWNER_PID);
	sigact = OPTS_GET(opts, sigact, NULL);

	if (fcntl_flags == 0 && signal == 0 && !owner.type == 0 && sigact == 0)
		return err;

	err = sigaction(signal, sigact, NULL);
	if (err)
		return err;

	switch (owner.type) {
	case F_OWNER_PID:
		owner.pid = getpid();
		break;
	case F_OWNER_TID:
		owner.pid = syscall(SYS_gettid);
		break;
	case F_OWNER_PGRP:
	default:
		return -1;
	}

	for (cpu_map_idx = 0; cpu_map_idx < xyarray__max_x(evsel->fd); cpu_map_idx++) {
		err = perf_evsel__run_fcntl(evsel, F_SETFL, fcntl_flags, cpu_map_idx);
		if (err)
			return err;

		err = perf_evsel__run_fcntl(evsel, F_SETSIG, signal, cpu_map_idx);
		if (err)
			return err;

		err = perf_evsel__run_fcntl(evsel, F_SETOWN_EX,
					    (unsigned long)&owner, cpu_map_idx);
		if (err)
			return err;
	}

	return err;
}

int perf_evsel__open_opts(struct perf_evsel *evsel, struct perf_cpu_map *cpus,
			  struct perf_thread_map *threads,
			  struct perf_evsel_open_opts *opts)
{
	int err = 0;

	if (!OPTS_VALID(opts, perf_evsel_open_opts)) {
		err = -EINVAL;
		return err;
	}

	evsel->open_flags = OPTS_GET(opts, open_flags, 0);

	err = perf_evsel__open(evsel, cpus, threads);
	if (err)
		return err;

	err = perf_evsel__set_signal_handler(evsel, opts);
	if (err)
		return err;

	return err;
}

bool perf_evsel__has_fd(struct perf_evsel *evsel, int fd)
{
	int cpu_map_idx;
	int thread;
	int *evsel_fd;

	for (cpu_map_idx = 0; cpu_map_idx < xyarray__max_x(evsel->fd); ++cpu_map_idx) {
		for (thread = 0; thread < xyarray__max_y(evsel->fd); ++thread) {
			evsel_fd = FD(evsel, cpu_map_idx, thread);

			if (fd == *evsel_fd)
				return true;
		}
	}

	return false;
}
