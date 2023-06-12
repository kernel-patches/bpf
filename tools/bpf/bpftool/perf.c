// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (C) 2018 Facebook
// Author: Yonghong Song <yhs@fb.com>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <bpf/bpf.h>

#include "main.h"
#include "perf.h"

static const char *perf_type_name[PERF_TYPE_MAX] = {
	[PERF_TYPE_HARDWARE]			= "hardware",
	[PERF_TYPE_SOFTWARE]			= "software",
	[PERF_TYPE_TRACEPOINT]			= "tracepoint",
	[PERF_TYPE_HW_CACHE]			= "hw-cache",
	[PERF_TYPE_RAW]				= "raw",
	[PERF_TYPE_BREAKPOINT]			= "breakpoint",
};

const char *event_symbols_hw[PERF_COUNT_HW_MAX] = {
	[PERF_COUNT_HW_CPU_CYCLES]		= "cpu-cycles",
	[PERF_COUNT_HW_INSTRUCTIONS]		= "instructions",
	[PERF_COUNT_HW_CACHE_REFERENCES]	= "cache-references",
	[PERF_COUNT_HW_CACHE_MISSES]		= "cache-misses",
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= "branch-instructions",
	[PERF_COUNT_HW_BRANCH_MISSES]		= "branch-misses",
	[PERF_COUNT_HW_BUS_CYCLES]		= "bus-cycles",
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= "stalled-cycles-frontend",
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= "stalled-cycles-backend",
	[PERF_COUNT_HW_REF_CPU_CYCLES]		= "ref-cycles",
};

const char *event_symbols_sw[PERF_COUNT_SW_MAX] = {
	[PERF_COUNT_SW_CPU_CLOCK]		= "cpu-clock",
	[PERF_COUNT_SW_TASK_CLOCK]		= "task-clock",
	[PERF_COUNT_SW_PAGE_FAULTS]		= "page-faults",
	[PERF_COUNT_SW_CONTEXT_SWITCHES]	= "context-switches",
	[PERF_COUNT_SW_CPU_MIGRATIONS]		= "cpu-migrations",
	[PERF_COUNT_SW_PAGE_FAULTS_MIN]		= "minor-faults",
	[PERF_COUNT_SW_PAGE_FAULTS_MAJ]		= "major-faults",
	[PERF_COUNT_SW_ALIGNMENT_FAULTS]	= "alignment-faults",
	[PERF_COUNT_SW_EMULATION_FAULTS]	= "emulation-faults",
	[PERF_COUNT_SW_DUMMY]			= "dummy",
	[PERF_COUNT_SW_BPF_OUTPUT]		= "bpf-output",
	[PERF_COUNT_SW_CGROUP_SWITCHES]		= "cgroup-switches",
};

const char *evsel__hw_cache[PERF_COUNT_HW_CACHE_MAX] = {
	[PERF_COUNT_HW_CACHE_L1D]		= "L1-dcache",
	[PERF_COUNT_HW_CACHE_L1I]		= "L1-icache",
	[PERF_COUNT_HW_CACHE_LL]		= "LLC",
	[PERF_COUNT_HW_CACHE_DTLB]		= "dTLB",
	[PERF_COUNT_HW_CACHE_ITLB]		= "iTLB",
	[PERF_COUNT_HW_CACHE_BPU]		= "branch",
	[PERF_COUNT_HW_CACHE_NODE]		= "node",
};

const char *evsel__hw_cache_op[PERF_COUNT_HW_CACHE_OP_MAX] = {
	[PERF_COUNT_HW_CACHE_OP_READ]		= "load",
	[PERF_COUNT_HW_CACHE_OP_WRITE]		= "store",
	[PERF_COUNT_HW_CACHE_OP_PREFETCH]	= "prefetch",
};

const char *evsel__hw_cache_result[PERF_COUNT_HW_CACHE_RESULT_MAX] = {
	[PERF_COUNT_HW_CACHE_RESULT_ACCESS]	= "refs",
	[PERF_COUNT_HW_CACHE_RESULT_MISS]	= "misses",
};

const char *perf_type_str(enum perf_type_id t)
{
	if (t < 0 || t >= ARRAY_SIZE(perf_type_name))
		return NULL;

	return perf_type_name[t];
}

const char *perf_hw_str(enum perf_hw_id t)
{
	if (t < 0 || t >= ARRAY_SIZE(event_symbols_hw))
		return NULL;

	return event_symbols_hw[t];
}

const char *perf_hw_cache_str(enum perf_hw_cache_id t)
{
	if (t < 0 || t >= ARRAY_SIZE(evsel__hw_cache))
		return NULL;

	return evsel__hw_cache[t];
}

const char *perf_hw_cache_op_str(enum perf_hw_cache_op_id t)
{
	if (t < 0 || t >= ARRAY_SIZE(evsel__hw_cache_op))
		return NULL;

	return evsel__hw_cache_op[t];
}

const char *perf_hw_cache_op_result_str(enum perf_hw_cache_op_result_id t)
{
	if (t < 0 || t >= ARRAY_SIZE(evsel__hw_cache_result))
		return NULL;

	return evsel__hw_cache_result[t];
}

const char *perf_sw_str(enum perf_sw_ids t)
{
	if (t < 0 || t >= ARRAY_SIZE(event_symbols_sw))
		return NULL;

	return event_symbols_sw[t];
}

/* 0: undecided, 1: supported, 2: not supported */
static int perf_query_supported;
static bool has_perf_query_support(void)
{
	__u64 probe_offset, probe_addr;
	__u32 len, prog_id, fd_type;
	char buf[256];
	int fd;

	if (perf_query_supported)
		goto out;

	fd = open("/", O_RDONLY);
	if (fd < 0) {
		p_err("perf_query_support: cannot open directory \"/\" (%s)",
		      strerror(errno));
		goto out;
	}

	/* the following query will fail as no bpf attachment,
	 * the expected errno is ENOTSUPP
	 */
	errno = 0;
	len = sizeof(buf);
	bpf_task_fd_query(getpid(), fd, 0, buf, &len, &prog_id,
			  &fd_type, &probe_offset, &probe_addr);

	if (errno == 524 /* ENOTSUPP */) {
		perf_query_supported = 1;
		goto close_fd;
	}

	perf_query_supported = 2;
	p_err("perf_query_support: %s", strerror(errno));
	fprintf(stderr,
		"HINT: non root or kernel doesn't support TASK_FD_QUERY\n");

close_fd:
	close(fd);
out:
	return perf_query_supported == 1;
}

static void print_perf_json(int pid, int fd, __u32 prog_id, __u32 fd_type,
			    char *buf, __u64 probe_offset, __u64 probe_addr)
{
	jsonw_start_object(json_wtr);
	jsonw_int_field(json_wtr, "pid", pid);
	jsonw_int_field(json_wtr, "fd", fd);
	jsonw_uint_field(json_wtr, "prog_id", prog_id);
	switch (fd_type) {
	case BPF_FD_TYPE_RAW_TRACEPOINT:
		jsonw_string_field(json_wtr, "fd_type", "raw_tracepoint");
		jsonw_string_field(json_wtr, "tracepoint", buf);
		break;
	case BPF_FD_TYPE_TRACEPOINT:
		jsonw_string_field(json_wtr, "fd_type", "tracepoint");
		jsonw_string_field(json_wtr, "tracepoint", buf);
		break;
	case BPF_FD_TYPE_KPROBE:
		jsonw_string_field(json_wtr, "fd_type", "kprobe");
		if (buf[0] != '\0') {
			jsonw_string_field(json_wtr, "func", buf);
			jsonw_lluint_field(json_wtr, "offset", probe_offset);
		} else {
			jsonw_lluint_field(json_wtr, "addr", probe_addr);
		}
		break;
	case BPF_FD_TYPE_KRETPROBE:
		jsonw_string_field(json_wtr, "fd_type", "kretprobe");
		if (buf[0] != '\0') {
			jsonw_string_field(json_wtr, "func", buf);
			jsonw_lluint_field(json_wtr, "offset", probe_offset);
		} else {
			jsonw_lluint_field(json_wtr, "addr", probe_addr);
		}
		break;
	case BPF_FD_TYPE_UPROBE:
		jsonw_string_field(json_wtr, "fd_type", "uprobe");
		jsonw_string_field(json_wtr, "filename", buf);
		jsonw_lluint_field(json_wtr, "offset", probe_offset);
		break;
	case BPF_FD_TYPE_URETPROBE:
		jsonw_string_field(json_wtr, "fd_type", "uretprobe");
		jsonw_string_field(json_wtr, "filename", buf);
		jsonw_lluint_field(json_wtr, "offset", probe_offset);
		break;
	default:
		break;
	}
	jsonw_end_object(json_wtr);
}

static void print_perf_plain(int pid, int fd, __u32 prog_id, __u32 fd_type,
			     char *buf, __u64 probe_offset, __u64 probe_addr)
{
	printf("pid %d  fd %d: prog_id %u  ", pid, fd, prog_id);
	switch (fd_type) {
	case BPF_FD_TYPE_RAW_TRACEPOINT:
		printf("raw_tracepoint  %s\n", buf);
		break;
	case BPF_FD_TYPE_TRACEPOINT:
		printf("tracepoint  %s\n", buf);
		break;
	case BPF_FD_TYPE_KPROBE:
		if (buf[0] != '\0')
			printf("kprobe  func %s  offset %llu\n", buf,
			       probe_offset);
		else
			printf("kprobe  addr %llu\n", probe_addr);
		break;
	case BPF_FD_TYPE_KRETPROBE:
		if (buf[0] != '\0')
			printf("kretprobe  func %s  offset %llu\n", buf,
			       probe_offset);
		else
			printf("kretprobe  addr %llu\n", probe_addr);
		break;
	case BPF_FD_TYPE_UPROBE:
		printf("uprobe  filename %s  offset %llu\n", buf, probe_offset);
		break;
	case BPF_FD_TYPE_URETPROBE:
		printf("uretprobe  filename %s  offset %llu\n", buf,
		       probe_offset);
		break;
	default:
		break;
	}
}

static int show_proc(void)
{
	struct dirent *proc_de, *pid_fd_de;
	__u64 probe_offset, probe_addr;
	__u32 len, prog_id, fd_type;
	DIR *proc, *pid_fd;
	int err, pid, fd;
	const char *pch;
	char buf[4096];

	proc = opendir("/proc");
	if (!proc)
		return -1;

	while ((proc_de = readdir(proc))) {
		pid = 0;
		pch = proc_de->d_name;

		/* pid should be all numbers */
		while (isdigit(*pch)) {
			pid = pid * 10 + *pch - '0';
			pch++;
		}
		if (*pch != '\0')
			continue;

		err = snprintf(buf, sizeof(buf), "/proc/%s/fd", proc_de->d_name);
		if (err < 0 || err >= (int)sizeof(buf))
			continue;

		pid_fd = opendir(buf);
		if (!pid_fd)
			continue;

		while ((pid_fd_de = readdir(pid_fd))) {
			fd = 0;
			pch = pid_fd_de->d_name;

			/* fd should be all numbers */
			while (isdigit(*pch)) {
				fd = fd * 10 + *pch - '0';
				pch++;
			}
			if (*pch != '\0')
				continue;

			/* query (pid, fd) for potential perf events */
			len = sizeof(buf);
			err = bpf_task_fd_query(pid, fd, 0, buf, &len,
						&prog_id, &fd_type,
						&probe_offset, &probe_addr);
			if (err < 0)
				continue;

			if (json_output)
				print_perf_json(pid, fd, prog_id, fd_type, buf,
						probe_offset, probe_addr);
			else
				print_perf_plain(pid, fd, prog_id, fd_type, buf,
						 probe_offset, probe_addr);
		}
		closedir(pid_fd);
	}
	closedir(proc);
	return 0;
}

static int do_show(int argc, char **argv)
{
	int err;

	if (!has_perf_query_support())
		return -1;

	if (json_output)
		jsonw_start_array(json_wtr);
	err = show_proc();
	if (json_output)
		jsonw_end_array(json_wtr);

	return err;
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }\n"
		"       %1$s %2$s help }\n"
		"\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ 0 }
};

int do_perf(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
