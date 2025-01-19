// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Arm Limited. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "perf-sys.h"
#include "trace_helpers.h"
#include "trace_counter.skel.h"

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))
#define SAMPLE_PERIOD		0x7fffffffffffffffULL

static struct trace_counter *skel;

/* Set the flag TRACE_MODE_FUNCTION for function trace. */
#define TRACE_MODE_FUNCTION	(1 << 0)

/* The PID for the profiled program */
static int pid;

/*
 * The PID for a pipe used for synchronization between the parent
 * process and the forked program in the child process.
 *
 * The synchronization mechanism is borrowed from the perf tool.
 */
static int cork_fd;

/*
 * The PMU event for tracing.  Four events are supported:
 *   cycles, instructions, branches, branch-misses.
 */
static char *event;

/*
 * The absolute path for executable file.
 */
static char *executable;

/*
 * The function name for function trace.
 */
static char *func;

/* File descriptor for PMU events */
static int pmu_fd = -1;

/* The target CPU for PMU event */
static int pmu_cpu = -1;

static char exec_path[PATH_MAX + 1];

/* Only trace user mode */
static bool user_mode;

/* CPU number */
static int nr_cpus;

/* Raw event number */
static long raw_event = -1;

static void usage(const char *cmd)
{
	printf("USAGE: %s [-f function] [-x binary_path] [-e event] -- command ...\n", cmd);
	printf("       %s [-f function] [-e event] command\n", cmd);
	printf("       %s [-h]\n", cmd);
	printf("       -c cpu		# Traced CPU (default: -1 for all CPUs)\n");
	printf("       -f function      # Traced function name\n");
	printf("       -x executable    # Absolute path for executable for adding uprobes\n");
	printf("       -e event         # Event name (default: cycles). Supported events:\n");
	printf("                        # cycles, instructions, branches, branch-misses\n");
	printf("       -r raw_event_num # Raw event number in hexadecimal format.\n");
	printf("                        # The '-r' option is mutually exclusive to the '-e' option.\n");
	printf("       -u               # Only trace user mode\n");
	printf("       -h               # Help\n");
}

static void err_exit(int err)
{
	if (pid)
		kill(pid, SIGKILL);
	exit(err);
}

static void print_counter(void)
{
	int cpu, fd, key;
	__u64 value, sum = 0, count, min, max, avg;

	if (event)
		printf("Event (%s) statistics:\n", event);
	else
		printf("Event (0x%lx) statistics:\n", raw_event);

	printf(" +-----------+------------------+\n");

	fd = bpf_map__fd(skel->maps.values);
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		if (bpf_map_lookup_elem(fd, &cpu, &value))
			continue;

		printf(" | CPU[%04d] | %16llu |\n", cpu, value);
		printf(" +-----------+------------------+\n");
		sum += value;
	}

	printf("   Total     : %16llu\n", sum);

	if (func) {
		fd = bpf_map__fd(skel->maps.func_stat);
		key = 0;
		if (bpf_map_lookup_elem(fd, &key, &count)) {
			printf("failed to read out function count\n");
			return;
		}

		key = 1;
		if (bpf_map_lookup_elem(fd, &key, &min)) {
			printf("failed to read out function min duration\n");
			return;
		}

		key = 2;
		if (bpf_map_lookup_elem(fd, &key, &max)) {
			printf("failed to read out function max duration\n");
			return;
		}

		avg = sum / count;
		printf("Function (%s) duration statistics:\n"
		       "   Count     : %16llu\n"
		       "   Minimum   : %16llu\n"
		       "   Maximum   : %16llu\n"
		       "   Average   : %16llu\n",
		       func, count, min, max, avg);
	}
}

/*
 * Prepare process for profiled workload.  The synchronization mechanism is
 * borrowed from the perf tool for avoid accounting the loads by the tool
 * itself.
 *
 * It creates a child process context for the profiled program and the child
 * process waits on pipe (go_pipe[0]).  The parent process will enable PMU
 * events and notify the child process to proceed.
 */
static int prepare_workload(char **argv)
{
	int child_ready_pipe[2], go_pipe[2];
	char bf;
	int key = 0, fd;

	if (pipe(child_ready_pipe) < 0) {
		printf("Failed to create 'ready' pipe\n");
		return -1;
	}

	if (pipe(go_pipe) < 0) {
		printf("Failed to create 'go' pipe\n");
		goto out_close_ready_pipe;
	}

	printf("Create process for the workload.\n");

	pid = fork();
	if (pid < 0) {
		printf("Failed to fork child process\n");
		goto out_close_pipes;
	}

	/* Child process */
	if (!pid) {
		int ret;

		close(child_ready_pipe[0]);
		close(go_pipe[1]);

		fcntl(go_pipe[0], F_SETFD, FD_CLOEXEC);

		/*
		 * Tell the parent we're ready to go
		 */
		close(child_ready_pipe[1]);

		/*
		 * Wait until the parent tells us to go.
		 */
		ret = read(go_pipe[0], &bf, 1);
		if (ret != 1) {
			if (ret == -1)
				printf("Unable to read go_pipe[0]\n");
			exit(ret);
		}

		execvp(argv[0], (char **)argv);

		/* Should not run to here */
		exit(-1);
	}

	close(child_ready_pipe[1]);
	close(go_pipe[0]);

	/* Wait for child to settle */
	if (read(child_ready_pipe[0], &bf, 1) == -1) {
		printf("Unable to read ready pipe\n");
		goto out_close_pipes;
	}

	fcntl(go_pipe[1], F_SETFD, FD_CLOEXEC);
	cork_fd = go_pipe[1];
	close(child_ready_pipe[0]);

	fd = bpf_map__fd(skel->maps.task_filter);
	/* Set task filter for only trace the target process */
	assert(bpf_map_update_elem(fd, &key, &pid, BPF_ANY) == 0);
	return 0;

out_close_pipes:
	close(go_pipe[0]);
	close(go_pipe[1]);
out_close_ready_pipe:
	close(child_ready_pipe[0]);
	close(child_ready_pipe[1]);
	return -1;
}

static int run_workload(void)
{
	int ret, status;
	char bf = 0;

	if (cork_fd >= 0) {
		/*
		 * Remove the cork, let it rip!
		 */
		ret = write(cork_fd, &bf, 1);
		close(cork_fd);
		cork_fd = -1;

		if (ret < 0) {
			printf("Unable to write to cork pipe");
			return ret;
		}
	}

	waitpid(pid, &status, 0);
	printf("Finished the workload.\n");

	return 0;
}

static void disable_perf_event(void)
{
	if (pmu_fd < 0)
		return;

	ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE, 0);
	close(pmu_fd);
}

static int enable_perf_event(void)
{
	int key = 0, fd;
	struct perf_event_attr attr = {
		.freq = 0,
		.sample_period = SAMPLE_PERIOD,
		.inherit = 0,
		.type = PERF_TYPE_RAW,
		.read_format = 0,
		.sample_type = 0,
		.enable_on_exec = 1,
		.disabled = 1,
	};

	if (event) {
		attr.type = PERF_TYPE_HARDWARE;
		if (!strcmp(event, "cycles"))
			attr.config = PERF_COUNT_HW_CPU_CYCLES;
		else if (!strcmp(event, "instructions"))
			attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		else if (!strcmp(event, "branches"))
			attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		else if (!strcmp(event, "branch-misses"))
			attr.config = PERF_COUNT_HW_BRANCH_MISSES;
		else
			return -EINVAL;
		printf("Enable the event %s.\n", event);
	} else {
		attr.type = PERF_TYPE_RAW;
		attr.config = raw_event;
		printf("Enable the raw event 0x%lx.\n", raw_event);
	}

	if (user_mode) {
		attr.exclude_kernel = 1;
		attr.exclude_hv = 1;
	}

	pmu_fd = sys_perf_event_open(&attr, pid, pmu_cpu, -1, 0);
	if (pmu_fd < 0) {
		printf("sys_perf_event_open failed: %d\n", pmu_fd);
		return pmu_fd;
	}

	fd = bpf_map__fd(skel->maps.counters);
	assert(bpf_map_update_elem(fd, &key, &pmu_fd, BPF_ANY) == 0);
	return 0;
}

static int parse_opts(int argc, char **argv)
{
	int opt;

	nr_cpus = libbpf_num_possible_cpus();

	while ((opt = getopt(argc, argv, "c:f:e:r:x:uh")) != -1) {
		switch (opt) {
		case 'c':
			pmu_cpu = atoi(optarg);
			break;
		case 'f':
			func = optarg;
			break;
		case 'e':
			event = optarg;
			break;
		case 'r':
			raw_event = strtol(optarg, NULL, 16);
			break;
		case 'x':
			executable = optarg;
			break;
		case 'u':
			user_mode = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (pmu_cpu != -1 && (pmu_cpu < 0 || pmu_cpu >= nr_cpus)) {
		printf("Target CPU %d is out-of-range [0..%d].\n",
		       pmu_cpu, nr_cpus - 1);
		return -EINVAL;
	}

	if (event && raw_event != -1) {
		printf("Only one of event name or raw event can be enabled.\n");
		return -EINVAL;
	}

	if (!event && raw_event == -1)
		event = "cycles";

	if (event) {
		if (strcmp(event, "cycles") && strcmp(event, "instructions") &&
		    strcmp(event, "branches") && strcmp(event, "branch-misses")) {
			printf("Invalid event name: %s\n", event);
			printf("Supported events: cycles/instructions/branches/branch-misses\n");
			return -EOPNOTSUPP;
		}
	} else {
		if (raw_event == LONG_MIN || raw_event == LONG_MAX) {
			printf("Invalid raw event number: %ld\n", raw_event);
			return -EOPNOTSUPP;
		}
	}

	if (func) {
		if (!executable)
			executable = argv[optind];

		if (!executable) {
			printf("Missed the executable path\n");
			return -EINVAL;
		}

		if (!realpath(executable, exec_path)) {
			printf("Unable to find the executable's absolute path.\n"
			       "Use the '-x' option to specify it.\n");
			return -EINVAL;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i;
	struct bpf_link *links[4] = { NULL };
	int error = 1;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	__u64 finish_task_switch_addr;
	char *finish_task_switch_str = NULL;

	if (parse_opts(argc, argv))
		return 0;

	/*
	 * The kernel function "finish_task_switch" is an occasion for recording
	 * a task scheduling out.  The compiler can perform interprocedural
	 * scalar replacement (-fipa-sra) and the function can be altered (e.g.
	 * "finish_task_switch.isra.0").  Search the kernel symbols to find out
	 * the correct symbol name.
	 */
	if (!kallsyms_find("finish_task_switch", &finish_task_switch_addr)) {
		finish_task_switch_str = "finish_task_switch";
	} else if (!kallsyms_find("finish_task_switch.isra.0",
				&finish_task_switch_addr)) {
		finish_task_switch_str = "finish_task_switch.isra.0";
	} else {
		printf("Failed to find kernel symbol 'finish_task_switch'\n");
		return -1;
	}

	signal(SIGINT, err_exit);
	signal(SIGTERM, err_exit);

	skel = trace_counter__open();
	if (!skel) {
		printf("Failed to open trace counter skeleton\n");
		return -1;
	}

	bpf_map__set_max_entries(skel->maps.values_begin, nr_cpus);
	bpf_map__set_max_entries(skel->maps.values, nr_cpus);

	if (func)
		skel->rodata->trace_mode = TRACE_MODE_FUNCTION;

	if (trace_counter__load(skel)) {
		printf("Failed to load trace counter skeleton\n");
		goto cleanup;
	}

	/* Create a child process for profied program */
	if (prepare_workload(&argv[optind]))
		goto cleanup;

	links[0] = bpf_program__attach(skel->progs.schedule_out);
	if (libbpf_get_error(links[0])) {
		printf("bpf_program__attach failed\n");
		links[0] = NULL;
		goto cleanup;
	}

	links[1] = bpf_program__attach_kprobe(skel->progs.schedule_in,
					      true, finish_task_switch_str);
	if (libbpf_get_error(links[1])) {
		printf("bpf_program__attach_kprobe failed\n");
		links[1] = NULL;
		goto cleanup;
	}

	if (func) {
		uprobe_opts.func_name = func;

		uprobe_opts.retprobe = false;
		links[2] = bpf_program__attach_uprobe_opts(skel->progs.func_begin,
							   pid,
							   exec_path,
							   0 /* offset */,
							   &uprobe_opts);
		if (libbpf_get_error(links[2])) {
			printf("Failed to attach func_begin uprobe\n");
			links[2] = NULL;
			goto cleanup;
		}

		uprobe_opts.retprobe = true;
		links[3] = bpf_program__attach_uprobe_opts(skel->progs.func_exit,
							   pid,
							   exec_path,
							   0 /* offset */,
							   &uprobe_opts);
		if (libbpf_get_error(links[3])) {
			printf("Failed to attach func_exit uprobe\n");
			links[3] = NULL;
			goto cleanup;
		}
	}

	/* Enable perf events */
	if (enable_perf_event() < 0)
		goto cleanup;

	/* Excute the workload */
	if (run_workload() < 0)
		goto cleanup;

	print_counter();
	error = 0;

cleanup:
	/* Disable perf events */
	disable_perf_event();

	for (i = 0; i < ARRAY_SIZE(links); i++) {
		if (!links[i])
			continue;
		bpf_link__destroy(links[i]);
	}
	trace_counter__destroy(skel);

	err_exit(error);
	return 0;
}
