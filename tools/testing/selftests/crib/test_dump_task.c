// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <autoconf.h>

#include "../kselftest_harness.h"

#include "test_dump_task.h"
#include "test_dump_task.bpf.skel.h"

struct task {
	int pid;
	unsigned int flags;
	int prio;
	unsigned int policy;
	int exit_code;
	char comm[16];
};

struct mm {
	unsigned long start_code;
	unsigned long end_code;
	unsigned long start_data;
	unsigned long end_data;
	unsigned long start_brk;
	unsigned long brk;
	unsigned long start_stack;
	unsigned long arg_start;
	unsigned long arg_end;
	unsigned long env_start;
	unsigned long env_end;
	int map_count;
};

struct vma {
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_flags;
	unsigned long vm_pgoff;
};

struct dump_info {
	struct task task;
	struct mm mm;
	struct vma *vma;
	unsigned int vma_count;
};

static int handle_vma_event(struct dump_info *info, struct event_vma *e_vma)
{
	struct vma *vma = &info->vma[info->vma_count];
	vma->vm_start = e_vma->vm_start;
	vma->vm_end = e_vma->vm_end;
	vma->vm_flags = e_vma->vm_flags;
	vma->vm_pgoff = e_vma->vm_pgoff;
	info->vma_count++;
	return 0;
}

static int handle_mm_event(struct dump_info *info, struct event_mm *e_mm)
{
	info->mm.start_code = e_mm->start_code;
	info->mm.end_code = e_mm->end_code;
	info->mm.start_data = e_mm->start_data;
	info->mm.end_data = e_mm->end_data;
	info->mm.start_brk = e_mm->start_brk;
	info->mm.brk = e_mm->brk;
	info->mm.start_stack = e_mm->start_stack;
	info->mm.arg_start = e_mm->arg_start;
	info->mm.arg_end = e_mm->arg_end;
	info->mm.env_start = e_mm->env_start;
	info->mm.env_end = e_mm->env_end;
	info->mm.map_count = e_mm->map_count;
	info->vma = (struct vma *)malloc(sizeof(struct vma) * e_mm->map_count);
	info->vma_count = 0;
	return 0;
}

static int handle_task_event(struct dump_info *info, struct event_task *e_task)
{
	info->task.pid = e_task->pid;
	info->task.flags = e_task->flags;
	info->task.prio = e_task->prio;
	info->task.policy = e_task->policy;
	info->task.exit_code = e_task->exit_code;
	memcpy(info->task.comm, e_task->comm, sizeof(info->task.comm));
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct dump_info *info = (struct dump_info *)ctx;
	const struct event_hdr *e_hdr = data;
	int err = 0;

	switch (e_hdr->type) {
	case EVENT_TYPE_TASK:
		handle_task_event(info, (struct event_task *)data);
		break;
	case EVENT_TYPE_VMA:
		handle_vma_event(info, (struct event_vma *)data);
		break;
	case EVENT_TYPE_MM:
		handle_mm_event(info, (struct event_mm *)data);
		break;
	default:
		err = -1;
		printf("Unknown event type!\n");
		break;
	}
	return err;
}

static int dump_task_and_mm_struct_from_proc(struct dump_info *info)
{
	FILE *file = fopen("/proc/self/stat", "r");
	if (!file)
		return -1;

	fscanf(file, "%d %s %*c %*d %*d %*d %*d %*d %u %*lu %*lu %*lu %*lu "
		   "%*lu %*lu %*ld %*ld %d %*ld %*d %*d %*llu %*lu %*ld %*lu %lu %lu %lu "
		   "%*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*d %*d %*u %u %*llu %*lu %*ld "
		   "%lu %lu %lu %lu %lu %lu %lu %d",
		   &info->task.pid, info->task.comm, &info->task.flags, &info->task.prio,
		   &info->mm.start_code, &info->mm.end_code, &info->mm.start_stack,
		   &info->task.policy, &info->mm.start_data, &info->mm.end_data,
		   &info->mm.start_brk, &info->mm.arg_start, &info->mm.arg_end,
		   &info->mm.env_start, &info->mm.env_end, &info->task.exit_code);

	fclose(file);
	return 0;
}

static void parse_vma_vmflags(char *buf, struct vma *vma)
{
	vma->vm_flags = 0;
	char *token = strtok(buf, " ");
	do {
		if (!strncmp(token, "rd", 2))
			vma->vm_flags |= VM_READ;
		else if (!strncmp(token, "wr", 2))
			vma->vm_flags |= VM_WRITE;
		else if (!strncmp(token, "ex", 2))
			vma->vm_flags |= VM_EXEC;
		else if (!strncmp(token, "sh", 2))
			vma->vm_flags |= VM_SHARED;
		else if (!strncmp(token, "mr", 2))
			vma->vm_flags |= VM_MAYREAD;
		else if (!strncmp(token, "mw", 2))
			vma->vm_flags |= VM_MAYWRITE;
		else if (!strncmp(token, "me", 2))
			vma->vm_flags |= VM_MAYEXEC;
		else if (!strncmp(token, "ms", 2))
			vma->vm_flags |= VM_MAYSHARE;
		else if (!strncmp(token, "gd", 2))
			vma->vm_flags |= VM_GROWSDOWN;
		else if (!strncmp(token, "pf", 2))
			vma->vm_flags |= VM_PFNMAP;
		else if (!strncmp(token, "lo", 2))
			vma->vm_flags |= VM_LOCKED;
		else if (!strncmp(token, "io", 2))
			vma->vm_flags |= VM_IO;
		else if (!strncmp(token, "sr", 2))
			vma->vm_flags |= VM_SEQ_READ;
		else if (!strncmp(token, "rr", 2))
			vma->vm_flags |= VM_RAND_READ;
		else if (!strncmp(token, "dc", 2))
			vma->vm_flags |= VM_DONTCOPY;
		else if (!strncmp(token, "de", 2))
			vma->vm_flags |= VM_DONTEXPAND;
		else if (!strncmp(token, "lf", 2))
			vma->vm_flags |= VM_LOCKONFAULT;
		else if (!strncmp(token, "ac", 2))
			vma->vm_flags |= VM_ACCOUNT;
		else if (!strncmp(token, "nr", 2))
			vma->vm_flags |= VM_NORESERVE;
		else if (!strncmp(token, "ht", 2))
			vma->vm_flags |= VM_HUGETLB;
		else if (!strncmp(token, "sf", 2))
			vma->vm_flags |= VM_SYNC;
		else if (!strncmp(token, "ar", 2))
			vma->vm_flags |= VM_ARCH_1;
		else if (!strncmp(token, "wf", 2))
			vma->vm_flags |= VM_WIPEONFORK;
		else if (!strncmp(token, "dd", 2))
			vma->vm_flags |= VM_DONTDUMP;
		else if (!strncmp(token, "sd", 2))
			vma->vm_flags |= VM_SOFTDIRTY;
		else if (!strncmp(token, "mm", 2))
			vma->vm_flags |= VM_MIXEDMAP;
		else if (!strncmp(token, "hg", 2))
			vma->vm_flags |= VM_HUGEPAGE;
		else if (!strncmp(token, "nh", 2))
			vma->vm_flags |= VM_NOHUGEPAGE;
		else if (!strncmp(token, "mg", 2))
			vma->vm_flags |= VM_MERGEABLE;
		else if (!strncmp(token, "um", 2))
			vma->vm_flags |= VM_UFFD_MISSING;
		else if (!strncmp(token, "uw", 2))
			vma->vm_flags |= VM_UFFD_WP;
	}
	while ((token = strtok(NULL, " ")) != NULL);
}

static int dump_vma_from_proc(struct dump_info *info)
{
	FILE *file = fopen("/proc/self/smaps", "r");
	if (!file)
		return -1;

	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	while ((nread = getline(&line, &len, file)) != -1) {
		struct vma *vma = &info->vma[info->vma_count];
		if (isupper(*line)) {
			if (!strncmp(line, "VmFlags: ", 9)) {
				parse_vma_vmflags(&line[9], vma);
				info->vma_count++;
			}
		} else {
			sscanf(line, "%lx-%lx %*c%*c%*c%*c %lx",
			&vma->vm_start, &vma->vm_end, &vma->vm_pgoff);
		}
	}

	fclose(file);
	return 0;
}

static int check_dump_info_correctness(struct dump_info *crib_info, struct dump_info *proc_info)
{
	if (crib_info->task.pid != proc_info->task.pid ||
		crib_info->task.flags != proc_info->task.flags ||
		crib_info->task.prio - 100 != proc_info->task.prio ||
		crib_info->task.policy != proc_info->task.policy ||
		crib_info->task.exit_code != proc_info->task.exit_code ||
		strncmp(crib_info->task.comm, proc_info->task.comm + 1,
			strlen(crib_info->task.comm)))
		return -1;

	if (crib_info->mm.start_code != proc_info->mm.start_code ||
		crib_info->mm.end_code != proc_info->mm.end_code ||
		crib_info->mm.start_data != proc_info->mm.start_data ||
		crib_info->mm.end_data != proc_info->mm.end_data ||
		crib_info->mm.start_brk != proc_info->mm.start_brk ||
		crib_info->mm.arg_start != proc_info->mm.arg_start ||
		crib_info->mm.arg_end != proc_info->mm.arg_end ||
		crib_info->mm.env_start != proc_info->mm.env_start ||
		crib_info->mm.env_end != proc_info->mm.env_end ||
		crib_info->mm.start_stack != proc_info->mm.start_stack)
		return -1;

	struct vma *crib_vma, *proc_vma;
	for (int i = 0; i < crib_info->mm.map_count; i++) {
		crib_vma = &crib_info->vma[i];
		proc_vma = &proc_info->vma[i];
		if (crib_vma->vm_start != proc_vma->vm_start ||
			crib_vma->vm_end != proc_vma->vm_end ||
			crib_vma->vm_flags != proc_vma->vm_flags ||
			crib_vma->vm_pgoff << CONFIG_PAGE_SHIFT != proc_vma->vm_pgoff)
			return -1;
	}
	return 0;
}

TEST(dump_task)
{
	struct prog_args args = {
		.pid = getpid(),
	};
	ASSERT_GT(args.pid, 0);

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);

	struct test_dump_task_bpf *skel = test_dump_task_bpf__open_and_load();
	ASSERT_NE(skel, NULL);

	int dump_task_stat_fd = bpf_program__fd(skel->progs.dump_task_stat);
	ASSERT_GT(dump_task_stat_fd, 0);

	int dump_all_vma_fd = bpf_program__fd(skel->progs.dump_all_vma);
	ASSERT_GT(dump_all_vma_fd, 0);

	struct dump_info crib_info, proc_info;
	memset(&crib_info, 0, sizeof(struct dump_info));
	memset(&proc_info, 0, sizeof(struct dump_info));

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event,
						  &crib_info, NULL);
	ASSERT_NE(rb, NULL);

	clock_t crib_begin = clock();

	ASSERT_EQ(bpf_prog_test_run_opts(dump_task_stat_fd, &opts), 0);
	ASSERT_EQ(bpf_prog_test_run_opts(dump_all_vma_fd, &opts), 0);

	ASSERT_GT(ring_buffer__poll(rb, 100), 0);

	clock_t crib_end = clock();

	printf("CRIB dump took %f seconds\n", (double)(crib_end - crib_begin) / CLOCKS_PER_SEC);

	clock_t proc_begin = clock();

	proc_info.vma = (struct vma *)malloc(sizeof(struct vma) * (crib_info.mm.map_count + 1));
	ASSERT_EQ(dump_task_and_mm_struct_from_proc(&proc_info), 0);
	ASSERT_EQ(dump_vma_from_proc(&proc_info), 0);

	clock_t proc_end = clock();

	printf("PROC dump took %f seconds\n", (double)(proc_end - proc_begin) / CLOCKS_PER_SEC);

	ASSERT_EQ(check_dump_info_correctness(&crib_info, &proc_info), 0);

	free(crib_info.vma);
	free(proc_info.vma);
	ring_buffer__free(rb);
	test_dump_task_bpf__destroy(skel);
}

TEST_HARNESS_MAIN
