// SPDX-License-Identifier: GPL-2.0

/* Copyright 2024 Arm Limited */

#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/err.h>

#include "util/auxtrace.h"
#include "util/cpumap.h"
#include "util/thread_map.h"
#include "util/debug.h"
#include "util/evlist.h"
#include "util/bpf_counter.h"
#include "util/record.h"
#include "util/target.h"

#include "util/bpf_skel/auxtrace_pause.skel.h"

/* The valid controlling type is "p" (pause) and "r" (resume) */
#define is_attach_kprobe(str)		\
	(!strcmp((str), "kprobe") || !strcmp((str), "kretprobe"))
#define is_attach_uprobe(str)		\
	(!strcmp((str), "uprobe") || !strcmp((str), "uretprobe"))
#define is_attach_tracepoint(str)	\
	(!strcmp((str), "tp") || !strcmp((str), "tracepoint"))

/* The valid controlling type is "p" (pause) and "r" (resume) */
#define is_valid_ctrl_type(str)	\
	(!strcmp((str), "p") || !strcmp((str), "r"))

static struct auxtrace_pause_bpf *skel;

struct trigger_entry {
	struct list_head list;
	char *arg0;
	char *arg1;
	char *arg2;
	char *arg3;
};

static int trigger_entry_num;
static LIST_HEAD(trigger_list);
static struct bpf_link **trigger_links;

static void auxtrace__free_bpf_trigger_list(void)
{
	struct trigger_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &trigger_list, list) {
		free(entry->arg0);
		free(entry->arg1);
		free(entry->arg2);
		free(entry->arg3);
		free(entry);
	}

	trigger_entry_num = 0;
}

static int auxtrace__alloc_bpf_trigger_list(const char *str)
{
	char *cmd_str;
	char *substr, *saveptr1;
	struct trigger_entry *entry;
	int ret = 0;

	if (!str)
		return -EINVAL;

	cmd_str = strdup(str);
	if (!cmd_str)
		return -ENOMEM;

	substr = strtok_r(cmd_str, ",", &saveptr1);
	for ( ; substr != NULL; substr = strtok_r(NULL, ",", &saveptr1)) {
		char *fmt1_str, *fmt2_str, *fmt3_str, *fmt4_str, *fmt;

		entry = zalloc(sizeof(*entry));
		if (!entry) {
			ret = -ENOMEM;
			goto out;
		}

		/*
		 * A trigger is expressed with several fields with separator ":".
		 * The first field is specified for attach types, it can be one
		 * of types listed below:
		 *   kprobe / kretprobe
		 *   uprobe / uretprobe
		 *   tp / tracepoint
		 *
		 * The kprobe and kretprobe trigger format is:
		 *   {kprobe|kretprobe}:{p|r}:function_name
		 *
		 * The uprobe and uretprobe trigger format is:
		 *   {uprobe|uretprobe}:{p|r}:executable:function_name
		 *
		 * Tracepoint trigger format is:
		 *   {tp|tracepoint}:{p|r}:category:tracepint_name
		 *
		 * The last field is used to express the controlling type: "p"
		 * means aux pause and "r" is for aux resume.
		 */
		fmt1_str = strtok_r(substr, ":", &fmt);
		fmt2_str = strtok_r(NULL, ":", &fmt);
		fmt3_str = strtok_r(NULL, ":", &fmt);
		if (!fmt1_str || !fmt2_str || !fmt3_str) {
			pr_err("Failed to parse bpf aux pause string: %s\n",
				substr);
			ret = -EINVAL;
			goto out;
		}

		entry->arg0 = strdup(fmt1_str);
		entry->arg1 = strdup(fmt2_str);
		entry->arg2 = strdup(fmt3_str);
		if (!entry->arg0 || !entry->arg1 || !entry->arg2) {
			ret = -ENOMEM;
			goto out;
		}

		if (!is_attach_kprobe(entry->arg0) &&
		    !is_attach_uprobe(entry->arg0) &&
		    !is_attach_tracepoint(entry->arg0)) {
			pr_err("Failed to support bpf aux pause attach: %s\n",
			       entry->arg0);
			ret = -EINVAL;
			goto out;
		}

		if (!is_valid_ctrl_type(entry->arg1)) {
			pr_err("Failed to support bpf aux pause ctrl: %s\n",
			       entry->arg1);
			ret = -EINVAL;
			goto out;
		}

		if (!is_attach_kprobe(entry->arg0)) {
			fmt4_str = strtok_r(NULL, ":", &fmt);
			if (!fmt4_str) {
				ret = -ENOMEM;
				goto out;
			}

			entry->arg3 = strdup(fmt4_str);
			if (!entry->arg3) {
				ret = -ENOMEM;
				goto out;
			}
		}

		if (ret)
			goto out;

		list_add(&entry->list, &trigger_list);
		trigger_entry_num++;
	}

	free(cmd_str);
	return 0;

out:
	free(cmd_str);
	if (entry) {
		free(entry->arg0);
		free(entry->arg1);
		free(entry->arg2);
		free(entry->arg3);
		free(entry);
	}
	auxtrace__free_bpf_trigger_list();
	return ret;
}

int auxtrace__prepare_bpf(struct auxtrace_record *itr, const char *str)
{
	int ret;

	if (!itr || !str)
		return 0;

	skel = auxtrace_pause_bpf__open();
	if (!skel) {
		pr_err("Failed to open func latency skeleton\n");
		return -1;
	}

	ret = auxtrace__alloc_bpf_trigger_list(str);
	if (ret) {
		auxtrace_pause_bpf__destroy(skel);
		skel = NULL;
		return ret;
	}

	return 0;
}

static struct bpf_link *auxtrace__attach_bpf_prog(struct trigger_entry *entry)
{
	struct bpf_link *link = NULL;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (!strcmp(entry->arg0, "kprobe")) {
		if (!strcmp(entry->arg1, "p")) {
			link = bpf_program__attach_kprobe(
					skel->progs.kprobe_event_pause,
					false, entry->arg2);
		} else if (!strcmp(entry->arg1, "r")) {
			link = bpf_program__attach_kprobe(
					skel->progs.kprobe_event_resume,
					false, entry->arg2);
		}
	} else if (!strcmp(entry->arg0, "kretprobe")) {
		if (!strcmp(entry->arg1, "p")) {
			link = bpf_program__attach_kprobe(
					skel->progs.kretprobe_event_pause,
					true, entry->arg2);
		} else if (!strcmp(entry->arg1, "r")) {
			link = bpf_program__attach_kprobe(
					skel->progs.kretprobe_event_resume,
					true, entry->arg2);
		}
	} else if (!strcmp(entry->arg0, "uprobe")) {
		uprobe_opts.func_name = entry->arg3;
		uprobe_opts.retprobe = false;
		if (!strcmp(entry->arg1, "p")) {
			link = bpf_program__attach_uprobe_opts(
					skel->progs.uprobe_event_pause,
					-1, entry->arg2, 0, &uprobe_opts);
		} else if (!strcmp(entry->arg1, "r")) {
			link = bpf_program__attach_uprobe_opts(
					skel->progs.uprobe_event_resume,
					-1, entry->arg2, 0, &uprobe_opts);
		}
	} else if (!strcmp(entry->arg0, "uretprobe")) {
		uprobe_opts.func_name = entry->arg3;
		uprobe_opts.retprobe = true;
		if (!strcmp(entry->arg1, "p")) {
			link = bpf_program__attach_uprobe_opts(
					skel->progs.uretprobe_event_pause,
					-1, entry->arg2, 0, &uprobe_opts);
		} else if (!strcmp(entry->arg1, "r")) {
			link = bpf_program__attach_uprobe_opts(
					skel->progs.uretprobe_event_resume,
					-1, entry->arg2, 0, &uprobe_opts);
		}

	} else if (is_attach_tracepoint(entry->arg0)) {
		if (!strcmp(entry->arg1, "p")) {
			link = bpf_program__attach_tracepoint(
					skel->progs.tp_event_pause,
					entry->arg2, entry->arg3);
		} else if (!strcmp(entry->arg1, "r")) {
			link = bpf_program__attach_tracepoint(
					skel->progs.tp_event_resume,
					entry->arg2, entry->arg3);
		}
	}

	return link;
}

int auxtrace__set_bpf_filter(struct evlist *evlist, struct record_opts *opts)
{
	int fd, err;
	int i, ncpus = 1, ntasks = 1;
	struct trigger_entry *trigger_entry;
	struct target *target;

	if (!skel)
		return 0;

	if (!opts)
		return -EINVAL;

	target = &opts->target;

	if (target__has_cpu(target)) {
		ncpus = perf_cpu_map__nr(evlist->core.user_requested_cpus);
		bpf_map__set_max_entries(skel->maps.cpu_filter, ncpus);
		skel->rodata->has_cpu = 1;
	}

	if (target__has_task(target) || target__none(target)) {
		ntasks = perf_thread_map__nr(evlist->core.threads);
		bpf_map__set_max_entries(skel->maps.task_filter, ntasks);
		skel->rodata->has_task = 1;
	}

	if (target->per_thread)
		skel->rodata->per_thread = 1;

	bpf_map__set_max_entries(skel->maps.events, libbpf_num_possible_cpus());

	err = auxtrace_pause_bpf__load(skel);
	if (err) {
		pr_err("Failed to load func latency skeleton: %d\n", err);
		goto out;
	}

	if (target__has_cpu(target)) {
		u32 cpu;
		u8 val = 1;

		fd = bpf_map__fd(skel->maps.cpu_filter);

		for (i = 0; i < ncpus; i++) {
			cpu = perf_cpu_map__cpu(evlist->core.user_requested_cpus, i).cpu;
			bpf_map_update_elem(fd, &cpu, &val, BPF_ANY);
		}
	}

	if (target__has_task(target) || target__none(target)) {
		u32 pid;
		u8 val = 1;

		fd = bpf_map__fd(skel->maps.task_filter);

		for (i = 0; i < ntasks; i++) {
			pid = perf_thread_map__pid(evlist->core.threads, i);
			bpf_map_update_elem(fd, &pid, &val, BPF_ANY);
		}
	}

	trigger_links = zalloc(sizeof(*trigger_links) * trigger_entry_num);
	if (!trigger_links)
		return -ENOMEM;

	i = 0;
	list_for_each_entry(trigger_entry, &trigger_list, list) {
		trigger_links[i] = auxtrace__attach_bpf_prog(trigger_entry);
		err = libbpf_get_error(trigger_links[i]);
		if (err) {
			pr_err("Failed to attach bpf program to aux pause entry\n");
			pr_err("  arg0=%s arg1=%s arg2=%s arg3=%s\n",
			       trigger_entry->arg0, trigger_entry->arg1,
			       trigger_entry->arg2, trigger_entry->arg3);
			trigger_links[i] = NULL;
			goto out;
		}
		i++;
	}

	return 0;

out:
	for (i = 0; i < trigger_entry_num; i++) {
		if (!trigger_links[i])
			continue;
		bpf_link__destroy(trigger_links[i]);
	}

	return err;
}

int auxtrace__enable_bpf(void)
{
	if (!skel)
		return 0;

	skel->bss->enabled = 1;
	return 0;
}

int auxtrace__cleanup_bpf(void)
{
	int i;

	if (!skel)
		return 0;

	for (i = 0; i < trigger_entry_num; i++) {
		if (!trigger_links[i])
			continue;
		bpf_link__destroy(trigger_links[i]);
	}

	auxtrace__free_bpf_trigger_list();
	auxtrace_pause_bpf__destroy(skel);
	return 0;
}

int auxtrace__update_bpf_map(struct evsel *evsel, int cpu_map_idx, int fd)
{
	int ret;

	if (!skel)
		return 0;

	if (!evsel->needs_auxtrace_mmap)
		return 0;

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.events),
				  &cpu_map_idx, &fd, BPF_ANY);
	if (ret) {
		pr_err("Failed to update BPF map for auxtrace: %s.\n",
			strerror(errno));
		if (errno == EOPNOTSUPP)
			pr_err("  Try to disable inherit mode with option '-i'.\n");
		return ret;
	}

	return 0;
}
