// SPDX-License-Identifier: GPL-2.0
#ifndef _BPF_MONITOR_H
#define _BPF_MONITOR_H

#ifdef HAVE_LIBBPF
int bpf_list_monitors(char *container);
int bpf_run_monitor(char *monitor_name, int argc, char **argv);
#else
static inline int bpf_list_monitors(char *container)
{
	return 0;
}

static inline int bpf_run_monitor(char *monitor_name, int argc, char **argv)
{
	return 0;
}

void bpf_usage_print_reactors(void) { }
#endif /* HAVE_LIBBPF */

#endif
