// SPDX-License-Identifier: GPL-2.0
#ifndef _BPF_MONITOR_H
#define _BPF_MONITOR_H

#ifdef HAVE_LIBBPF
int bpf_list_monitors(char *container);
#else
static inline int bpf_list_monitors(char *container)
{
	return 0;
}
#endif /* HAVE_LIBBPF */

#endif
