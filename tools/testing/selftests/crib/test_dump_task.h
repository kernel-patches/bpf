// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#ifndef __TEST_DUMP_TASK_H
#define __TEST_DUMP_TASK_H

#define EVENT_TYPE_VMA	0
#define EVENT_TYPE_TASK	1
#define EVENT_TYPE_MM	2

#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
#define VM_MAYREAD	0x00000010
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080
#define VM_GROWSDOWN	0x00000100
#define VM_UFFD_MISSING	0x00000200
#define VM_MAYOVERLAY	0x00000200
#define VM_PFNMAP	0x00000400
#define VM_UFFD_WP	0x00001000
#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000
#define VM_SEQ_READ	0x00008000
#define VM_RAND_READ	0x00010000
#define VM_DONTCOPY	0x00020000
#define VM_DONTEXPAND	0x00040000
#define VM_LOCKONFAULT	0x00080000
#define VM_ACCOUNT	0x00100000
#define VM_NORESERVE	0x00200000
#define VM_HUGETLB	0x00400000
#define VM_SYNC		0x00800000
#define VM_ARCH_1	0x01000000
#define VM_WIPEONFORK	0x02000000
#define VM_DONTDUMP	0x04000000
#define VM_SOFTDIRTY	0x08000000
#define VM_MIXEDMAP	0x10000000
#define VM_HUGEPAGE	0x20000000
#define VM_NOHUGEPAGE	0x40000000
#define VM_MERGEABLE	0x80000000

struct prog_args {
	int pid;
};

struct event_hdr {
	int type;
	int subtype;
};

struct event_task {
	struct event_hdr hdr;
	int pid;
	unsigned int flags;
	int prio;
	unsigned int policy;
	int exit_code;
	char comm[16];
};

struct event_vma {
	struct event_hdr hdr;
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_flags;
	unsigned long vm_pgoff;
};

struct event_mm {
	struct event_hdr hdr;
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

#endif /* __TEST_DUMP_TASK_H */
