/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BUILD_ID_H
#define __BUILD_ID_H

/*
 * The helper issues getpgid() with this (nonexistent) pid after paging out the
 * build ID page.  The BPF program filters on the syscall id and this argument,
 * so getpid()/read() etc. issued before the page-out cannot be mistaken for it.
 */
#define TARGET_SYSCALL_ARG	0x7ffffffeUL

#endif /* __BUILD_ID_H */

