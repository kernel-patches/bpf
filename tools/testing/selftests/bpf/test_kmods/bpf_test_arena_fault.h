// SPDX-License-Identifier: GPL-2.0

#ifndef __BPF_TEST_ARENA_FAULT_H
#define __BPF_TEST_ARENA_FAULT_H

void bpf_test_arena_fault_stash(__u64 *ptr__arena) __ksym;
__u64 bpf_test_arena_fault_load_stashed(void) __ksym;
void bpf_test_arena_fault_clear_stashed(void) __ksym;

#endif /* __BPF_TEST_ARENA_FAULT_H */
