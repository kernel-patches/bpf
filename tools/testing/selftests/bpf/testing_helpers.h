/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (C) 2020 Facebook, Inc. */

#ifndef __TRACING_HELPERS_H
#define __TRACING_HELPERS_H

#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int parse_num_list(const char *s, bool **set, int *set_len);
__u32 link_info_prog_id(const struct bpf_link *link, struct bpf_link_info *info);
int bpf_prog_test_load(const char *file, enum bpf_prog_type type,
		       struct bpf_object **pobj, int *prog_fd);
int bpf_test_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
			  size_t insns_cnt, const char *license,
			  __u32 kern_version, char *log_buf,
			  size_t log_buf_sz);

/*
 * below function is exported for testing in prog_test test
 */
struct test_filter_set;
int parse_test_list(const char *s,
		    struct test_filter_set *test_set,
		    bool is_glob_pattern);

int load_bpf_testmod(FILE *err, bool verbose);
int unload_bpf_testmod(FILE *err, bool verbose);
int kern_sync_rcu(void);

#endif /* __TRACING_HELPERS_H */
