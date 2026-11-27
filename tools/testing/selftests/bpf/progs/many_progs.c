// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define REP10(M, p) M(p##0) M(p##1) M(p##2) M(p##3) M(p##4) M(p##5) M(p##6) M(p##7) M(p##8) M(p##9)
#define REP100(M, p) REP10(M, p##0) REP10(M, p##1) REP10(M, p##2) REP10(M, p##3) REP10(M, p##4) \
		     REP10(M, p##5) REP10(M, p##6) REP10(M, p##7) REP10(M, p##8) REP10(M, p##9)

#define PROG(n)							\
struct {							\
	__uint(type, BPF_MAP_TYPE_ARRAY);			\
	__uint(max_entries, 1);					\
	__type(key, int);					\
	__type(value, int);					\
} map##n SEC(".maps");						\
								\
SEC("tc")							\
int prog##n(void *ctx)						\
{								\
	int *v = bpf_map_lookup_elem(&map##n, &(int){ 0 });	\
								\
	return v ? *v + n : 0;					\
}

REP100(PROG, 1) REP100(PROG, 2) REP100(PROG, 3) REP100(PROG, 4) REP100(PROG, 5) REP100(PROG, 6)

extern const void no_such_symbol __ksym __weak;

/* The loader is more than 32768 insns away from its cleanup code */
SEC("tc")
int last(void *ctx)
{
	return &no_such_symbol ? 1 : 2;
}

char _license[] SEC("license") = "GPL";
