#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int bug(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;

	/* We want to print two strings */
	static const char fmt[] = "str1=%s str2=%s ";
	static char str1[] = "STR1";
	static char str2[] = "STR2";

	/*
	 * Because bpf_seq_printf takes parameters to its format specifiers in
	 * an array, we need to stuff pointers to str1 and str2 in a u64 array.
	 */

	/* First, we try a one-liner array initialization. Note that this is
	 * what the BPF_SEQ_PRINTF macro does under the hood. */
	__u64 param_not_working[] = { (__u64)str1, (__u64)str2 };
	/* But we also try a field by field initialization of the array. We
	 * would expect the arrays and the behavior to be exactly the same. */
	__u64 param_working[2];
	param_working[0] = (__u64)str1;
	param_working[1] = (__u64)str2;

	/* For convenience, only print once */
	if (ctx->meta->seq_num != 0)
		return 0;

	/* Using the one-liner array of params, it does not print the strings */
	bpf_seq_printf(seq, fmt, sizeof(fmt),
		       param_not_working, sizeof(param_not_working));
	/* Using the field-by-field array of params, it prints the strings */
	bpf_seq_printf(seq, fmt, sizeof(fmt),
		       param_working, sizeof(param_working));

	return 0;
}
