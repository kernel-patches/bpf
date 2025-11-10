// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

unsigned char test_input[3] = "abc";

/* Expected SHA-256 hash of "abc" */
/* ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
unsigned char expected_sha256[32] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/* Output buffers for test results */
unsigned char sha256_output[32] = {};
unsigned char sha384_output[48] = {};
unsigned char sha512_output[64] = {};

int sha256_status = -1;
int sha384_status = -1;
int sha512_status = -1;

/* Declare the SHA hash kfuncs */
extern int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;
extern int bpf_sha384_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;
extern int bpf_sha512_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out) __ksym;

SEC("syscall")
int test_sha256(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha256_output, sizeof(sha256_output), 0, &output_ptr);

	sha256_status = bpf_sha256_hash(&input_ptr, &output_ptr);
	return 0;
}

SEC("syscall")
int test_sha384(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha384_output, sizeof(sha384_output), 0, &output_ptr);

	sha384_status = bpf_sha384_hash(&input_ptr, &output_ptr);
	return 0;
}

SEC("syscall")
int test_sha512(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha512_output, sizeof(sha512_output), 0, &output_ptr);

	sha512_status = bpf_sha512_hash(&input_ptr, &output_ptr);
	return 0;
}

SEC("syscall")
int test_sha256_zero_len(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	int ret;

	bpf_dynptr_from_mem(test_input, 0, 0, &input_ptr);
	bpf_dynptr_from_mem(sha256_output, sizeof(sha256_output), 0, &output_ptr);

	ret = bpf_sha256_hash(&input_ptr, &output_ptr);
	sha256_status = (ret == -22) ? 0 : ret;
	return 0;
}

char __license[] SEC("license") = "GPL";
