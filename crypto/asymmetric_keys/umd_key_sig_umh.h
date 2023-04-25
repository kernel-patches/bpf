/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file for communication between the kernel and the UMD handler.
 */

#include <linux/hash_info.h>

#define MAX_KEY_SIZE 1024
#define MAX_KEY_DESC_SIZE 256
#define MAX_PAYLOAD_SIZE 8192
#define MAX_KID_SIZE 256
#define MAX_SIG_SIZE MAX_KEY_SIZE
#define MAX_SIG_DATA_SIZE 1024

#ifndef __packed
#define __packed __attribute__((packed))
#endif

enum cmds { CMD_KEY, CMD_SIG, CMD__LAST };

/* Public key algorithms that the kernel supports. */
enum pub_key_algos { PUBKEY_ALGO_RSA, PUBKEY_ALGO_ECDSA,
		     PUBKEY_ALGO_ECDSA_NIST_P192, PUBKEY_ALGO_ECDSA_NIST_P256,
		     PUBKEY_ALGO_ECDSA_NIST_P384, PUBKEY_ALGO__LAST };

/* Signature encodings that the kernel supports. */
enum sig_encodings { SIG_ENC_PKCS1, SIG_ENC_X962, SIG_ENC_RAW, SIG_ENC__LAST };

struct msg_in {
	enum cmds cmd;
	size_t data_len;
	unsigned char data[MAX_PAYLOAD_SIZE];
} __packed;

struct umd_asymmetric_key_ids {
	size_t kid1_len[3];
	unsigned char kid1[3][MAX_KID_SIZE];
	size_t kid2_len[3];
	unsigned char kid2[3][MAX_KID_SIZE];
} __packed;

struct umd_key_msg_out {
	size_t pub_key_len;
	unsigned char pub_key[MAX_KEY_SIZE];
	enum pub_key_algos pkey_algo;
	struct umd_asymmetric_key_ids kids;
	char key_desc[MAX_KEY_DESC_SIZE];
} __packed;

struct umd_sig_msg_out {
	size_t sig_len;
	unsigned char sig[MAX_SIG_SIZE];
	enum pub_key_algos pkey_algo;
	enum hash_algo hash_algo;
	enum sig_encodings enc;
	struct umd_asymmetric_key_ids auth_ids;
	size_t sig_data_len;
	unsigned char sig_data[MAX_SIG_DATA_SIZE];
} __packed;

struct msg_out {
	int ret;
	union {
		struct umd_key_msg_out key;
		struct umd_sig_msg_out sig;
	};
} __packed;
