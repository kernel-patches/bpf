// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_DATA_SIZE 4096

#ifdef __BIG_ENDIAN__
#define be32_to_cpu(x) (x)
#else
#define be32_to_cpu(x) ___bpf_swab32(x)
#endif

#define VERIFY_USE_SECONDARY_KEYRING (1UL)

/* In stripped ARM and x86-64 modules, ~ is surprisingly rare. */
#define MODULE_SIG_STRING "~Module signature appended~\n"

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_PKCS7,		/* Signature in PKCS#7 message */
};

/*
 * Module signature information block.
 *
 * The constituents of the signature section are, in order:
 *
 *	- Signer's name
 *	- Key identifier
 *	- Signature data
 *	- Information block
 */
struct module_signature {
	u8	algo;		/* Public-key crypto algorithm [0] */
	u8	hash;		/* Digest algorithm [0] */
	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	u8	signer_len;	/* Length of signer's name [0] */
	u8	key_id_len;	/* Length of key identifier [0] */
	u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

u32 monitored_pid;
u32 keyring_id;

struct data {
	u8 payload[MAX_DATA_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct data);
} data_input SEC(".maps");

char _license[] SEC("license") = "GPL";

static int mod_check_sig(const struct module_signature *ms, size_t file_len)
{
	if (!ms)
		return -ENOENT;

	if (be32_to_cpu(ms->sig_len) >= file_len - sizeof(*ms))
		return -EBADMSG;

	if (ms->id_type != PKEY_ID_PKCS7)
		return -ENOPKG;

	if (ms->algo != 0 ||
	    ms->hash != 0 ||
	    ms->signer_len != 0 ||
	    ms->key_id_len != 0 ||
	    ms->__pad[0] != 0 ||
	    ms->__pad[1] != 0 ||
	    ms->__pad[2] != 0)
		return -EBADMSG;

	return 0;
}

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	const size_t marker_len = sizeof(MODULE_SIG_STRING) - 1;
	char marker[sizeof(MODULE_SIG_STRING) - 1];
	struct module_signature ms;
	struct data *data_ptr;
	u32 modlen;
	u32 sig_len;
	u64 value;
	u8 *mod;
	u32 pid;
	int ret, zero = 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	data_ptr = bpf_map_lookup_elem(&data_input, &zero);
	if (!data_ptr)
		return 0;

	bpf_probe_read(&value, sizeof(value), &attr->value);

	bpf_copy_from_user(data_ptr, sizeof(struct data),
			   (void *)(unsigned long)value);

	modlen = be32_to_cpu(*(u32 *)data_ptr->payload);
	mod = data_ptr->payload + sizeof(u32);

	if (modlen > sizeof(struct data) - sizeof(u32))
		return -EINVAL;

	if (modlen <= marker_len)
		return -ENOENT;

	modlen &= sizeof(struct data) - 1;
	bpf_probe_read(marker, marker_len, (char *)mod + modlen - marker_len);

	if (bpf_strncmp(marker, marker_len, MODULE_SIG_STRING))
		return -ENOENT;

	modlen -= marker_len;

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	bpf_probe_read(&ms, sizeof(ms), (char *)mod + (modlen - sizeof(ms)));

	ret = mod_check_sig(&ms, modlen);
	if (ret)
		return ret;

	sig_len = be32_to_cpu(ms.sig_len);
	modlen -= sig_len + sizeof(ms);

	modlen &= 0x3ff;
	sig_len &= 0x3ff;

	return bpf_verify_signature(mod, modlen, mod + modlen, sig_len,
				    keyring_id + (PKEY_ID_PKCS7 << 16));
}
