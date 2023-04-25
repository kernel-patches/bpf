// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/keyctl.h>
#include <test_progs.h>

#include "test_verify_pkcs7_umd_sig.skel.h"

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

#define VERIFY_USE_SECONDARY_KEYRING (1UL)
#define VERIFY_USE_PLATFORM_KEYRING  (2UL)

/* In stripped ARM and x86-64 modules, ~ is surprisingly rare. */
#define MODULE_SIG_STRING "~Module signature appended~\n"

#define PKEY_ID_PGP 0
#define PKEY_ID_X509 1
#define PKEY_ID_PKCS7 2

static char *key_types_str[PKEY_ID_PKCS7 + 1] = {
	[PKEY_ID_PGP] = "pgp",
	[PKEY_ID_X509] = "x509",
	[PKEY_ID_PKCS7] = "pkcs7",
};

enum algos { ALGO_RSA, ALGO_ECDSA_P256, ALGO_ECDSA_P384, ALGO__LAST };

static char *algos_str[ALGO_ECDSA_P384 + 1] = {
	[ALGO_RSA] = "rsa",
	[ALGO_ECDSA_P256] = "ecdsa_p256",
	[ALGO_ECDSA_P384] = "ecdsa_p384",
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
	__u8	algo;		/* Public-key crypto algorithm [0] */
	__u8	hash;		/* Digest algorithm [0] */
	__u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	__u8	signer_len;	/* Length of signer's name [0] */
	__u8	key_id_len;	/* Length of key identifier [0] */
	__u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

struct data {
	__u8 data[MAX_DATA_SIZE];
	__u32 data_len;
	__u8 sig[MAX_SIG_SIZE];
	__u32 sig_len;
};

static bool kfunc_not_supported;

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (level == LIBBPF_WARN)
		vprintf(fmt, args);

	if (strcmp(fmt, "libbpf: extern (func ksym) '%s': not found in kernel or module BTFs\n"))
		return 0;

	if (strcmp(va_arg(args, char *), "bpf_verify_pkcs7_signature"))
		return 0;

	kfunc_not_supported = true;
	return 0;
}

static int _run_setup_process(const char *setup_dir, const char *cmd,
			      __u8 key_type, __u8 pkey_algo)
{
	int child_pid, child_status;

	child_pid = fork();
	if (child_pid == 0) {
		execlp("./verify_sig_setup.sh", "./verify_sig_setup.sh",
		       cmd, key_types_str[key_type], algos_str[pkey_algo] ?: "",
		       setup_dir, NULL);
		exit(errno);

	} else if (child_pid > 0) {
		waitpid(child_pid, &child_status, 0);
		return WEXITSTATUS(child_status);
	}

	return -EINVAL;
}

static int populate_data_item_str(const char *tmp_dir, __u8 key_type,
				  struct data *data_item)
{
	struct stat st;
	char data_template[] = "/tmp/dataXXXXXX";
	char path[PATH_MAX];
	int ret, fd, child_status, child_pid;

	data_item->data_len = 4;
	memcpy(data_item->data, "test", data_item->data_len);

	fd = mkstemp(data_template);
	if (fd == -1)
		return -errno;

	ret = write(fd, data_item->data, data_item->data_len);

	close(fd);

	if (ret != data_item->data_len) {
		ret = -EIO;
		goto out;
	}

	child_pid = fork();

	if (child_pid == -1) {
		ret = -errno;
		goto out;
	}

	if (child_pid == 0) {
		if (key_type == PKEY_ID_PKCS7) {
			snprintf(path, sizeof(path), "%s/signing_key.pem",
				 tmp_dir);

			return execlp("./sign-file", "./sign-file", "-d",
				      "sha256", path, path, data_template,
				      NULL);
		} else {
			snprintf(path, sizeof(path), "%s.gpg", data_template);

			return execlp("gpg", "gpg", "--no-options",
				      "--no-auto-check-trustdb",
				      "--no-permission-warning",
				      "--default-key", "eBPF_UMD_Test",
				      "--sign", "-o", path, "--batch", "--yes",
				      "--compress-algo=none", "-b",
				      "--passphrase", "abc",
				      "--pinentry-mode", "loopback", "-q",
				      data_template, NULL);
		}
	}

	waitpid(child_pid, &child_status, 0);

	ret = WEXITSTATUS(child_status);
	if (ret)
		goto out;

	if (key_type == PKEY_ID_PKCS7)
		snprintf(path, sizeof(path), "%s.p7s", data_template);
	else
		snprintf(path, sizeof(path), "%s.gpg", data_template);

	ret = stat(path, &st);
	if (ret == -1) {
		ret = -errno;
		goto out;
	}

	if (st.st_size > sizeof(data_item->sig)) {
		ret = -EINVAL;
		goto out_sig;
	}

	data_item->sig_len = st.st_size;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ret = -errno;
		goto out_sig;
	}

	ret = read(fd, data_item->sig, data_item->sig_len);

	close(fd);

	if (ret != data_item->sig_len) {
		ret = -EIO;
		goto out_sig;
	}

	ret = 0;
out_sig:
	unlink(path);
out:
	unlink(data_template);
	return ret;
}

static int populate_data_item_mod(struct data *data_item)
{
	char mod_path[PATH_MAX], *mod_path_ptr;
	struct stat st;
	void *mod;
	FILE *fp;
	struct module_signature ms;
	int ret, fd, modlen, marker_len, sig_len;

	data_item->data_len = 0;

	if (stat("/lib/modules", &st) == -1)
		return 0;

	/* Requires CONFIG_TCP_CONG_BIC=m. */
	fp = popen("find /lib/modules/$(uname -r) -name tcp_bic.ko", "r");
	if (!fp)
		return 0;

	mod_path_ptr = fgets(mod_path, sizeof(mod_path), fp);
	pclose(fp);

	if (!mod_path_ptr)
		return 0;

	mod_path_ptr = strchr(mod_path, '\n');
	if (!mod_path_ptr)
		return 0;

	*mod_path_ptr = '\0';

	if (stat(mod_path, &st) == -1)
		return 0;

	modlen = st.st_size;
	marker_len = sizeof(MODULE_SIG_STRING) - 1;

	fd = open(mod_path, O_RDONLY);
	if (fd == -1)
		return -errno;

	mod = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	close(fd);

	if (mod == MAP_FAILED)
		return -errno;

	if (strncmp(mod + modlen - marker_len, MODULE_SIG_STRING, marker_len)) {
		ret = -EINVAL;
		goto out;
	}

	modlen -= marker_len;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));

	sig_len = __be32_to_cpu(ms.sig_len);
	modlen -= sig_len + sizeof(ms);

	if (modlen > sizeof(data_item->data)) {
		ret = -E2BIG;
		goto out;
	}

	memcpy(data_item->data, mod, modlen);
	data_item->data_len = modlen;

	if (sig_len > sizeof(data_item->sig)) {
		ret = -E2BIG;
		goto out;
	}

	memcpy(data_item->sig, mod + modlen, sig_len);
	data_item->sig_len = sig_len;
	ret = 0;
out:
	munmap(mod, st.st_size);
	return ret;
}

static void test_verify_pkcs7_umd_sig(__u8 key_type, __u8 pkey_algo)
{
	libbpf_print_fn_t old_print_cb;
	char tmp_dir_template[] = "/tmp/verify_sigXXXXXX";
	char *tmp_dir;
	struct test_verify_pkcs7_umd_sig *skel = NULL;
	struct bpf_map *map;
	struct data data;
	int ret, zero = 0;

	/* Trigger creation of session keyring. */
	syscall(__NR_request_key, "keyring", "_uid.0", NULL,
		KEY_SPEC_SESSION_KEYRING);

	tmp_dir = mkdtemp(tmp_dir_template);
	if (!ASSERT_OK_PTR(tmp_dir, "mkdtemp"))
		return;

	ret = _run_setup_process(tmp_dir, "setup", key_type, pkey_algo);
	if (!ASSERT_OK(ret, "_run_setup_process"))
		goto close_prog;

	skel = test_verify_pkcs7_umd_sig__open();
	if (!ASSERT_OK_PTR(skel, "test_verify_pkcs7_umd_sig__open"))
		goto close_prog;

	old_print_cb = libbpf_set_print(libbpf_print_cb);
	ret = test_verify_pkcs7_umd_sig__load(skel);
	libbpf_set_print(old_print_cb);

	if (ret < 0 && kfunc_not_supported) {
		printf(
		  "%s:SKIP:bpf_verify_*_signature() kfunc not supported\n",
		  __func__);
		test__skip();
		goto close_prog;
	}

	if (!ASSERT_OK(ret, "test_verify_pkcs7_umd_sig__load"))
		goto close_prog;

	ret = test_verify_pkcs7_umd_sig__attach(skel);
	if (!ASSERT_OK(ret, "test_verify_pkcs7_umd_sig__attach"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (!ASSERT_OK_PTR(map, "data_input not found"))
		goto close_prog;

	skel->bss->key_type = key_type;
	skel->bss->monitored_pid = getpid();

	/* Test without data and signature. */
	skel->bss->user_keyring_serial = KEY_SPEC_SESSION_KEYRING;

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem data_input"))
		goto close_prog;

	/* Test successful signature verification with session keyring. */
	ret = populate_data_item_str(tmp_dir, key_type, &data);
	if (!ASSERT_OK(ret, "populate_data_item_str"))
		goto close_prog;

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_OK(ret, "bpf_map_update_elem data_input"))
		goto close_prog;

	/* Test successful signature verification with testing keyring. */
	skel->bss->user_keyring_serial = syscall(__NR_request_key, "keyring",
						 "ebpf_testing_keyring", NULL,
						 KEY_SPEC_SESSION_KEYRING);

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_OK(ret, "bpf_map_update_elem data_input"))
		goto close_prog;

	/*
	 * Ensure key_task_permission() is called and rejects the keyring
	 * (no Search permission).
	 */
	syscall(__NR_keyctl, KEYCTL_SETPERM, skel->bss->user_keyring_serial,
		0x37373737);

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem data_input"))
		goto close_prog;

	syscall(__NR_keyctl, KEYCTL_SETPERM, skel->bss->user_keyring_serial,
		0x3f3f3f3f);

	/*
	 * Ensure key_validate() is called and rejects the keyring (key expired)
	 */
	syscall(__NR_keyctl, KEYCTL_SET_TIMEOUT,
		skel->bss->user_keyring_serial, 1);
	sleep(1);

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem data_input"))
		goto close_prog;

	skel->bss->user_keyring_serial = KEY_SPEC_SESSION_KEYRING;

	/* Test with corrupted data (signature verification should fail). */
	data.data[0] = 'a';
	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem data_input"))
		goto close_prog;

	data.data_len = 0;

	if (key_type == PKEY_ID_PKCS7) {
		ret = populate_data_item_mod(&data);
		if (!ASSERT_OK(ret, "populate_data_item_mod"))
			goto close_prog;
	}

	/* Test signature verification with system keyrings. */
	if (data.data_len) {
		skel->bss->user_keyring_serial = 0;
		skel->bss->system_keyring_id = 0;

		ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data,
					  BPF_ANY);
		if (!ASSERT_OK(ret, "bpf_map_update_elem data_input"))
			goto close_prog;

		skel->bss->system_keyring_id = VERIFY_USE_SECONDARY_KEYRING;

		ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data,
					  BPF_ANY);
		if (!ASSERT_OK(ret, "bpf_map_update_elem data_input"))
			goto close_prog;

		skel->bss->system_keyring_id = VERIFY_USE_PLATFORM_KEYRING;

		ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data,
					  BPF_ANY);
		ASSERT_LT(ret, 0, "bpf_map_update_elem data_input");
	}

close_prog:
	_run_setup_process(tmp_dir, "cleanup", key_type, pkey_algo);

	if (!skel)
		return;

	skel->bss->monitored_pid = 0;
	test_verify_pkcs7_umd_sig__destroy(skel);
}

void test_verify_pkcs7_sig(void)
{
	return test_verify_pkcs7_umd_sig(PKEY_ID_PKCS7, ALGO__LAST);
}

void test_verify_umd_sig(void)
{
	int i;

	/* Change the limit to ALGO__LAST when UMD supports PGP. */
	for (i = 0; i < 0; i++)
		test_verify_pkcs7_umd_sig(PKEY_ID_PGP, i);
}
