// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Sign a module file using the given key and certificate.
 *
 * Inspired by Linux scripts/sign-file.c
 * Copyright (C) 2021 Matteo Croce <mcroce@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/cms.h>

#include "main.h"

static const char *key_pass;

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	int pwlen;

	if (!key_pass)
		return -1;

	pwlen = strlen(key_pass);
	if (pwlen >= len)
		return -1;

	strcpy(buf, key_pass);

	/* If it's wrong, don't keep trying it. */
	key_pass = NULL;

	return pwlen;
}

static void display_openssl_errors(void)
{
	const char *file;
	char buf[120];
	int e, line;

	if (!ERR_peek_error())
		return;

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static EVP_PKEY *read_private_key(const char *key_path)
{
	EVP_PKEY *private_key;

	if (!strncmp(key_path, "pkcs11:", 7)) {
		ENGINE *e;

		ENGINE_load_builtin_engines();
		display_openssl_errors();
		e = ENGINE_by_id("pkcs11");
		if (!e)
			return NULL;

		if (!ENGINE_init(e)) {
			display_openssl_errors();
			return NULL;
		}
		display_openssl_errors();

		if (key_pass)
			if (!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0))
				return NULL;
		private_key = ENGINE_load_private_key(e, key_path, NULL, NULL);
	} else {
		BIO *b;

		b = BIO_new_file(key_path, "rb");
		if (!b)
			return NULL;
		private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, NULL);
		BIO_free(b);
	}

	return private_key;
}

static X509 *read_x509(const char *x509_path)
{
	unsigned char buf[2];
	X509 *x509 = NULL;
	BIO *b;
	int n;

	b = BIO_new_file(x509_path, "rb");
	if (!b) {
		display_openssl_errors();
		return NULL;
	}

	/* Look at the first two bytes of the file to determine the encoding */
	n = BIO_read(b, buf, 2);
	if (n != 2) {
		if (BIO_should_retry(b))
			fprintf(stderr, "%s: Read wanted retry\n", x509_path);
		if (n >= 0)
			fprintf(stderr, "%s: Short read\n", x509_path);
		display_openssl_errors();
		goto out_free;
	}

	if (BIO_reset(b)) {
		display_openssl_errors();
		goto out_free;
	}

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		/* Assume raw DER encoded X.509 */
		x509 = d2i_X509_bio(b, NULL);
	else
		/* Assume PEM encoded X.509 */
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	if (!x509)
		display_openssl_errors();

out_free:
	BIO_free(b);

	return x509;
}

int sign(const char *hash_algo, const char *key_path, const char *x509_path,
	 const char *indata, int indatalen, unsigned char **outdata)
{
	CMS_ContentInfo *cms = NULL;
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key;
	X509 *x509;
	BIO *bm;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	key_pass = getenv("KBUILD_SIGN_PIN");

	/* Open the module file */
	bm = BIO_new_mem_buf(indata, indatalen);
	if (!bm) {
		display_openssl_errors();
		return -1;
	}

	/* Read the private key and the X.509 cert the PKCS#7 message
	 * will point to.
	 */
	private_key = read_private_key(key_path);
	if (!private_key)
		goto out_free;

	x509 = read_x509(x509_path);
	if (!x509)
		goto out_free;

	/* Digest the module data. */
	OpenSSL_add_all_digests();
	display_openssl_errors();

	digest_algo = EVP_get_digestbyname(hash_algo);
	if (!digest_algo) {
		display_openssl_errors();
		goto out_free;
	}

	/* Load the signature message from the digest buffer. */
	cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_NOCERTS | CMS_PARTIAL |
		       CMS_BINARY | CMS_DETACHED | CMS_STREAM);
	if (!cms) {
		display_openssl_errors();
		goto out_free;
	}

	if (!CMS_add1_signer(cms, x509, private_key, digest_algo,
			     CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
			     CMS_NOATTR)) {
		display_openssl_errors();
		goto out_free;
	}

	if (CMS_final(cms, bm, NULL, CMS_NOCERTS | CMS_BINARY) < 0)
		display_openssl_errors();

out_free:
	BIO_free(bm);

	if (!cms)
		return -1;

	return i2d_CMS_ContentInfo(cms, outdata);
}
