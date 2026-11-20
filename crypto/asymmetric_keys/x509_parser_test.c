// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for the X.509 certificate parser.
 *
 * The cases build a minimal certificate in memory, vary the Subject or Issuer
 * name, and call x509_cert_parse().  The key and signature are dummies, so
 * Issuer and Subject must differ or the parser tries to verify the signature
 * as a self-signed certificate.
 */
#include <kunit/test.h>
#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "x509_parser.h"

/* Name DERs: empty, CN=x, CN=y, and one whose member is not a SET. */
static const u8 name_empty[] = { 0x30, 0x00 };
static const u8 name_cn[] = {
	0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x01, 0x78
};

static const u8 name_other_cn[] = {
	0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x01, 0x79
};

static const u8 name_not_a_set[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };

static const u8 cert_version[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
static const u8 cert_serial[] = { 0x02, 0x01, 0x01 };
/* sha256WithRSAEncryption, NULL parameters */
static const u8 cert_sig_algo[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x0b, 0x05, 0x00
};

/* 2026-01-01 to 2036-01-01 */
static const u8 cert_validity[] = {
	0x30, 0x1e,
	0x17, 0x0d, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
	0x17, 0x0d, '3', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
};

/* rsaEncryption with a dummy 4-byte key; the key is not parsed here */
static const u8 cert_spki[] = {
	0x30, 0x16,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00,
	0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04
};

static const u8 cert_signature[] = { 0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04 };

/* Write tag, length (up to 255) and @len bytes of @val at @out. */
static u8 *put_tlv(u8 *out, u8 tag, const u8 *val, size_t len)
{
	*out++ = tag;
	if (len > 127)
		*out++ = 0x81;
	*out++ = len;
	memcpy(out, val, len);
	return out + len;
}

static u8 *put_raw(u8 *out, const u8 *val, size_t len)
{
	memcpy(out, val, len);
	return out + len;
}

static struct x509_certificate *parse_cert(struct kunit *test,
					   const u8 *issuer, size_t issuer_len,
					   const u8 *subject, size_t subject_len)
{
	/* The parsed certificate keeps pointers into this buffer. */
	u8 *cert = kunit_kzalloc(test, 256, GFP_KERNEL);
	u8 tbs[160], body[256], *p = tbs, *q = body;

	KUNIT_ASSERT_NOT_NULL(test, cert);
	/* Keep tbs[] and body[] large enough for the fixed parts plus the names. */
	KUNIT_ASSERT_LE(test, issuer_len + subject_len, 64);

	p = put_raw(p, cert_version, sizeof(cert_version));
	p = put_raw(p, cert_serial, sizeof(cert_serial));
	p = put_raw(p, cert_sig_algo, sizeof(cert_sig_algo));
	p = put_raw(p, issuer, issuer_len);
	p = put_raw(p, cert_validity, sizeof(cert_validity));
	p = put_raw(p, subject, subject_len);
	p = put_raw(p, cert_spki, sizeof(cert_spki));

	q = put_tlv(q, 0x30, tbs, p - tbs);
	q = put_raw(q, cert_sig_algo, sizeof(cert_sig_algo));
	q = put_raw(q, cert_signature, sizeof(cert_signature));
	p = put_tlv(cert, 0x30, body, q - body);

	return x509_cert_parse(cert, p - cert);
}

/* RFC 5280 allows an empty Subject, so the certificate must parse. */
static void x509_empty_subject(struct kunit *test)
{
	struct x509_certificate *cert __free(x509_free_certificate) =
		parse_cert(test, name_other_cn, sizeof(name_other_cn),
			   name_empty, sizeof(name_empty));

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cert);
	/* raw_subject_size counts the contents, not the tag and length. */
	KUNIT_EXPECT_EQ(test, cert->raw_subject_size, 0);
}

/* Control: the same certificate with a one-RDN Subject parses. */
static void x509_named_subject(struct kunit *test)
{
	struct x509_certificate *cert __free(x509_free_certificate) =
		parse_cert(test, name_other_cn, sizeof(name_other_cn),
			   name_cn, sizeof(name_cn));

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cert);
	KUNIT_EXPECT_EQ(test, cert->raw_subject_size, sizeof(name_cn) - 2);
}

/* A Subject member that is not a SET must be rejected, not looped over. */
static void x509_subject_not_a_set(struct kunit *test)
{
	struct x509_certificate *cert __free(x509_free_certificate) =
		parse_cert(test, name_other_cn, sizeof(name_other_cn),
			   name_not_a_set, sizeof(name_not_a_set));

	KUNIT_EXPECT_EQ(test, PTR_ERR_OR_ZERO(cert), -EBADMSG);
}

/* The Issuer must not be empty. */
static void x509_empty_issuer(struct kunit *test)
{
	struct x509_certificate *cert __free(x509_free_certificate) =
		parse_cert(test, name_empty, sizeof(name_empty),
			   name_cn, sizeof(name_cn));

	KUNIT_EXPECT_EQ(test, PTR_ERR_OR_ZERO(cert), -EBADMSG);
}

static struct kunit_case x509_parser_cases[] = {
	KUNIT_CASE(x509_empty_subject),
	KUNIT_CASE(x509_named_subject),
	KUNIT_CASE(x509_subject_not_a_set),
	KUNIT_CASE(x509_empty_issuer),
	{}
};

static struct kunit_suite x509_parser_suite = {
	.name = "x509_parser",
	.test_cases = x509_parser_cases,
};

kunit_test_suite(x509_parser_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for the X.509 certificate parser");
