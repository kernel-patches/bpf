// SPDX-License-Identifier: GPL-2.0
#include <openssl/err.h>

/*
 * ERR_get_error_all() was introduced in openssl3
 *
 * https://docs.openssl.org/3.0/man3/ERR_get_error/
 */
int main(void)
{
	return ERR_get_error_all(NULL, NULL, NULL, NULL, NULL);
}
