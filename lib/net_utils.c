// SPDX-License-Identifier: GPL-2.0
#include <linux/string.h>
#include <linux/if_ether.h>
#include <linux/ctype.h>
#include <linux/export.h>
#include <linux/hex.h>

/**
 * parse_mac_pton - convert a MAC address string using a custom delimiter
 * @s: string to be parsed
 * @mac: buffer to store the result, left untouched if @s is malformed
 * @delim: characters accepted as a separator between the byte pairs
 *
 * @s must be MAC_ADDR_STR_LEN characters long and use a character from
 * @delim at every separator position, e.g. "aa.bb:cc.dd:ee.ff" with ".:".
 *
 * Return: true on success, false if @s is malformed.
 */
bool parse_mac_pton(const char *s, u8 *mac, const char *delim)
{
	int i;

	if (strnlen(s, MAC_ADDR_STR_LEN) < MAC_ADDR_STR_LEN)
		return false;

	/* Don't dirty result unless string is valid MAC. */
	for (i = 0; i < ETH_ALEN; i++) {
		if (!isxdigit(s[i * 3]) || !isxdigit(s[i * 3 + 1]))
			return false;
		if (i != ETH_ALEN - 1 && !strchr(delim, s[i * 3 + 2]))
			return false;
	}
	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = (hex_to_bin(s[i * 3]) << 4) | hex_to_bin(s[i * 3 + 1]);
	}
	return true;
}
EXPORT_SYMBOL(parse_mac_pton);
