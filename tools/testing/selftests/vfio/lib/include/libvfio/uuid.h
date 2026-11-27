/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_UUID_H
#define SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_UUID_H

/*
 * Minimal replacement for libuuid's uuid_t and uuid_parse(). These mirror
 * the libuuid API, not the kernel's: uuid_t is a byte array (not a struct)
 * and uuid_parse() fills it in place (it does not take a uuid_t pointer).
 */
#define UUID_SIZE	16

typedef unsigned char uuid_t[UUID_SIZE];

int uuid_parse(const char *in, uuid_t uu);

#endif /* SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_UUID_H */
