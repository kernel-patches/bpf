/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_ZIP_H
#define __LIBBPF_ZIP_H

#include <stdint.h>

/* Represents an opened zip archive.
 * Only basic ZIP files are supported, in particular the following are not
 * supported:
 * - encryption
 * - streaming
 * - multi-part ZIP files
 * - ZIP64
 */
struct zip_archive;

/* Carries information on name, compression method, and data corresponding to a
 * file in a zip archive.
 */
struct zip_entry {
	/* Compression method as defined in pkzip spec. 0 means data is uncompressed. */
	uint16_t compression;

	/* Non-null terminated name of the file. */
	const char *name;
	/* Length of the file name. */
	uint16_t name_length;

	/* Pointer to the file data. */
	const void *data;
	/* Length of the file data. */
	uint32_t data_length;
	/* Offset of the file data within the archive. */
	uint32_t data_offset;
};

/* Open a zip archive. Returns NULL in case of an error. */
struct zip_archive *zip_archive_open(const char *path);

/* Close a zip archive and release resources. */
void zip_archive_close(struct zip_archive *archive);

/* Look up an entry corresponding to a file in given zip archive. */
int zip_archive_find_entry(struct zip_archive *archive, const char *name, struct zip_entry *out);

#endif
