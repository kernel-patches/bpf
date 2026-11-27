/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_KMSG_H
#define SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_KMSG_H

int kmsg_open(void);
void kmsg_print_warnings(int fd);

#endif /* SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_KMSG_H */
