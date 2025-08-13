/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TC_HELPERS_H
#define __TC_HELPERS_H


int generic_attach(const char *dev, int igr_fd, int egr_fd);
int generic_attach_igr(const char *dev, int igr_fd);
int generic_attach_egr(const char *dev, int egr_fd);
#endif
