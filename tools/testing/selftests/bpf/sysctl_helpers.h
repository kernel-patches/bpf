/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SYSCTL_HELPERS_H
#define __SYSCTL_HELPERS_H

int sysctl_set(const char *sysctl_path, char *old_val, const char *new_val);

#endif
