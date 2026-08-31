/* SPDX-License-Identifier: GPL-2.0 */

#ifndef NETDEVSIM_HELPERS_H
#define NETDEVSIM_HELPERS_H

int netdevsim_create(unsigned int *ifindex);
void netdevsim_destroy(unsigned int id);

#endif /* NETDEVSIM_HELPERS_H */
