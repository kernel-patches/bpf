/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SIBYTE_SWARM_RTC_H
#define _SIBYTE_SWARM_RTC_H

#include <linux/time64.h>

int xicor_probe(void);
int xicor_set_time(time64_t t);
time64_t xicor_get_time(void);

int m41t81_probe(void);
int m41t81_set_time(time64_t t);
time64_t m41t81_get_time(void);

#endif /* _SIBYTE_SWARM_RTC_H */
