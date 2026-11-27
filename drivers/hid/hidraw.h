/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (c) 2007 Jiri Kosina
 */
#ifndef _HIDRAW_H
#define _HIDRAW_H

#include <linux/errno.h>

struct hid_device;

#ifdef CONFIG_HIDRAW
int hidraw_init(void);
void hidraw_exit(void);
int hidraw_report_event(struct hid_device *, u8 *, int);
int hidraw_connect(struct hid_device *);
void hidraw_disconnect(struct hid_device *);
int hidraw_instance(const struct hid_device *hdev);
#else
static inline int hidraw_init(void) { return 0; }
static inline void hidraw_exit(void) { }
static inline int hidraw_report_event(struct hid_device *hid, u8 *data, int len) { return 0; }
static inline int hidraw_connect(struct hid_device *hid) { return -1; }
static inline void hidraw_disconnect(struct hid_device *hid) { }
static inline int hidraw_instance(const struct hid_device *hdev) { return -ENODEV; }
#endif

#endif
