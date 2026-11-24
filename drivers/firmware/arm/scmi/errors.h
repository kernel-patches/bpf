/* SPDX-License-Identifier: GPL-2.0 */
/*
 * System Control and Management Interface (SCMI) Message Protocol
 * header containing SCMI errors definitions and Linux mapping.
 *
 * Copyright (C) 2018-2026 ARM Ltd.
 */
#ifndef _SCMI_ERRORS_H
#define _SCMI_ERRORS_H

#include <linux/errno.h>
#include <linux/array_size.h>

enum scmi_error_codes {
	SCMI_SUCCESS = 0,	/* Success */
	SCMI_ERR_SUPPORT = -1,	/* Not supported */
	SCMI_ERR_PARAMS = -2,	/* Invalid Parameters */
	SCMI_ERR_ACCESS = -3,	/* Invalid access/permission denied */
	SCMI_ERR_ENTRY = -4,	/* Not found */
	SCMI_ERR_RANGE = -5,	/* Value out of range */
	SCMI_ERR_BUSY = -6,	/* Device busy */
	SCMI_ERR_COMMS = -7,	/* Communication Error */
	SCMI_ERR_GENERIC = -8,	/* Generic Error */
	SCMI_ERR_HARDWARE = -9,	/* Hardware Error */
	SCMI_ERR_PROTOCOL = -10,/* Protocol Error */
	SCMI_ERR_IN_USE = -11,  /* In Use Error */
	SCMI_ERR_PARTIAL = -12, /* Partial Error */
};

static const int scmi_linux_errmap[] = {
	/* better than switch case as long as return value is continuous */
	0,			/* SCMI_SUCCESS */
	-EOPNOTSUPP,		/* SCMI_ERR_SUPPORT */
	-EINVAL,		/* SCMI_ERR_PARAM */
	-EACCES,		/* SCMI_ERR_ACCESS */
	-ENOENT,		/* SCMI_ERR_ENTRY */
	-ERANGE,		/* SCMI_ERR_RANGE */
	-EBUSY,			/* SCMI_ERR_BUSY */
	-ECOMM,			/* SCMI_ERR_COMMS */
	-EIO,			/* SCMI_ERR_GENERIC */
	-EREMOTEIO,		/* SCMI_ERR_HARDWARE */
	-EPROTO,		/* SCMI_ERR_PROTOCOL */
	-EBUSY,			/* SCMI_ERR_IN_USE */
	-EBADMSG,		/* SCMI_ERR_PARTIAL */
};

static inline int scmi_to_linux_errno(int errno)
{
	int err_idx = -errno;

	if (err_idx >= SCMI_SUCCESS && err_idx < ARRAY_SIZE(scmi_linux_errmap))
		return scmi_linux_errmap[err_idx];
	return -EIO;
}

#endif /* _SCMI_ERRORS_H */
