/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLE_UMH_MSGFMT_H
#define _SAMPLE_UMH_MSGFMT_H

struct sample_request {
	uint32_t offset;
};

struct sample_reply {
	uint8_t data[128 * 1024];
};

#endif
