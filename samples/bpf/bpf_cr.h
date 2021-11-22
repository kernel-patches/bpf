// SPDX-License-Identifier: GPL-2.0-only

#ifndef BPF_CR_H
#define BPF_CR_H

/* The order of restore actions is in order of declaration for each type,
 * hence on restore consumed descriptors can be sorted based on their type,
 * and then each action for the corresponding descriptor can be invoked, to
 * recreate the io_uring.
 */
enum io_uring_state_type {
	DUMP_SETUP,	/* Record setup parameters */
	DUMP_EVENTFD,	/* eventfd registered in io_uring */
	DUMP_REG_FD,	/* fd registered in io_uring */
	DUMP_REG_BUF,	/* buffer registered in io_uring */
	__DUMP_MAX,
};

struct io_uring_dump {
	enum io_uring_state_type type;
	int32_t io_uring_fd;
	bool end;
	union {
		struct /* DUMP_SETUP */ {
			uint32_t flags;
			uint32_t sq_entries;
			uint32_t cq_entries;
			int32_t sq_thread_cpu;
			int32_t sq_thread_idle;
			uint32_t wq_fd;
		} setup;
		struct /* DUMP_EVENTFD */ {
			uint32_t eventfd;
			bool async;
		} eventfd;
		struct /* DUMP_REG_FD */ {
			uint32_t reg_fd;
			uint64_t index;
		} reg_fd;
		struct /* DUMP_REG_BUF */ {
			uint64_t addr;
			uint64_t len;
			uint64_t index;
		} reg_buf;
	} desc;
};

#endif
