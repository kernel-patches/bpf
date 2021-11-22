// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF C/R
 *
 * Tool to use BPF iterators to dump process state.  This currently supports
 * dumping io_uring fd state, by taking process PID and fd number pair, then
 * dumping to stdout the state as binary struct, which can be passed to the
 * tool consuming it, to recreate io_uring.
 */

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <bpf/libbpf.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

#include "bpf_cr.h"
#include "bpf_cr.skel.h"

/* Approx. 4096/40 */
#define MAX_DESC 96
size_t dump_desc_cnt;
size_t reg_fd_cnt;
size_t reg_buf_cnt;
struct io_uring_dump *dump_desc[MAX_DESC];
int fds[MAX_DESC];
struct iovec bufs[MAX_DESC];

static int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

static int sys_io_uring_setup(uint32_t entries, struct io_uring_params *p)
{
	return syscall(__NR_io_uring_setup, entries, p);
}

static int sys_io_uring_register(unsigned int fd, unsigned int opcode,
				 void *arg, unsigned int nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

static const char *type2str[__DUMP_MAX] = {
	[DUMP_SETUP]   = "DUMP_SETUP",
	[DUMP_EVENTFD] = "DUMP_EVENTFD",
	[DUMP_REG_FD]  = "DUMP_REG_FD",
	[DUMP_REG_BUF] = "DUMP_REG_BUF",
};

static int do_dump_parent(struct bpf_cr *skel, int parent_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};
	int ret = 0, buf_it, file_it;
	struct bpf_link *lb, *lf;
	char buf[4096];

	linfo.io_uring.io_uring_fd = parent_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	lb = bpf_program__attach_iter(skel->progs.dump_io_uring_buf, &opts);
	if (!lb) {
		ret = -errno;
		fprintf(stderr, "Failed to attach to io_uring_buf: %m\n");
		return ret;
	}

	lf = bpf_program__attach_iter(skel->progs.dump_io_uring_file, &opts);
	if (!lf) {
		ret = -errno;
		fprintf(stderr, "Failed to attach io_uring_file: %m\n");
		goto end;
	}

	buf_it = bpf_iter_create(bpf_link__fd(lb));
	if (buf_it < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to create io_uring_buf: %m\n");
		goto end_lf;
	}

	file_it = bpf_iter_create(bpf_link__fd(lf));
	if (file_it < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to create io_uring_file: %m\n");
		goto end_buf_it;
	}

	ret = read(file_it, buf, sizeof(buf));
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to read from io_uring_file iterator: %m\n");
		goto end_file_it;
	}

	ret = write(STDOUT_FILENO, buf, ret);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to write to stdout: %m\n");
		goto end_file_it;
	}

	ret = read(buf_it, buf, sizeof(buf));
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to read from io_uring_buf iterator: %m\n");
		goto end_file_it;
	}

	ret = write(STDOUT_FILENO, buf, ret);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to write to stdout: %m\n");
		goto end_file_it;
	}

end_file_it:
	close(file_it);
end_buf_it:
	close(buf_it);
end_lf:
	bpf_link__destroy(lf);
end:
	bpf_link__destroy(lb);
	return ret;
}

static int do_dump(pid_t tpid, int tfd)
{
	int pidfd, ret = 0, buf_it, file_it, task_it;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};
	const struct io_uring_dump *d;
	struct bpf_cr *skel;
	char buf[4096];

	pidfd = sys_pidfd_open(tpid, 0);
	if (pidfd < 0) {
		fprintf(stderr, "Failed to open pidfd for PID %d: %m\n", tpid);
		return 1;
	}

	tfd = sys_pidfd_getfd(pidfd, tfd, 0);
	if (tfd < 0) {
		fprintf(stderr, "Failed to acquire io_uring fd from PID %d: %m\n", tpid);
		ret = 1;
		goto end;
	}

	skel = bpf_cr__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF prog: %m\n");
		ret = 1;
		goto end_tfd;
	}
	skel->rodata->tgid = tpid;

	ret = bpf_cr__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to load BPF prog: %m\n");
		ret = 1;
		goto end_skel;
	}

	skel->links.dump_task = bpf_program__attach_iter(skel->progs.dump_task, NULL);
	if (!skel->links.dump_task) {
		fprintf(stderr, "Failed to attach task_file iterator: %m\n");
		ret = 1;
		goto end_skel;
	}

	task_it = bpf_iter_create(bpf_link__fd(skel->links.dump_task));
	if (task_it < 0) {
		fprintf(stderr, "Failed to create task_file iterator: %m\n");
		ret = 1;
		goto end_skel;
	}

	/* Drive task iterator */
	ret = read(task_it, buf, sizeof(buf));
	close(task_it);
	if (ret < 0) {
		fprintf(stderr, "Failed to read from task_file iterator: %m\n");
		ret = 1;
		goto end_skel;
	}

	linfo.io_uring.io_uring_fd = tfd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	skel->links.dump_io_uring_buf = bpf_program__attach_iter(skel->progs.dump_io_uring_buf,
								 &opts);
	if (!skel->links.dump_io_uring_buf) {
		fprintf(stderr, "Failed to attach io_uring_buf iterator: %m\n");
		ret = 1;
		goto end_skel;
	}
	skel->links.dump_io_uring_file = bpf_program__attach_iter(skel->progs.dump_io_uring_file,
								  &opts);
	if (!skel->links.dump_io_uring_file) {
		fprintf(stderr, "Failed to attach io_uring_file iterator: %m\n");
		ret = 1;
		goto end_skel;
	}

	buf_it = bpf_iter_create(bpf_link__fd(skel->links.dump_io_uring_buf));
	if (buf_it < 0) {
		fprintf(stderr, "Failed to create io_uring_buf iterator: %m\n");
		ret = 1;
		goto end_skel;
	}

	file_it = bpf_iter_create(bpf_link__fd(skel->links.dump_io_uring_file));
	if (file_it < 0) {
		fprintf(stderr, "Failed to create io_uring_file iterator: %m\n");
		ret = 1;
		goto end_buf_it;
	}

	ret = read(file_it, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "Failed to read from io_uring_file iterator: %m\n");
		ret = 1;
		goto end_file_it;
	}

	/* Check if we have to dump its parent as well, first descriptor will
	 * always be DUMP_SETUP, if so, recurse and dump it first.
	 */
	d = (void *)buf;
	if (ret >= sizeof(*d) && d->type == DUMP_SETUP && d->desc.setup.wq_fd) {
		int r;

		r = sys_pidfd_getfd(pidfd, d->desc.setup.wq_fd, 0);
		if (r < 0) {
			fprintf(stderr, "Failed to obtain parent io_uring: %m\n");
			ret = 1;
			goto end_file_it;
		}
		r = do_dump_parent(skel, r);
		if (r < 0) {
			ret = 1;
			goto end_file_it;
		}
	}

	ret = write(STDOUT_FILENO, buf, ret);
	if (ret < 0) {
		fprintf(stderr, "Failed to write to stdout: %m\n");
		ret = 1;
		goto end_file_it;
	}

	ret = read(buf_it, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "Failed to read from io_uring_buf iterator: %m\n");
		ret = 1;
		goto end_file_it;
	}

	ret = write(STDOUT_FILENO, buf, ret);
	if (ret < 0) {
		fprintf(stderr, "Failed to write to stdout: %m\n");
		ret = 1;
		goto end_file_it;
	}

end_file_it:
	close(file_it);
end_buf_it:
	close(buf_it);
end_skel:
	bpf_cr__destroy(skel);
end_tfd:
	close(tfd);
end:
	close(pidfd);
	return ret;
}

static int dump_desc_cmp(const void *a, const void *b)
{
	const struct io_uring_dump *da = a;
	const struct io_uring_dump *db = b;
	uint64_t dafd = da->io_uring_fd;
	uint64_t dbfd = db->io_uring_fd;

	if (dafd < dbfd)
		return -1;
	else if (dafd > dbfd)
		return 1;
	else if (da->type < db->type)
		return -1;
	else if (da->type > db->type)
		return 1;
	return 0;
}

static int do_restore_setup(const struct io_uring_dump *d)
{
	struct io_uring_params p;
	int fd, nfd;

	memset(&p, 0, sizeof(p));

	p.flags = d->desc.setup.flags;
	if (p.flags & IORING_SETUP_SQ_AFF)
		p.sq_thread_cpu = d->desc.setup.sq_thread_cpu;
	if (p.flags & IORING_SETUP_SQPOLL)
		p.sq_thread_idle = d->desc.setup.sq_thread_idle;
	if (p.flags & IORING_SETUP_ATTACH_WQ)
		p.wq_fd = d->desc.setup.wq_fd;
	if (p.flags & IORING_SETUP_CQSIZE)
		p.cq_entries = d->desc.setup.cq_entries;

	fd = sys_io_uring_setup(d->desc.setup.sq_entries, &p);
	if (fd < 0) {
		fprintf(stderr, "Failed to restore DUMP_SETUP desc: %m\n");
		return -errno;
	}

	nfd = dup2(fd, d->io_uring_fd);
	if (nfd < 0) {
		fprintf(stderr, "Failed to dup io_uring_fd: %m\n");
		close(fd);
		return -errno;
	}
	return 0;
}

static int do_restore_eventfd(const struct io_uring_dump *d)
{
	int evfd, ret, opcode;

	/* This would require restoring the eventfd first in CRIU, which would
	 * be found using eventfd_ctx and peeking into struct file guts from
	 * task_file iterator. Here, we just reopen a normal eventfd and
	 * register it. The BPF program does have code which does eventfd
	 * matching to report the fd number.
	 */
	evfd = eventfd(42, 0);
	if (evfd < 0) {
		fprintf(stderr, "Failed to open eventfd: %m\n");
		return -errno;
	}

	opcode = d->desc.eventfd.async ? IORING_REGISTER_EVENTFD_ASYNC : IORING_REGISTER_EVENTFD;
	ret = sys_io_uring_register(d->io_uring_fd, opcode, &evfd, 1);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Failed to register eventfd: %m\n");
		goto end;
	}

	ret = 0;
end:
	close(evfd);
	return ret;
}

static void print_desc(const struct io_uring_dump *d)
{
	printf("%s:\n\tio_uring_fd: %d\n\tend: %s\n",
	       type2str[d->type % __DUMP_MAX], d->io_uring_fd, d->end ? "true" : "false");
	switch (d->type) {
	case DUMP_SETUP:
		printf("\t\tflags: %u\n\t\tsq_entries: %u\n\t\tcq_entries: %u\n"
		       "\t\tsq_thread_cpu: %d\n\t\tsq_thread_idle: %d\n\t\twq_fd: %d\n",
		       d->desc.setup.flags, d->desc.setup.sq_entries,
		       d->desc.setup.cq_entries, d->desc.setup.sq_thread_cpu,
		       d->desc.setup.sq_thread_idle, d->desc.setup.wq_fd);
		break;
	case DUMP_EVENTFD:
		printf("\t\teventfd: %d\n\t\tasync: %s\n",
		       d->desc.eventfd.eventfd,
		       d->desc.eventfd.async ? "true" : "false");
		break;
	case DUMP_REG_FD:
		printf("\t\treg_fd: %d\n\t\tindex: %lu\n",
		       d->desc.reg_fd.reg_fd, d->desc.reg_fd.index);
		break;
	case DUMP_REG_BUF:
		printf("\t\taddr: %lu\n\t\tlen: %lu\n\t\tindex: %lu\n",
		       d->desc.reg_buf.addr, d->desc.reg_buf.len,
		       d->desc.reg_buf.index);
		break;
	default:
		printf("\t\t{Unknown}\n");
		break;
	}
}

static int do_restore_reg_fd(const struct io_uring_dump *d)
{
	int ret;

	/* In CRIU, we restore the fds to be registered before executing the
	 * restore action that registers file descriptors to io_uring.
	 * Our example app would register stdin/stdout/stderr in a sparse
	 * table, so the test case in the commit works.
	 */
	if (reg_fd_cnt == MAX_DESC || d->desc.reg_fd.index >= MAX_DESC) {
		fprintf(stderr, "Exceeded max fds MAX_DESC (%d)\n", MAX_DESC);
		return -EDOM;
	}
	assert(reg_fd_cnt <= d->desc.reg_fd.index);
	/* Fill sparse entries */
	while (reg_fd_cnt < d->desc.reg_fd.index)
		fds[reg_fd_cnt++] = -1;
	fds[reg_fd_cnt++] = d->desc.reg_fd.reg_fd;
	if (d->end) {
		ret = sys_io_uring_register(d->io_uring_fd,
					    IORING_REGISTER_FILES, &fds,
					    reg_fd_cnt);
		if (ret < 0) {
			fprintf(stderr, "Failed to register files: %m\n");
			return -errno;
		}
	}
	return 0;
}

static int do_restore_reg_buf(const struct io_uring_dump *d)
{
	struct iovec *iov;
	int ret;

	/* This step in CRIU for buffers with intact source buffers must be
	 * executed with care. There are primarily three cases (each with corner
	 * cases excluded for brevity):
	 * 1. Source VMA is intact ([ubuf->ubuf, ubuf->ubuf_end) is in VMA, base
	 *    page PFN is same)
	 * 2. Source VMA is split (with multiple pages of ubuf overlaying over
	 *    holes) using munmap(s).
	 * 3. Source VMA is absent (no VMA or full VMA with incorrect PFN).
	 *
	 * PFN remains unique as pages are pinned, hence one with same PFN will
	 * not be recycled to be part of another mapping by page allocator. 2
	 * and 3 required page contents dumping.
	 *
	 * VMA with holes (registered before punching holes) also needs partial
	 * page content dumping to restore without holes, and then punch the
	 * holes. This can be detected when buffer touches two VMAs with holes,
	 * and base page PFN matches (split VMA case).
	 *
	 * All of this is too complicated to demonstrate here, and is done in
	 * userspace, hence left out. Future patches will implement the page
	 * dumping from ubuf iterator part.
	 *
	 * In usual cases we might be able to dump page contents from inside
	 * io_uring that we are dumping, by submitting operations, but we want
	 * to avoid manipulating the ring while dumping, and opcodes we might
	 * need for doing that may be restricted, hence preventing dump.
	 */
	if (reg_buf_cnt == MAX_DESC) {
		fprintf(stderr, "Exceeded max buffers MAX_DESC (%d)\n", MAX_DESC);
		return -EDOM;
	}
	assert(d->desc.reg_buf.index == reg_buf_cnt);
	iov = &bufs[reg_buf_cnt++];
	iov->iov_base = (void *)d->desc.reg_buf.addr;
	iov->iov_len  = d->desc.reg_buf.len;
	if (d->end) {
		if (reg_fd_cnt) {
			ret = sys_io_uring_register(d->io_uring_fd,
						    IORING_REGISTER_FILES, &fds,
						    reg_fd_cnt);
			if (ret < 0) {
				fprintf(stderr, "Failed to register files: %m\n");
				return -errno;
			}
		}

		ret = sys_io_uring_register(d->io_uring_fd,
					    IORING_REGISTER_BUFFERS, &bufs,
					    reg_buf_cnt);
		if (ret < 0) {
			fprintf(stderr, "Failed to register buffers: %m\n");
			return -errno;
		}
	}
	return 0;
}

static int do_restore_action(const struct io_uring_dump *d, bool dry_run)
{
	int ret;

	print_desc(d);

	if (dry_run)
		return 0;

	switch (d->type) {
	case DUMP_SETUP:
		ret = do_restore_setup(d);
		break;
	case DUMP_EVENTFD:
		ret = do_restore_eventfd(d);
		break;
	case DUMP_REG_FD:
		ret = do_restore_reg_fd(d);
		break;
	case DUMP_REG_BUF:
		ret = do_restore_reg_buf(d);
		break;
	default:
		fprintf(stderr, "Unknown dump descriptor\n");
		return -EDOM;
	}
	return ret;
}

static int do_restore(bool dry_run)
{
	struct io_uring_dump dump;
	int ret, prev_fd = 0;

	while ((ret = read(STDIN_FILENO, &dump, sizeof(dump)))) {
		struct io_uring_dump *d;

		if (ret < 0) {
			fprintf(stderr, "Failed to read descriptor: %m\n");
			return 1;
		}

		d = calloc(1, sizeof(*d));
		if (!d) {
			fprintf(stderr, "Failed to allocate dump descriptor: %m\n");
			goto free;
		}

		if (dump_desc_cnt == MAX_DESC) {
			fprintf(stderr, "Cannot process more than MAX_DESC (%d) dump descs\n",
				MAX_DESC);
			goto free;
		}

		*d = dump;
		if (!prev_fd)
			prev_fd = d->io_uring_fd;
		if (prev_fd != d->io_uring_fd) {
			dump_desc[dump_desc_cnt - 1]->end = true;
			prev_fd = d->io_uring_fd;
		}
		dump_desc[dump_desc_cnt++] = d;
		qsort(dump_desc, dump_desc_cnt, sizeof(dump_desc[0]), dump_desc_cmp);
	}
	if (dump_desc_cnt)
		dump_desc[dump_desc_cnt - 1]->end = true;

	for (size_t i = 0; i < dump_desc_cnt; i++) {
		ret = do_restore_action(dump_desc[i], dry_run);
		if (ret < 0) {
			fprintf(stderr, "Failed to execute restore action\n");
			goto free;
		}
	}

	if (!dry_run && dump_desc_cnt)
		sleep(10000);
	else
		puts("Nothing to do, exiting...");
	ret = 0;
free:
	while (dump_desc_cnt--)
		free(dump_desc[dump_desc_cnt]);
	return ret;
}

static int run_app(void)
{
	struct io_uring_params p;
	int r, ret, fd, evfd;

	memset(&p, 0, sizeof(p));
	p.flags |= IORING_SETUP_CQSIZE | IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
	p.sq_thread_idle = 1500;
	p.cq_entries = 4;
	/* Create a test case with parent io_uring, dependent io_uring,
	 * registered files, eventfd (async), buffers, etc.
	 */
	fd = sys_io_uring_setup(2, &p);
	if (fd < 0) {
		fprintf(stderr, "Failed to create io_uring: %m\n");
		return 1;
	}

	r = 1;
	printf("PID: %d, Parent io_uring: %d, ", getpid(), fd);
	p.flags |= IORING_SETUP_ATTACH_WQ;
	p.wq_fd = fd;

	fd = sys_io_uring_setup(2, &p);
	if (fd < 0) {
		fprintf(stderr, "\nFailed to create io_uring: %m\n");
		goto end_wq_fd;
	}

	printf("Dependent io_uring: %d\n", fd);

	evfd = eventfd(42, 0);
	if (evfd < 0) {
		fprintf(stderr, "Failed to create eventfd: %m\n");
		goto end_fd;
	}

	ret = sys_io_uring_register(fd, IORING_REGISTER_EVENTFD_ASYNC, &evfd, 1);
	if (ret < 0) {
		fprintf(stderr, "Failed to register eventfd (async): %m\n");
		goto end_evfd;
	}

	ret = sys_io_uring_register(fd, IORING_REGISTER_FILES, &(int []){0, -1, 1, -1, 2}, 5);
	if (ret < 0) {
		fprintf(stderr, "Failed to register files: %m\n");
		goto end_evfd;
	}

	/* Register dummy buf as well */
	ret = sys_io_uring_register(fd, IORING_REGISTER_BUFFERS, &(struct iovec[]){{}, {&p, sizeof(p)}}, 2);
	if (ret < 0) {
		fprintf(stderr, "Failed to register buffers: %m\n");
		goto end_evfd;
	}

	pause();

	r = 0;
end_evfd:
	close(evfd);
end_fd:
	close(fd);
end_wq_fd:
	close(p.wq_fd);
	return r;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || argc > 4) {
usage:
		fprintf(stderr, "Usage: %s dump PID FD > dump.out\n"
			"\tcat dump.out | %s restore [--dry-run]\n"
			"\t%s app\n", argv[0], argv[0], argv[0]);
		return 1;
	}

	if (libbpf_set_strict_mode(LIBBPF_STRICT_ALL)) {
		fprintf(stderr, "Failed to set libbpf strict mode\n");
		return 1;
	}

	if (!strcmp(argv[1], "app")) {
		return run_app();
	} else if (!strcmp(argv[1], "dump")) {
		if (argc != 4)
			goto usage;
		return do_dump(atoi(argv[2]), atoi(argv[3]));
	} else if (!strcmp(argv[1], "restore")) {
		if (argc < 2 || argc > 3)
			goto usage;
		if (argc == 3 && strcmp(argv[2], "--dry-run"))
			goto usage;
		return do_restore(argc == 3 /* dry_run mode */);
	}
	fprintf(stderr, "Unknown argument\n");
	goto usage;
}
