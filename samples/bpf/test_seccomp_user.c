// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	char filename[256];
	int prog_fd;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SECCOMP, &obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		exit(EXIT_FAILURE);
	}

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(EXIT_FAILURE);
	}

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_EXTENDED, &prog_fd)) {
		perror("seccomp");
		exit(EXIT_FAILURE);
	}

	close(111);
	assert(errno == EBADF);
	close(999);
	assert(errno == EPERM);

	printf("close syscall successfully filtered\n");
	return 0;
}
