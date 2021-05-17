// SPDX-License-Identifier: GPL-2.0

#include "io.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../kselftest_harness.h"

FIXTURE(test_pvm)
{
	int wstatus;
	int fd[2];
	pid_t pid;
	pid_t ppid;
	char expected[5];
	char actual[5];
};

FIXTURE_SETUP(test_pvm)
{
	snprintf(self->expected, sizeof(self->expected), "ipfw");
	memset(self->actual, 0, sizeof(self->actual));
	self->ppid = getpid();
	ASSERT_EQ(pipe(self->fd), 0);
	self->pid = fork();
	ASSERT_NE(self->pid, -1) TH_LOG("Cannot fork(): %m\n");
	close(self->fd[!!self->pid]);
};

FIXTURE_TEARDOWN(test_pvm)
{
	int wstatus;

	if (!self->pid)
		exit(0);

	kill(self->pid, SIGKILL);
	waitpid(self->pid, &wstatus, -2);
	close(self->fd[1]);
}

TEST_F(test_pvm, read)
{
	if (!self->pid) {
		const uint8_t baton = 'x';

		memcpy(self->actual, self->expected, sizeof(self->actual));
		ASSERT_EQ(write(self->fd[1], &baton, sizeof(baton)), sizeof(baton));

		pause();
		exit(0);
	} else {
		int err;
		uint8_t baton;

		EXPECT_EQ(read(self->fd[0], &baton, sizeof(baton)), sizeof(baton));
		EXPECT_EQ(baton, 'x');

		err = pvm_read(self->pid, &self->actual, &self->actual, sizeof(self->actual));
		EXPECT_EQ(err, 0)
		TH_LOG("Cannot pvm_read(): %s\n", strerror(-err));

		EXPECT_EQ(memcmp(&self->expected, &self->actual, sizeof(self->actual)), 0);
	}
}

TEST_F(test_pvm, write)
{
	if (getuid())
		SKIP(return, "pvm_write requires CAP_SYS_PTRACE");

	if (!self->pid) {
		const uint8_t baton = 'x';
		int err;

		err = pvm_write(self->ppid, &self->actual, &self->expected, sizeof(self->expected));
		EXPECT_EQ(err, 0) TH_LOG("Cannot pvm_write: %s\n", strerror(-err));

		ASSERT_EQ(write(self->fd[1], &baton, sizeof(baton)), sizeof(baton));

		pause();
		exit(0);

	} else {
		uint8_t baton;

		EXPECT_EQ(read(self->fd[0], &baton, sizeof(baton)), sizeof(baton));
		EXPECT_EQ(baton, 'x');

		EXPECT_EQ(memcmp(&self->expected, &self->actual, sizeof(self->actual)), 0);
	}
}

TEST_HARNESS_MAIN
