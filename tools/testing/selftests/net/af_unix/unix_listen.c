// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for the state checks in AF_UNIX listen().
 *
 * The central case is a regression test: listen() on a bound socket that
 * is already connected (i.e. not in TCP_CLOSE or TCP_LISTEN state) must
 * fail with EINVAL.  A prior change accidentally let it return success
 * without doing anything, because a helper called in between reset the
 * error code to 0.  The neighbouring checks (unbound, already listening)
 * are tested too so they cannot silently regress the same way.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "kselftest_harness.h"

/* Fill @addr with an abstract-namespace address named @name. */
static socklen_t unix_abstract(struct sockaddr_un *addr, const char *name)
{
	size_t len = strlen(name);

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	/* Leading NUL selects the abstract namespace (no filesystem entry). */
	memcpy(addr->sun_path + 1, name, len);

	return offsetof(struct sockaddr_un, sun_path) + 1 + len;
}

FIXTURE(unix_listen)
{
	int sk;			/* socket under test */
	int server;		/* a listening peer, when a test needs one */
	struct sockaddr_un addr, srv_addr;
	socklen_t addrlen, srv_addrlen;
};

FIXTURE_SETUP(unix_listen)
{
	self->sk = -1;
	self->server = -1;
	self->addrlen = unix_abstract(&self->addr, "unix_listen.sk");
	self->srv_addrlen = unix_abstract(&self->srv_addr, "unix_listen.srv");
}

FIXTURE_TEARDOWN(unix_listen)
{
	if (self->sk >= 0)
		close(self->sk);
	if (self->server >= 0)
		close(self->server);
	/* Abstract addresses are released automatically on close. */
}

/* A bound socket in TCP_CLOSE is the normal, allowed case. */
TEST_F(unix_listen, bound_is_ok)
{
	self->sk = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, self->sk);
	ASSERT_EQ(0, bind(self->sk, (struct sockaddr *)&self->addr,
			  self->addrlen));

	EXPECT_EQ(0, listen(self->sk, 8));
}

/* Listening again on an already-listening socket (TCP_LISTEN) is allowed. */
TEST_F(unix_listen, relisten_is_ok)
{
	self->sk = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, self->sk);
	ASSERT_EQ(0, bind(self->sk, (struct sockaddr *)&self->addr,
			  self->addrlen));
	ASSERT_EQ(0, listen(self->sk, 8));

	EXPECT_EQ(0, listen(self->sk, 16));
}

/* listen() on an unbound socket fails: there is nothing to listen on. */
TEST_F(unix_listen, unbound_is_einval)
{
	int ret;

	self->sk = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, self->sk);

	ret = listen(self->sk, 8);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
}

/*
 * The regression: a bound socket that has already been connected is not in
 * TCP_CLOSE or TCP_LISTEN, so listen() must reject it with EINVAL rather
 * than quietly succeeding.
 */
TEST_F(unix_listen, connected_is_einval)
{
	int ret;

	self->server = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, self->server);
	ASSERT_EQ(0, bind(self->server, (struct sockaddr *)&self->srv_addr,
			  self->srv_addrlen));
	ASSERT_EQ(0, listen(self->server, 8));

	self->sk = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, self->sk);
	/* Bind first so the unbound check does not mask the state check. */
	ASSERT_EQ(0, bind(self->sk, (struct sockaddr *)&self->addr,
			  self->addrlen));
	ASSERT_EQ(0, connect(self->sk, (struct sockaddr *)&self->srv_addr,
			     self->srv_addrlen));

	ret = listen(self->sk, 8);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
}

TEST_HARNESS_MAIN
