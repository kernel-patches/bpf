#ifndef __SOCKMAP_HELPERS__
#define __SOCKMAP_HELPERS__

#include "network_helpers.h"

#define IO_TIMEOUT_SEC 30
#define MAX_STRERR_LEN 256
#define MAX_TEST_NAME 80

#define __always_unused	__attribute__((__unused__))

#define _FAIL(errnum, fmt...)                                                  \
	({                                                                     \
		error_at_line(0, (errnum), __func__, __LINE__, fmt);           \
		CHECK_FAIL(true);                                              \
	})
#define FAIL(fmt...) _FAIL(0, fmt)
#define FAIL_ERRNO(fmt...) _FAIL(errno, fmt)
#define FAIL_LIBBPF(err, msg)                                                  \
	({                                                                     \
		char __buf[MAX_STRERR_LEN];                                    \
		libbpf_strerror((err), __buf, sizeof(__buf));                  \
		FAIL("%s: %s", (msg), __buf);                                  \
	})

/* Wrappers that fail the test on error and report it. */

#define xaccept_nonblock(fd, addr, len)                                        \
	({                                                                     \
		int __ret =                                                    \
			accept_timeout((fd), (addr), (len), IO_TIMEOUT_SEC);   \
		if (__ret == -1)                                               \
			FAIL_ERRNO("accept");                                  \
		__ret;                                                         \
	})

#define xbind(fd, addr, len)                                                   \
	({                                                                     \
		int __ret = bind((fd), (addr), (len));                         \
		if (__ret == -1)                                               \
			FAIL_ERRNO("bind");                                    \
		__ret;                                                         \
	})

#define xclose(fd)                                                             \
	({                                                                     \
		int __ret = close((fd));                                       \
		if (__ret == -1)                                               \
			FAIL_ERRNO("close");                                   \
		__ret;                                                         \
	})

#define xconnect(fd, addr, len)                                                \
	({                                                                     \
		int __ret = connect((fd), (addr), (len));                      \
		if (__ret == -1)                                               \
			FAIL_ERRNO("connect");                                 \
		__ret;                                                         \
	})

#define xgetsockname(fd, addr, len)                                            \
	({                                                                     \
		int __ret = getsockname((fd), (addr), (len));                  \
		if (__ret == -1)                                               \
			FAIL_ERRNO("getsockname");                             \
		__ret;                                                         \
	})

#define xgetsockopt(fd, level, name, val, len)                                 \
	({                                                                     \
		int __ret = getsockopt((fd), (level), (name), (val), (len));   \
		if (__ret == -1)                                               \
			FAIL_ERRNO("getsockopt(" #name ")");                   \
		__ret;                                                         \
	})

#define xlisten(fd, backlog)                                                   \
	({                                                                     \
		int __ret = listen((fd), (backlog));                           \
		if (__ret == -1)                                               \
			FAIL_ERRNO("listen");                                  \
		__ret;                                                         \
	})

#define xsetsockopt(fd, level, name, val, len)                                 \
	({                                                                     \
		int __ret = setsockopt((fd), (level), (name), (val), (len));   \
		if (__ret == -1)                                               \
			FAIL_ERRNO("setsockopt(" #name ")");                   \
		__ret;                                                         \
	})

#define xsend(fd, buf, len, flags)                                             \
	({                                                                     \
		ssize_t __ret = send((fd), (buf), (len), (flags));             \
		if (__ret == -1)                                               \
			FAIL_ERRNO("send");                                    \
		__ret;                                                         \
	})

#define xrecv_nonblock(fd, buf, len, flags)                                    \
	({                                                                     \
		ssize_t __ret = recv_timeout((fd), (buf), (len), (flags),      \
					     IO_TIMEOUT_SEC);                  \
		if (__ret == -1)                                               \
			FAIL_ERRNO("recv");                                    \
		__ret;                                                         \
	})

#define xsocket(family, sotype, flags)                                         \
	({                                                                     \
		int __ret = socket(family, sotype, flags);                     \
		if (__ret == -1)                                               \
			FAIL_ERRNO("socket");                                  \
		__ret;                                                         \
	})

#define xbpf_map_delete_elem(fd, key)                                          \
	({                                                                     \
		int __ret = bpf_map_delete_elem((fd), (key));                  \
		if (__ret < 0)                                               \
			FAIL_ERRNO("map_delete");                              \
		__ret;                                                         \
	})

#define xbpf_map_lookup_elem(fd, key, val)                                     \
	({                                                                     \
		int __ret = bpf_map_lookup_elem((fd), (key), (val));           \
		if (__ret < 0)                                               \
			FAIL_ERRNO("map_lookup");                              \
		__ret;                                                         \
	})

#define xbpf_map_update_elem(fd, key, val, flags)                              \
	({                                                                     \
		int __ret = bpf_map_update_elem((fd), (key), (val), (flags));  \
		if (__ret < 0)                                               \
			FAIL_ERRNO("map_update");                              \
		__ret;                                                         \
	})

#define xbpf_prog_attach(prog, target, type, flags)                            \
	({                                                                     \
		int __ret =                                                    \
			bpf_prog_attach((prog), (target), (type), (flags));    \
		if (__ret < 0)                                               \
			FAIL_ERRNO("prog_attach(" #type ")");                  \
		__ret;                                                         \
	})

#define xbpf_prog_detach2(prog, target, type)                                  \
	({                                                                     \
		int __ret = bpf_prog_detach2((prog), (target), (type));        \
		if (__ret < 0)                                               \
			FAIL_ERRNO("prog_detach2(" #type ")");                 \
		__ret;                                                         \
	})

#define xpthread_create(thread, attr, func, arg)                               \
	({                                                                     \
		int __ret = pthread_create((thread), (attr), (func), (arg));   \
		errno = __ret;                                                 \
		if (__ret)                                                     \
			FAIL_ERRNO("pthread_create");                          \
		__ret;                                                         \
	})

#define xpthread_join(thread, retval)                                          \
	({                                                                     \
		int __ret = pthread_join((thread), (retval));                  \
		errno = __ret;                                                 \
		if (__ret)                                                     \
			FAIL_ERRNO("pthread_join");                            \
		__ret;                                                         \
	})

static inline int poll_connect(int fd, unsigned int timeout_sec)
{
	struct timeval timeout = { .tv_sec = timeout_sec };
	fd_set wfds;
	int r, eval;
	socklen_t esize = sizeof(eval);

	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);

	r = select(fd + 1, NULL, &wfds, NULL, &timeout);
	if (r == 0)
		errno = ETIME;
	if (r != 1)
		return -1;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &eval, &esize) < 0)
		return -1;
	if (eval != 0) {
		errno = eval;
		return -1;
	}

	return 0;
}

static inline int poll_read(int fd, unsigned int timeout_sec)
{
	struct timeval timeout = { .tv_sec = timeout_sec };
	fd_set rfds;
	int r;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	r = select(fd + 1, &rfds, NULL, NULL, &timeout);
	if (r == 0)
		errno = ETIME;

	return r == 1 ? 0 : -1;
}

static inline int accept_timeout(int fd, struct sockaddr *addr, socklen_t *len,
				 unsigned int timeout_sec)
{
	if (poll_read(fd, timeout_sec))
		return -1;

	return accept(fd, addr, len);
}

static inline int recv_timeout(int fd, void *buf, size_t len, int flags,
			       unsigned int timeout_sec)
{
	if (poll_read(fd, timeout_sec))
		return -1;

	return recv(fd, buf, len, flags);
}

static inline void init_addr_loopback(int family, struct sockaddr_storage *ss,
				      socklen_t *len)
{
	make_sockaddr(family, loopback_addr_str(family), 0, ss, len);
}

static inline struct sockaddr *sockaddr(struct sockaddr_storage *ss)
{
	return (struct sockaddr *)ss;
}

static inline int add_to_sockmap(int sock_mapfd, int fd1, int fd2)
{
	u64 value;
	u32 key;
	int err;

	key = 0;
	value = fd1;
	err = xbpf_map_update_elem(sock_mapfd, &key, &value, BPF_NOEXIST);
	if (err)
		return err;

	key = 1;
	value = fd2;
	return xbpf_map_update_elem(sock_mapfd, &key, &value, BPF_NOEXIST);
}

static inline int create_pair(int s, int family, int sotype, int *c, int *p)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int err = 0;

	len = sizeof(addr);
	err = xgetsockname(s, sockaddr(&addr), &len);
	if (err)
		return err;

	*c = xsocket(family, sotype, 0);
	if (*c < 0)
		return errno;
	err = xconnect(*c, sockaddr(&addr), len);
	if (err) {
		err = errno;
		goto close_cli0;
	}

	*p = xaccept_nonblock(s, NULL, NULL);
	if (*p < 0) {
		err = errno;
		goto close_cli0;
	}
	return err;
close_cli0:
	close(*c);
	return err;
}

static inline int create_socket_pairs(int s, int family, int sotype,
				      int *c0, int *c1, int *p0, int *p1)
{
	int err;

	err = create_pair(s, family, sotype, c0, p0);
	if (err)
		return err;

	err = create_pair(s, family, sotype, c1, p1);
	if (err) {
		close(*c0);
		close(*p0);
	}
	return err;
}

struct cb_opts {
	int progfd;
};

static int enable_reuseport(int s, void *opts)
{
	struct cb_opts *co = (struct cb_opts *)opts;
	int progfd = co->progfd;
	int err, one = 1;

	err = xsetsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	if (err)
		return -1;
	err = xsetsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &progfd,
			  sizeof(progfd));
	if (err)
		return -1;

	return 0;
}

static inline int socket_loopback_reuseport(int family, int sotype, int progfd)
{
	struct cb_opts cb_opts = {
		.progfd = progfd,
	};
	struct network_helper_opts opts = {
		.backlog = SOMAXCONN,
	};

	if (progfd >= 0) {
		opts.post_socket_cb = enable_reuseport;
		opts.cb_opts = &cb_opts;
	}

	return start_server_str(family, sotype, loopback_addr_str(family), 0, &opts);
}

static inline int socket_loopback(int family, int sotype)
{
	return socket_loopback_reuseport(family, sotype, -1);
}


#endif // __SOCKMAP_HELPERS__
