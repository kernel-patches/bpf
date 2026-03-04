#ifndef __SOCKMAP_HELPERS__
#define __SOCKMAP_HELPERS__

#include "socket_helpers.h"

#define MAX_TEST_NAME 80

#define u32(v) ((u32){(v)})
#define u64(v) ((u64){(v)})

#define __always_unused	__attribute__((__unused__))

#define xbpf_map_delete_elem(fd, key)                                          \
	({                                                                     \
		int __ret = bpf_map_delete_elem((fd), (key));                  \
		if (__ret < 0)                                                 \
			FAIL_ERRNO("map_delete");                              \
		__ret;                                                         \
	})

#define xbpf_map_lookup_elem(fd, key, val)                                     \
	({                                                                     \
		int __ret = bpf_map_lookup_elem((fd), (key), (val));           \
		if (__ret < 0)                                                 \
			FAIL_ERRNO("map_lookup");                              \
		__ret;                                                         \
	})

#define xbpf_map_update_elem(fd, key, val, flags)                              \
	({                                                                     \
		int __ret = bpf_map_update_elem((fd), (key), (val), (flags));  \
		if (__ret < 0)                                                 \
			FAIL_ERRNO("map_update");                              \
		__ret;                                                         \
	})

#define xbpf_prog_attach(prog, target, type, flags)                            \
	({                                                                     \
		int __ret =                                                    \
			bpf_prog_attach((prog), (target), (type), (flags));    \
		if (__ret < 0)                                                 \
			FAIL_ERRNO("prog_attach(" #type ")");                  \
		__ret;                                                         \
	})

#define xbpf_prog_detach2(prog, target, type)                                  \
	({                                                                     \
		int __ret = bpf_prog_detach2((prog), (target), (type));        \
		if (__ret < 0)                                                 \
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

static inline int add_to_sockmap(int mapfd, int fd1, int fd2)
{
	int err;

	err = xbpf_map_update_elem(mapfd, &u32(0), &u64(fd1), BPF_NOEXIST);
	if (err)
		return err;

	return xbpf_map_update_elem(mapfd, &u32(1), &u64(fd2), BPF_NOEXIST);
}

static inline ssize_t recv_timeout_with_splice(int fd, void *buf, size_t len,
					       int flags,
					       unsigned int timeout_sec,
					       bool do_splice)
{
	ssize_t total = 0;
	int pipefd[2];
	int fl;

	int sotype, protocol;
	socklen_t optlen = sizeof(sotype);

	if (!do_splice || (flags & MSG_PEEK) ||
	    getsockopt(fd, SOL_SOCKET, SO_TYPE, &sotype, &optlen) ||
	    sotype != SOCK_STREAM ||
	    getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen) ||
	    protocol != IPPROTO_TCP)
		return recv_timeout(fd, buf, len, flags, timeout_sec);

	if (poll_read(fd, timeout_sec))
		return -1;

	if (pipe(pipefd) < 0)
		return -1;

	/*
	 * tcp_splice_read() only checks sock->file->f_flags for
	 * O_NONBLOCK, ignoring SPLICE_F_NONBLOCK for the socket
	 * side timeout. Set O_NONBLOCK on the fd so the loop won't
	 * block forever when no more data is available.
	 */
	fl = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, fl | O_NONBLOCK);

	/*
	 * Pipe has limited buffer slots (default 16), so a single
	 * splice may not transfer all requested bytes. Loop until
	 * we've read enough or no more data is available.
	 */
	while (total < (ssize_t)len) {
		ssize_t spliced, n;

		spliced = splice(fd, NULL, pipefd[1], NULL, len - total,
				 SPLICE_F_NONBLOCK);
		if (spliced <= 0)
			break;

		n = read(pipefd[0], buf + total, spliced);
		if (n <= 0)
			break;

		total += n;
	}

	fcntl(fd, F_SETFL, fl);

	close(pipefd[0]);
	close(pipefd[1]);

	return total > 0 ? total : -1;
}

#endif // __SOCKMAP_HELPERS__
