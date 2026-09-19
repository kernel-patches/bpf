// SPDX-License-Identifier: GPL-2.0
/*
 * TLS Hardware Offload Two-Node Test
 *
 * Tests kTLS hardware offload between two physical nodes using
 * hardcoded keys. Supports TLS 1.2/1.3, AES-GCM-128/256, and rekey.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/tls.h>

#define TLS_RECORD_TYPE_HANDSHAKE		22
#define TLS_HANDSHAKE_KEY_UPDATE		0x18

/* Large enough for a TLS 1.3 KeyUpdate handshake record's plaintext. */
#define MIN_BUF_SIZE   16

/* Initial key material */
static struct tls12_crypto_info_aes_gcm_128 tls_info_key0_128 = {
	.info = {
		.version = TLS_1_3_VERSION,
		.cipher_type = TLS_CIPHER_AES_GCM_128,
	},
	.iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	.key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
	.salt = { 0x01, 0x02, 0x03, 0x04 },
	.rec_seq = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static struct tls12_crypto_info_aes_gcm_256 tls_info_key0_256 = {
	.info = {
		.version = TLS_1_3_VERSION,
		.cipher_type = TLS_CIPHER_AES_GCM_256,
	},
	.iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	.key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 },
	.salt = { 0x01, 0x02, 0x03, 0x04 },
	.rec_seq = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static int num_rekeys;
static int num_iterations = 100;
static int cipher_type = TLS_CIPHER_AES_GCM_128;
static int tls_version = TLS_1_3_VERSION;
static int server_port = 4433;
static char *server_ip;
/* Address family to force: AF_UNSPEC (any), AF_INET (-4), AF_INET6 (-6). */
static int force_family = AF_UNSPEC;

static int send_size = 16384;
static int random_size_max;
/* Burst mode: sender keeps pushing records without reading from the peer;
 * receiver drains without echoing back. Only the client initiates rekey.
 */
static int burst_mode;
static int zc_rx;

/* XOR each byte with the generation so both endpoints derive the
 * same per-generation key without a real KDF. Generation 0 leaves
 * the base key unchanged.
 */
static void derive_key_fields(unsigned char *key, int key_size,
			      unsigned char *iv, int iv_size,
			      unsigned char *salt, int salt_size,
			      unsigned char *rec_seq, int rec_seq_size,
			      int generation)
{
	int i;

	for (i = 0; i < key_size; i++)
		key[i] ^= generation;
	for (i = 0; i < iv_size; i++)
		iv[i] ^= generation;
	for (i = 0; i < salt_size; i++)
		salt[i] ^= generation;
	memset(rec_seq, 0, rec_seq_size);
}

static void derive_key_128(struct tls12_crypto_info_aes_gcm_128 *key,
			   int generation)
{
	memcpy(key, &tls_info_key0_128, sizeof(*key));
	key->info.version = tls_version;
	derive_key_fields(key->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE,
			  key->iv, TLS_CIPHER_AES_GCM_128_IV_SIZE,
			  key->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			  key->rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE,
			  generation);
}

static void derive_key_256(struct tls12_crypto_info_aes_gcm_256 *key,
			   int generation)
{
	memcpy(key, &tls_info_key0_256, sizeof(*key));
	key->info.version = tls_version;
	derive_key_fields(key->key, TLS_CIPHER_AES_GCM_256_KEY_SIZE,
			  key->iv, TLS_CIPHER_AES_GCM_256_IV_SIZE,
			  key->salt, TLS_CIPHER_AES_GCM_256_SALT_SIZE,
			  key->rec_seq, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE,
			  generation);
}

static const char *cipher_name(int cipher)
{
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128: return "AES-GCM-128";
	case TLS_CIPHER_AES_GCM_256: return "AES-GCM-256";
	default: return "unknown";
	}
}

static const char *version_name(int version)
{
	switch (version) {
	case TLS_1_2_VERSION: return "TLS 1.2";
	case TLS_1_3_VERSION: return "TLS 1.3";
	default: return "unknown";
	}
}

static int setup_tls_ulp(int fd)
{
	int ret;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"));
	if (ret < 0) {
		printf("SETUP ERROR: TCP_ULP failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Echo (non-burst) mode drives both directions from a single thread: the
 * client pushes a whole payload with one blocking send() and only reads the
 * echo afterwards, while the server blocks in send() mid-echo. If a payload
 * exceeds the peer's receive window the two sides deadlock - client stuck in
 * send(), server stuck echoing, neither draining the other. Size the socket
 * buffers so a full payload always fits in the peer's window (the forward
 * send() then completes without needing the peer to read concurrently); the
 * send/recv timeouts armed by set_io_timeouts() turn any residual stall into a
 * loud EAGAIN instead of a hang.
 */
static void configure_echo_socket(int fd, int payload)
{
	int want = payload;

	if (want < MIN_BUF_SIZE)
		want = MIN_BUF_SIZE;

	/* SO_*BUFFORCE bypasses the rmem_max/wmem_max sysctl caps (needs
	 * CAP_NET_ADMIN); fall back to the best-effort, cap-limited option
	 * when unprivileged - the timeouts below still turn any resulting
	 * stall into a loud failure rather than a hang.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &want, sizeof(want)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want));
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &want, sizeof(want)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &want, sizeof(want));
}

/* Arm send/recv timeouts so any unexpected stall fails loudly with EAGAIN
 * instead of hanging until the harness SIGKILLs us. Wanted in both echo and
 * burst modes - burst mode has no other stall guard.
 */
static void set_io_timeouts(int fd)
{
	struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Send the whole buffer, looping over short counts. A blocking SOCK_STREAM
 * send() may return fewer bytes than requested (e.g. when SO_SNDTIMEO fires
 * after partial progress) without setting errno, so a short count is not an
 * error - only a negative return is. Looping also sends each iteration as one
 * uninterrupted run of bytes, which the peer's userspace reassembly in burst
 * mode counts on to keep iterations aligned.
 */
static int send_all(int fd, const char *buf, ssize_t len)
{
	ssize_t sent = 0;
	ssize_t ret;

	while (sent < len) {
		ret = send(fd, buf + sent, len - sent, 0);
		if (ret < 0) {
			printf("FAIL: send failed: %s\n", strerror(errno));
			return -1;
		}
		sent += ret;
	}
	return 0;
}

static int set_zc_rx(int fd)
{
	int val = 1;

	if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &val,
		       sizeof(val)) < 0) {
		printf("SETUP ERROR: TLS_RX_EXPECT_NO_PAD failed: %s\n",
		       strerror(errno));
		return -1;
	}
	return 0;
}

/* Send a TLS 1.3 KeyUpdate handshake record. The kernel only
 * inspects the HandshakeType byte to detect KeyUpdate, so don't
 * bother with the 3-byte length or request_update fields.
 */
static int send_tls_key_update(int fd)
{
	char cmsg_buf[CMSG_SPACE(sizeof(unsigned char))];
	unsigned char key_update_msg = TLS_HANDSHAKE_KEY_UPDATE;
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	struct iovec iov;

	iov.iov_base = &key_update_msg;
	iov.iov_len = sizeof(key_update_msg);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_TLS;
	cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned char));
	*CMSG_DATA(cmsg) = TLS_RECORD_TYPE_HANDSHAKE;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(fd, &msg, 0) < 0) {
		printf("sendmsg KeyUpdate failed: %s\n", strerror(errno));
		return -1;
	}

	printf("Sent TLS KeyUpdate handshake message\n");
	return 0;
}

static int recv_tls_message(int fd, char *buf, size_t buflen, int *record_type,
			    int flags)
{
	char cmsg_buf[CMSG_SPACE(sizeof(unsigned char))];
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	struct iovec iov;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = buflen;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

	ret = recvmsg(fd, &msg, flags);
	if (ret <= 0)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_level == SOL_TLS &&
	    cmsg->cmsg_type == TLS_GET_RECORD_TYPE)
		*record_type = *((unsigned char *)CMSG_DATA(cmsg));

	return ret;
}

/* Confirm a handshake record starting with HandshakeType KeyUpdate. */
static int check_keyupdate(const char *buf, int len, int record_type)
{
	if (record_type != TLS_RECORD_TYPE_HANDSHAKE) {
		printf("Expected handshake record (0x%02x), got 0x%02x\n",
		       TLS_RECORD_TYPE_HANDSHAKE, record_type);
		return -1;
	}
	if (len < 1 || (unsigned char)buf[0] != TLS_HANDSHAKE_KEY_UPDATE) {
		printf("Expected KeyUpdate (0x%02x), got 0x%02x\n",
		       TLS_HANDSHAKE_KEY_UPDATE,
		       len ? (unsigned char)buf[0] : 0);
		return -1;
	}
	printf("Received TLS KeyUpdate\n");
	return 0;
}

static int recv_tls_keyupdate(int fd)
{
	char buf[MIN_BUF_SIZE];
	int record_type = 0;
	int ret;

	ret = recv_tls_message(fd, buf, sizeof(buf), &record_type, 0);
	if (ret < 0) {
		printf("recv_tls_message failed: %s\n", strerror(errno));
		return -1;
	}

	return check_keyupdate(buf, ret, record_type);
}

static int check_ekeyexpired(int fd)
{
	char buf[MIN_BUF_SIZE];
	int ret;

	ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (ret == -1 && errno == EKEYEXPIRED) {
		printf("recv() returned EKEYEXPIRED as expected\n");
		return 0;
	}
	if (ret > 0) {
		printf("FAIL: recv() returned %d bytes, expected EKEYEXPIRED\n",
		       ret);
		return -1;
	}
	if (ret == 0) {
		printf("FAIL: connection closed during rekey\n");
		return -1;
	}
	printf("FAIL: recv() returned unexpected error: %s\n",
	       strerror(errno));
	return -1;
}

static int do_tls_rekey(int fd, int direction, int generation, int cipher)
{
	const char *dir = direction == TLS_TX ? "TX" : "RX";
	int ret;

	printf("%s TLS_%s %s gen %d...\n",
	       generation ? "Rekeying" : "Installing",
	       dir, cipher_name(cipher), generation);

	if (cipher == TLS_CIPHER_AES_GCM_256) {
		struct tls12_crypto_info_aes_gcm_256 key;

		derive_key_256(&key, generation);
		ret = setsockopt(fd, SOL_TLS, direction, &key, sizeof(key));
	} else {
		struct tls12_crypto_info_aes_gcm_128 key;

		derive_key_128(&key, generation);
		ret = setsockopt(fd, SOL_TLS, direction, &key, sizeof(key));
	}

	if (ret < 0) {
		printf("%sTLS_%s %s gen %d failed: %s\n",
		       generation ? "" : "SETUP ERROR: ", dir,
		       cipher_name(cipher), generation, strerror(errno));
		return -1;
	}
	printf("TLS_%s %s gen %d installed\n",
	       dir, cipher_name(cipher), generation);
	return 0;
}

/* Open a TCP connection to server_ip:server_port, switch to the TLS
 * ULP, and install initial generation-0 TX/RX keys. Works over IPv4 or
 * IPv6: getaddrinfo() resolves server_ip (honouring any -4/-6 forced
 * family and %zone scope IDs in link-local addresses). Returns the fd on
 * success, -1 on error (with the fd already closed).
 */
static int client_connect_tls(void)
{
	struct addrinfo hints = {0}, *res, *rp;
	char port_str[16];
	int csk = -1;
	int ret;

	hints.ai_family = force_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	snprintf(port_str, sizeof(port_str), "%d", server_port);

	ret = getaddrinfo(server_ip, port_str, &hints, &res);
	if (ret) {
		printf("SETUP ERROR: getaddrinfo(%s): %s\n", server_ip,
		       gai_strerror(ret));
		return -1;
	}

	printf("Connecting to %s:%d...\n", server_ip, server_port);
	for (rp = res; rp; rp = rp->ai_next) {
		csk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (csk < 0)
			continue;
		if (connect(csk, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(csk);
		csk = -1;
	}
	freeaddrinfo(res);

	if (csk < 0) {
		printf("SETUP ERROR: connect to %s:%d failed: %s\n",
		       server_ip, server_port, strerror(errno));
		return -1;
	}
	printf("Connected!\n");

	if (setup_tls_ulp(csk) < 0)
		goto err;

	if (do_tls_rekey(csk, TLS_TX, 0, cipher_type) < 0 ||
	    do_tls_rekey(csk, TLS_RX, 0, cipher_type) < 0)
		goto err;

	set_io_timeouts(csk);
	if (!burst_mode)
		configure_echo_socket(csk, random_size_max > 0 ?
					    random_size_max : send_size);

	return csk;
err:
	close(csk);
	return -1;
}

/* Drain `len` echoed bytes from the server and verify they match the
 * payload we just sent.
 */
static int client_recv_echo(int fd, const char *sent, char *echo_buf,
			    ssize_t len)
{
	ssize_t total = 0;
	ssize_t n;

	while (total < len) {
		n = recv(fd, echo_buf + total, len - total, 0);
		if (n < 0) {
			printf("FAIL: Echo recv failed: %s\n", strerror(errno));
			return -1;
		}
		if (n == 0) {
			printf("FAIL: Connection closed during echo\n");
			return -1;
		}
		total += n;
	}

	if (memcmp(sent, echo_buf, len) != 0) {
		printf("FAIL: Echo data mismatch!\n");
		return -1;
	}
	printf("Received echo %zd bytes (ok)\n", total);
	return 0;
}

/* Client side of a rekey: send KeyUpdate and rotate TX. In echo mode
 * also wait for the peer's KeyUpdate and rotate RX.
 */
static int client_rekey(int fd, int generation)
{
	if (send_tls_key_update(fd) < 0) {
		printf("FAIL: send KeyUpdate\n");
		return -1;
	}

	if (do_tls_rekey(fd, TLS_TX, generation, cipher_type) < 0)
		return -1;

	if (burst_mode)
		return 0;

	if (recv_tls_keyupdate(fd) < 0) {
		printf("FAIL: recv KeyUpdate from server\n");
		return -1;
	}

	if (check_ekeyexpired(fd) < 0)
		return -1;

	return do_tls_rekey(fd, TLS_RX, generation, cipher_type);
}

static int do_client(void)
{
	char *buf = NULL, *echo_buf = NULL;
	int max_size, rekey_interval;
	int csk = -1, i;
	int test_result = -1;
	int current_gen = 0;
	int next_rekey_at;
	ssize_t n;

	max_size = random_size_max > 0 ? random_size_max : send_size;
	if (max_size < MIN_BUF_SIZE)
		max_size = MIN_BUF_SIZE;
	buf = malloc(max_size);
	if (!burst_mode)
		echo_buf = malloc(max_size);
	if (!buf || (!burst_mode && !echo_buf)) {
		printf("SETUP ERROR: failed to allocate buffers\n");
		goto out;
	}

	csk = client_connect_tls();
	if (csk < 0)
		goto out;

	if (num_rekeys)
		printf("TLS %s setup complete. Will perform %d rekey(s).\n",
		       cipher_name(cipher_type), num_rekeys);
	else
		printf("TLS setup complete.\n");

	if (random_size_max > 0)
		printf("Sending %d messages of random size (1..%d bytes)...\n",
		       num_iterations, random_size_max);
	else
		printf("Sending %d messages of %d bytes...\n",
		       num_iterations, send_size);

	rekey_interval = num_iterations / (num_rekeys + 1);
	next_rekey_at = rekey_interval;

	for (i = 1; i <= num_iterations; i++) {
		int this_size;

		if (random_size_max > 0)
			this_size = (rand() % random_size_max) + 1;
		else
			this_size = send_size;

		/* In burst mode, use a per-iteration fill pattern so the
		 * receiver can detect any plaintext corruption without a
		 * round-trip echo.
		 */
		if (burst_mode) {
			memset(buf, i & 0xFF, this_size);
		} else {
			int j;

			for (j = 0; j < this_size; j++)
				buf[j] = rand() & 0xFF;
		}

		if (send_all(csk, buf, this_size) < 0)
			goto out;
		n = this_size;

		if (!burst_mode) {
			printf("Sent %zd bytes (iteration %d)\n", n, i);
			if (client_recv_echo(csk, buf, echo_buf, n) < 0)
				goto out;
		}

		/* Rekey at intervals. In echo mode this is a full bidirectional
		 * exchange; in burst mode the client only rotates its TX key
		 * and sends KeyUpdate - the peer is expected to follow.
		 */
		if (num_rekeys && current_gen < num_rekeys &&
		    i == next_rekey_at) {
			current_gen++;
			printf("\n=== Client Rekey gen %d ===\n", current_gen);

			if (client_rekey(csk, current_gen) < 0)
				goto out;

			next_rekey_at += rekey_interval;
			printf("=== Client Rekey gen %d Complete ===\n\n",
			       current_gen);
		}
	}

	test_result = 0;
out:
	if (num_rekeys)
		printf("Rekeys completed: %d/%d\n", current_gen, num_rekeys);
	if (csk >= 0)
		close(csk);
	free(buf);
	free(echo_buf);
	return test_result;
}

/* Bind/listen on server_port, accept one client, switch to the TLS ULP
 * and install initial generation-0 keys (plus zc_rx if requested).
 * Returns the connected fd on success and writes the listener fd to
 * *lsk_out so the caller can close it. Returns -1 on error, with all
 * intermediate fds already closed and *lsk_out left at -1.
 */
static int server_accept_tls(int *lsk_out)
{
	struct addrinfo hints = {0}, *res, *rp;
	int lsk = -1, csk, one = 1;
	char port_str[16];
	int ret;

	*lsk_out = -1;

	/* AI_PASSIVE gives a wildcard bind address for the chosen family
	 * (0.0.0.0 / ::). The family is forced by -4/-6; when unspecified,
	 * bind the first entry that works.
	 */
	hints.ai_family = force_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	snprintf(port_str, sizeof(port_str), "%d", server_port);

	ret = getaddrinfo(NULL, port_str, &hints, &res);
	if (ret) {
		printf("SETUP ERROR: getaddrinfo(port %d): %s\n", server_port,
		       gai_strerror(ret));
		return -1;
	}

	for (rp = res; rp; rp = rp->ai_next) {
		lsk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (lsk < 0)
			continue;
		setsockopt(lsk, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (bind(lsk, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(lsk);
		lsk = -1;
	}
	freeaddrinfo(res);

	if (lsk < 0) {
		printf("SETUP ERROR: failed to bind port %d: %s\n",
		       server_port, strerror(errno));
		return -1;
	}

	if (listen(lsk, 1) < 0) {
		printf("SETUP ERROR: listen failed: %s\n", strerror(errno));
		close(lsk);
		return -1;
	}

	printf("Server listening on port %d\n", server_port);
	printf("Waiting for client connection...\n");

	/* Bound accept() so a client that never connects (a deploy or connect
	 * failure on the peer) does not block the server forever and leak the
	 * process past the harness timeout. accept() honours SO_RCVTIMEO on the
	 * listening socket; the client connects right after wait_port_listen(),
	 * so 30s is generous.
	 */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };

		setsockopt(lsk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	csk = accept(lsk, (struct sockaddr *)NULL, (socklen_t *)NULL);
	if (csk < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			printf("SETUP ERROR: accept timed out; client never connected\n");
		else
			printf("SETUP ERROR: accept failed: %s\n", strerror(errno));
		close(lsk);
		return -1;
	}
	printf("Client connected!\n");

	if (setup_tls_ulp(csk) < 0)
		goto err;

	if (do_tls_rekey(csk, TLS_TX, 0, cipher_type) < 0 ||
	    do_tls_rekey(csk, TLS_RX, 0, cipher_type) < 0)
		goto err;

	if (zc_rx && set_zc_rx(csk) < 0)
		goto err;

	set_io_timeouts(csk);
	if (!burst_mode)
		configure_echo_socket(csk, random_size_max > 0 ?
					    random_size_max : send_size);

	*lsk_out = lsk;
	return csk;
err:
	close(csk);
	close(lsk);
	return -1;
}

/* Server side of a rekey: confirm recv() reports EKEYEXPIRED, then rotate RX.
 * In echo mode also send a KeyUpdate back and rotate TX.
 */
static int server_rekey(int fd, int generation)
{
	if (check_ekeyexpired(fd) < 0)
		return -1;

	if (do_tls_rekey(fd, TLS_RX, generation, cipher_type) < 0)
		return -1;

	if (burst_mode)
		return 0;

	if (send_tls_key_update(fd) < 0) {
		printf("FAIL: send KeyUpdate\n");
		return -1;
	}

	return do_tls_rekey(fd, TLS_TX, generation, cipher_type);
}

/* Burst mode: verify one reassembled iteration of send_size plaintext bytes,
 * each filled with (send_iter & 0xff). Catches decrypt-succeeded-but-
 * plaintext-corrupt bugs that AEAD counters alone would miss.
 */
static int server_verify_burst(const char *buf, int send_iter)
{
	unsigned char expect = send_iter & 0xFF;
	int j;

	for (j = 0; j < send_size; j++) {
		if ((unsigned char)buf[j] != expect) {
			printf("FAIL: data mismatch iter %d off %d: exp 0x%02x got 0x%02x\n",
			       send_iter, j, expect, (unsigned char)buf[j]);
			return -1;
		}
	}
	return 0;
}

static int do_server(void)
{
	int lsk = -1, csk = -1;
	ssize_t n, total = 0;
	int test_result = -1;
	int current_gen = 0;
	int recv_count = 0;
	int send_iter = 1;
	char *buf = NULL;
	int record_type = 0;
	int filled = 0;
	int buf_size;

	buf_size = send_size;
	if (buf_size < MIN_BUF_SIZE)
		buf_size = MIN_BUF_SIZE;
	buf = malloc(buf_size);
	if (!buf) {
		printf("SETUP ERROR: failed to allocate buffer\n");
		goto out;
	}

	csk = server_accept_tls(&lsk);
	if (csk < 0)
		goto out;

	printf("TLS %s setup complete. Receiving...\n",
	       cipher_name(cipher_type));

	/* Burst mode: reassemble one iteration (send_size bytes) in userspace
	 * from however much each recv returns, rather than demanding a full
	 * send_size batch in a single MSG_WAITALL call. A blocking MSG_WAITALL
	 * of send_size deadlocks when the client's last record of an iteration
	 * is still partly in flight as its socket buffer fills: the server
	 * waits for bytes the client cannot send until the server reads, and
	 * the server will not read until it has the whole batch. Draining
	 * whatever is available keeps the receive window open and breaks that
	 * cycle. kTLS never splits a record and returns data and control
	 * (KeyUpdate) records separately, and each iteration is a whole number
	 * of records, so capping each recv at the iteration boundary keeps the
	 * reassembly aligned and delivers a KeyUpdate on its own.
	 */

	/* Main receive loop */
	while (1) {
		char *dst = burst_mode ? buf + filled : buf;
		size_t want = burst_mode ? (size_t)(send_size - filled)
					 : (size_t)buf_size;

		n = recv_tls_message(csk, dst, want, &record_type, 0);
		if (n == 0) {
			/* A clean close on an iteration boundary is success;
			 * one with a partial iteration still buffered means the
			 * peer dropped the tail - the truncated-data case this
			 * test exists to catch, so fail loudly.
			 */
			if (burst_mode && filled) {
				printf("FAIL: closed mid-iteration (%d/%d bytes buffered)\n",
				       filled, send_size);
				goto out;
			}
			printf("Connection closed by client\n");
			break;
		}
		if (n < 0) {
			printf("FAIL: recv failed: %s\n", strerror(errno));
			goto out;
		}

		/* Handle KeyUpdate. In echo mode the server mirrors the
		 * rekey back to the peer; in burst mode it only rotates its
		 * RX key and keeps draining. A KeyUpdate always lands on a
		 * send_size boundary, so no partial iteration must be buffered
		 * when one arrives.
		 */
		if (record_type == TLS_RECORD_TYPE_HANDSHAKE) {
			/* Check for a partial iteration before validating the
			 * KeyUpdate, so a mid-iteration arrival fails with this
			 * message rather than a misleading KeyUpdate-OK line.
			 */
			if (burst_mode && filled) {
				printf("FAIL: KeyUpdate mid-iteration (%d/%d bytes buffered)\n",
				       filled, send_size);
				goto out;
			}
			if (check_keyupdate(dst, n, record_type) < 0)
				goto out;
			current_gen++;
			printf("\n=== Server Rekey gen %d ===\n", current_gen);

			if (server_rekey(csk, current_gen) < 0)
				goto out;

			printf("=== Server Rekey gen %d Complete ===\n\n",
			       current_gen);
			continue;
		}

		total += n;

		if (burst_mode) {
			filled += n;
			if (filled < send_size)
				continue;
			if (server_verify_burst(buf, send_iter) < 0)
				goto out;
			recv_count++;
			send_iter++;
			filled = 0;
			continue;
		}

		recv_count++;
		printf("Received %zd bytes (total: %zd, count: %d)\n",
		       n, total, recv_count);

		if (send_all(csk, buf, n) < 0)
			goto out;
		printf("Echoed %zd bytes back to client\n", n);
	}

	test_result = 0;
out:
	printf("Connection closed. Total received: %zd bytes\n", total);
	if (num_rekeys)
		printf("Rekeys completed: %d\n", current_gen);

	if (csk >= 0)
		close(csk);
	if (lsk >= 0)
		close(lsk);
	free(buf);
	return test_result;
}

static int parse_int_arg(const char *arg, int min, int max,
			 const char *name, int *out)
{
	char *endp;
	long val;

	errno = 0;
	val = strtol(arg, &endp, 10);
	if (errno || endp == arg || *endp != '\0' || val < min || val > max) {
		if (max == INT_MAX)
			printf("ERROR: Invalid %s '%s'. Must be >= %d.\n",
			       name, arg, min);
		else
			printf("ERROR: Invalid %s '%s'. Must be %d..%d.\n",
			       name, arg, min, max);
		return -1;
	}
	*out = (int)val;
	return 0;
}

static int parse_cipher_option(const char *arg)
{
	if (strcmp(arg, "128") == 0) {
		cipher_type = TLS_CIPHER_AES_GCM_128;
		return 0;
	} else if (strcmp(arg, "256") == 0) {
		cipher_type = TLS_CIPHER_AES_GCM_256;
		return 0;
	}
	printf("ERROR: Invalid cipher '%s'. Must be 128 or 256.\n", arg);
	return -1;
}

static int parse_version_option(const char *arg)
{
	if (strcmp(arg, "1.2") == 0) {
		tls_version = TLS_1_2_VERSION;
		return 0;
	} else if (strcmp(arg, "1.3") == 0) {
		tls_version = TLS_1_3_VERSION;
		return 0;
	}
	printf("ERROR: Invalid TLS version '%s'. Must be 1.2 or 1.3.\n", arg);
	return -1;
}

static void print_usage(const char *prog)
{
	printf("TLS Hardware Offload Two-Node Test\n\n");
	printf("Usage:\n");
	printf("  %s server [OPTIONS]\n", prog);
	printf("  %s client -s <ip> [OPTIONS]\n", prog);
	printf("\nOptions:\n");
	printf("  -s <ip>       Server IP address, v4 or v6 (client, required)\n");
	printf("  -p <port>     Server port (default: 4433)\n");
	printf("  -4            Force IPv4 (default: auto/either)\n");
	printf("  -6            Force IPv6 (default: auto/either)\n");
	printf("  -b <size>     Send buffer size in bytes (default: 16384)\n");
	printf("  -r <max>      Use random send buffer sizes (1..<max>)\n");
	printf("  -v <version>  TLS version: 1.2 or 1.3 (default: 1.3)\n");
	printf("  -c <cipher>   Cipher: 128 or 256 (default: 128)\n");
	printf("  -n <N>        Number of send/echo iterations (default: 100)\n");
	printf("  -k <N>        Perform N rekeys (client only, TLS 1.3; N < iterations)\n");
	printf("  -B            Burst mode: client sends continuously without echo;\n");
	printf("                server drains and handles KeyUpdate without responding.\n");
	printf("  -Z            Set TLS_RX_EXPECT_NO_PAD on the server: TLS 1.3\n");
	printf("                opt-in to the zero-copy RX fast path. Not needed\n");
	printf("                for TLS 1.2 (always eligible). Server only.\n");
	printf("  -h            Show this help message\n");
	printf("\nExample:\n");
	printf("  Node A: %s server\n", prog);
	printf("  Node B: %s client -s 192.168.20.2\n", prog);
	printf("\nRekey Example (3 rekeys, TLS 1.3 only):\n");
	printf("  Node A: %s server\n", prog);
	printf("  Node B: %s client -s 192.168.20.2 -k 3\n", prog);
	printf("\nBurst Mode Example (client stresses TX rekey under load):\n");
	printf("  Node A: %s server -B\n", prog);
	printf("  Node B: %s client -s 192.168.20.2 -B -k 3\n", prog);
	printf("\nIPv6 Example:\n");
	printf("  Node A: %s server -6\n", prog);
	printf("  Node B: %s client -6 -s fd00::2\n", prog);
}

int main(int argc, char *argv[])
{
	int send_size_set = 0;
	int is_server;
	int opt;

	/* When the peer aborts a TLS connection (e.g. tls_err_abort() on a
	 * failed decrypt), a send() here would raise SIGPIPE and kill us by
	 * signal, so the harness sees only a bare non-zero exit with no
	 * "FAIL:" line. Ignore it and let send()/sendmsg() return EPIPE, which
	 * send_all()/send_tls_key_update() report.
	 */
	signal(SIGPIPE, SIG_IGN);

	if (argc < 2 ||
	    (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		print_usage(argv[0]);
		return 1;
	}
	is_server = !strcmp(argv[1], "server");

	optind = 2; /* skip subcommand */
	while ((opt = getopt(argc, argv, "s:p:b:r:c:v:k:n:BZ46h")) != -1) {
		switch (opt) {
		case 's':
			server_ip = optarg;
			break;
		case '4':
			if (force_family == AF_INET6) {
				printf("ERROR: -4 and -6 are mutually exclusive\n");
				return 1;
			}
			force_family = AF_INET;
			break;
		case '6':
			if (force_family == AF_INET) {
				printf("ERROR: -4 and -6 are mutually exclusive\n");
				return 1;
			}
			force_family = AF_INET6;
			break;
		case 'B':
			burst_mode = 1;
			break;
		case 'Z':
			zc_rx = 1;
			break;
		case 'p':
			if (parse_int_arg(optarg, 1, 65535, "port",
					  &server_port) < 0)
				return 1;
			break;
		case 'b':
			if (parse_int_arg(optarg, 1, INT_MAX, "buffer size",
					  &send_size) < 0)
				return 1;
			send_size_set = 1;
			break;
		case 'r':
			if (parse_int_arg(optarg, 1, INT_MAX, "random size",
					  &random_size_max) < 0)
				return 1;
			break;
		case 'c':
			if (parse_cipher_option(optarg) < 0)
				return 1;
			break;
		case 'v':
			if (parse_version_option(optarg) < 0)
				return 1;
			break;
		case 'k':
			if (parse_int_arg(optarg, 1, 255, "rekey count",
					  &num_rekeys) < 0)
				return 1;
			break;
		case 'n':
			if (parse_int_arg(optarg, 1, INT_MAX, "iteration count",
					  &num_iterations) < 0)
				return 1;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (send_size_set && random_size_max > 0) {
		printf("ERROR: -b and -r are mutually exclusive\n");
		return 1;
	}

	if (zc_rx && tls_version != TLS_1_3_VERSION) {
		printf("ERROR: -Z (TLS_RX_EXPECT_NO_PAD) requires TLS 1.3\n");
		return 1;
	}

	if (burst_mode && random_size_max > 0) {
		printf("ERROR: -B and -r are mutually exclusive\n");
		return 1;
	}

	if (burst_mode && send_size < MIN_BUF_SIZE) {
		printf("ERROR: -b must be >= %d in burst mode (-B)\n",
		       MIN_BUF_SIZE);
		return 1;
	}

	if (is_server) {
		if (server_ip) {
			printf("warning: -s is ignored in server mode\n");
			server_ip = NULL;
		}
		if (random_size_max > 0) {
			printf("warning: -r is ignored in server mode\n");
			random_size_max = 0;
		}
		if (num_rekeys) {
			printf("warning: -k is ignored in server mode\n");
			num_rekeys = 0;
		}
	} else {
		if (!server_ip) {
			printf("ERROR: Client requires -s <ip> option\n");
			return 1;
		}
		if (tls_version == TLS_1_2_VERSION && num_rekeys) {
			printf("ERROR: TLS 1.2 does not support rekey\n");
			return 1;
		}
		if (num_rekeys >= num_iterations) {
			printf("ERROR: num_rekeys (%d) must be < num_iterations (%d)\n",
			       num_rekeys, num_iterations);
			return 1;
		}
		if (zc_rx) {
			printf("ERROR: -Z applies to the server (receiver) only\n");
			return 1;
		}
	}

	printf("TLS Version: %s\n", version_name(tls_version));
	printf("Cipher: %s\n", cipher_name(cipher_type));
	printf("Address family: %s\n",
	       force_family == AF_INET ? "IPv4" :
	       force_family == AF_INET6 ? "IPv6" : "auto");
	if (random_size_max > 0)
		printf("Buffer size: random (1..%d)\n", random_size_max);
	else
		printf("Buffer size: %d\n", send_size);

	if (num_rekeys)
		printf("Rekey testing ENABLED: %d rekey(s)\n", num_rekeys);
	if (burst_mode)
		printf("Burst mode ENABLED\n");
	if (zc_rx)
		printf("TLS_RX_EXPECT_NO_PAD ENABLED\n");

	srand(time(NULL));

	if (is_server)
		return do_server() ? 1 : 0;

	return do_client() ? 1 : 0;
}
