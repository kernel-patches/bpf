// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/bpf.h>
#include <uapi/linux/netdev.h>
#include <linux/if_link.h>
#include <signal.h>
#include <argp.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>

#include <network_helpers.h>

#include "xdp_features.skel.h"
#include "xdp_features.h"

#define RED(str)	"\033[0;31m" str "\033[0m"
#define GREEN(str)	"\033[0;32m" str "\033[0m"
#define YELLOW(str)	"\033[0;33m" str "\033[0m"

static struct env {
	bool verbosity;
	int ifindex;
	unsigned int feature;
	bool is_tester;
	int family;
	struct {
		struct sockaddr_storage addr;
		socklen_t addrlen;
	} dut_ctrl;
	struct {
		struct sockaddr_storage addr;
		socklen_t addrlen;
	} dut;
	struct {
		struct sockaddr_storage addr;
		socklen_t addrlen;
	} tester;
} env;

#define BUFSIZE		128

void test__fail(void) { /* for network_helpers.c */ }

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbosity)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

const char *argp_program_version = "xdp-features 0.0";
const char argp_program_doc[] =
"XDP features detecion application.\n"
"\n"
"XDP features application checks the XDP advertised features match detected ones.\n"
"\n"
"USAGE: ./xdp-features [-6vt] [-f <xdp-feature>] [-D <dut-data-ip>] [-T <tester-data-ip>] [-C <dut-ctrl-ip>] <iface-name>\n"
"\n"
"XDP features\n:"
"- XDP_PASS\n"
"- XDP_DROP\n"
"- XDP_ABORTED\n"
"- XDP_REDIRECT\n"
"- XDP_NDO_XMIT\n"
"- XDP_TX\n";

static const struct argp_option opts[] = {
	{ "ipv6", '6', NULL, 0, "Use IPv6 network stack" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "tester", 't', NULL, 0, "Tester mode" },
	{ "feature", 'f', "XDP-FEATURE", 0, "XDP feature to test" },
	{ "dut_data_ip", 'D', "DUT-DATA-IP", 0, "DUT IP data channel" },
	{ "dut_ctrl_ip", 'C', "DUT-CTRL-IP", 0, "DUT IP control channel" },
	{ "tester_data_ip", 'T', "TESTER-DATA-IP", 0, "Tester IP data channel" },
	{},
};

static int get_xdp_feature(const char *arg)
{
	if (!strcmp(arg, "XDP_PASS"))
		return XDP_FEATURE_PASS;
	else if (!strcmp(arg, "XDP_DROP"))
		return XDP_FEATURE_DROP;
	else if (!strcmp(arg, "XDP_ABORTED"))
		return XDP_FEATURE_ABORTED;
	else if (!strcmp(arg, "XDP_REDIRECT"))
		return XDP_FEATURE_REDIRECT;
	else if (!strcmp(arg, "XDP_NDO_XMIT"))
		return XDP_FEATURE_NDO_XMIT;
	else if (!strcmp(arg, "XDP_TX"))
		return XDP_FEATURE_TX;

	return -EINVAL;
}

static char *get_xdp_feature_str(int feature)
{
	switch (feature) {
	case XDP_FEATURE_PASS:
		return YELLOW("XDP_PASS");
	case XDP_FEATURE_DROP:
		return YELLOW("XDP_DROP");
	case XDP_FEATURE_ABORTED:
		return YELLOW("XDP_ABORTED");
	case XDP_FEATURE_TX:
		return YELLOW("XDP_TX");
	case XDP_FEATURE_REDIRECT:
		return YELLOW("XDP_REDIRECT");
	case XDP_FEATURE_NDO_XMIT:
		return YELLOW("XDP_NDO_XMIT");
	default:
		return "";
	}
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case '6':
		env.family = AF_INET6;
		break;
	case 'v':
		env.verbosity = true;
		break;
	case 't':
		env.is_tester = true;
		break;
	case 'f':
		env.feature = get_xdp_feature(arg);
		if (env.feature < 0) {
			fprintf(stderr, "Invalid xdp feature: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'D':
		if (make_sockaddr(env.family, arg, DUT_ECHO_PORT,
				  &env.dut.addr, &env.dut.addrlen)) {
			fprintf(stderr, "Invalid DUT address: %s\n", arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'C':
		if (make_sockaddr(env.family, arg, DUT_CTRL_PORT,
				  &env.dut_ctrl.addr, &env.dut_ctrl.addrlen)) {
			fprintf(stderr, "Invalid DUT CTRL address: %s\n", arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'T':
		if (make_sockaddr(env.family, arg, 0, &env.tester.addr,
				  &env.tester.addrlen)) {
			fprintf(stderr, "Invalid Tester address: %s\n", arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "Invalid device name: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}

		env.ifindex = if_nametoindex(arg);
		if (!env.ifindex)
			env.ifindex = strtoul(arg, NULL, 0);
		if (!env.ifindex) {
			fprintf(stderr,
				"Bad interface index or name (%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static void set_env_defaul(void)
{
	env.feature = XDP_FEATURE_PASS;
	env.ifindex = -ENODEV;
	env.family = AF_INET;
	make_sockaddr(AF_INET, "127.0.0.1", DUT_CTRL_PORT, &env.dut_ctrl.addr,
		      &env.dut_ctrl.addrlen);
	make_sockaddr(AF_INET, "127.0.0.1", DUT_ECHO_PORT, &env.dut.addr,
		      &env.dut.addrlen);
	make_sockaddr(AF_INET, "127.0.0.1", 0, &env.tester.addr,
		      &env.tester.addrlen);
}

static void *dut_echo_thread(void *arg)
{
	unsigned char buf[sizeof(struct tlv_hdr)];
	int sockfd = *(int *)arg;

	while (!exiting) {
		struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
		struct sockaddr_storage addr;
		socklen_t addrlen;
		size_t n;

		n = recvfrom(sockfd, buf, sizeof(buf), MSG_WAITALL,
			     (struct sockaddr *)&addr, &addrlen);
		if (n != ntohs(tlv->len))
			continue;

		if (ntohs(tlv->type) != CMD_ECHO)
			continue;

		sendto(sockfd, buf, sizeof(buf), MSG_NOSIGNAL | MSG_CONFIRM,
		       (struct sockaddr *)&addr, addrlen);
	}

	pthread_exit((void *)0);
	close(sockfd);

	return NULL;
}

static int dut_run_echo_thread(pthread_t *t, int *sockfd)
{
	int err;

	sockfd = start_reuseport_server(env.family, SOCK_DGRAM, NULL,
					DUT_ECHO_PORT, 0, 1);
	if (!sockfd) {
		fprintf(stderr, "Failed to create echo socket\n");
		return -errno;
	}

	/* start echo channel */
	err = pthread_create(t, NULL, dut_echo_thread, sockfd);
	if (err) {
		fprintf(stderr, "Failed creating dut_echo thread: %s\n",
			strerror(-err));
		free_fds(sockfd, 1);
		return -EINVAL;
	}

	return 0;
}

static int dut_attach_xdp_prog(struct xdp_features *skel, int feature,
			       int flags)
{
	struct bpf_program *prog;
	unsigned int key = 0;
	int err, fd = 0;

	switch (feature) {
	case XDP_FEATURE_TX:
		prog = skel->progs.xdp_do_tx;
		break;
	case XDP_FEATURE_DROP:
		prog = skel->progs.xdp_do_drop;
		break;
	case XDP_FEATURE_ABORTED:
		prog = skel->progs.xdp_do_aborted;
		break;
	case XDP_FEATURE_PASS:
		prog = skel->progs.xdp_do_pass;
		break;
	case XDP_FEATURE_NDO_XMIT: {
		struct bpf_devmap_val entry = {
			.ifindex = env.ifindex,
		};

		err = bpf_map__update_elem(skel->maps.dev_map,
					   &key, sizeof(key),
					   &entry, sizeof(entry), 0);
		if (err < 0)
			return err;

		fd = bpf_program__fd(skel->progs.xdp_do_redirect_cpumap);
	}
	case XDP_FEATURE_REDIRECT: {
		struct bpf_cpumap_val entry = {
			.qsize = 2048,
			.bpf_prog.fd = fd,
		};

		err = bpf_map__update_elem(skel->maps.cpu_map,
					   &key, sizeof(key),
					   &entry, sizeof(entry), 0);
		if (err < 0)
			return err;

		prog = skel->progs.xdp_do_redirect;
		break;
	}
	default:
		return -EINVAL;
	}

	err = bpf_xdp_attach(env.ifindex, bpf_program__fd(prog), flags, NULL);
	if (err)
		fprintf(stderr,
			"Failed to attach XDP program to ifindex %d\n",
			env.ifindex);
	return err;
}

static int __recv_msg(int sockfd, void *buf, size_t bufsize,
		      unsigned int *val, unsigned int val_size)
{
	struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
	int len, n = sizeof(*tlv), i = 0;

	len = recv(sockfd, buf, bufsize, 0);
	if (len != ntohs(tlv->len))
		return -EINVAL;

	while (n < len && i < val_size) {
		val[i] = ntohl(tlv->data[i]);
		n += sizeof(tlv->data[0]);
		i++;
	}

	return i;
}

static int recv_msg(int sockfd, void *buf, size_t bufsize)
{
	return __recv_msg(sockfd, buf, bufsize, NULL, 0);
}

static int dut_run(struct xdp_features *skel)
{
	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	int state, err, *sockfd, ctrl_sockfd, echo_sockfd;
	struct sockaddr_storage ctrl_addr;
	pthread_t dut_thread;
	socklen_t addrlen;

	sockfd = start_reuseport_server(env.family, SOCK_STREAM, NULL,
					DUT_CTRL_PORT, 0, 1);
	if (!sockfd) {
		fprintf(stderr, "Failed to create DUT socket\n");
		return -errno;
	}

	ctrl_sockfd = accept(*sockfd, (struct sockaddr *)&ctrl_addr, &addrlen);
	if (ctrl_sockfd < 0) {
		fprintf(stderr, "Failed to accept connection on DUT socket\n");
		free_fds(sockfd, 1);
		return -errno;
	}

	/* CTRL loop */
	while (!exiting) {
		unsigned char buf[BUFSIZE] = {};
		struct tlv_hdr *tlv = (struct tlv_hdr *)buf;

		err = recv_msg(ctrl_sockfd, buf, BUFSIZE);
		if (err)
			continue;

		switch (ntohs(tlv->type)) {
		case CMD_START: {
			if (state == CMD_START)
				continue;

			state = CMD_START;
			/* Load the XDP program on the DUT */
			err = dut_attach_xdp_prog(skel, ntohl(tlv->data[0]), flags);
			if (err)
				goto out;

			err = dut_run_echo_thread(&dut_thread, &echo_sockfd);
			if (err < 0)
				goto out;

			tlv->type = htons(CMD_ACK);
			tlv->len = htons(sizeof(*tlv));
			err = send(ctrl_sockfd, buf, sizeof(*tlv), 0);
			if (err < 0)
				goto end_thread;
			break;
		}
		case CMD_STOP:
			if (state != CMD_START)
				break;

			state = CMD_STOP;

			exiting = true;
			bpf_xdp_detach(env.ifindex, flags, NULL);

			tlv->type = htons(CMD_ACK);
			tlv->len = htons(sizeof(*tlv));
			err = send(ctrl_sockfd, buf, sizeof(*tlv), 0);
			goto end_thread;
		case CMD_GET_XDP_CAP: {
			LIBBPF_OPTS(bpf_xdp_query_opts, opts);
			size_t n;

			err = bpf_xdp_query(env.ifindex, XDP_FLAGS_DRV_MODE,
					    &opts);
			if (err) {
				fprintf(stderr,
					"Failed to query XDP cap for ifindex %d\n",
					env.ifindex);
				goto end_thread;
			}

			tlv->type = htons(CMD_ACK);
			n = sizeof(*tlv) + sizeof(opts.feature_flags);
			tlv->len = htons(n);
			tlv->data[0] = htonl(opts.feature_flags);

			err = send(ctrl_sockfd, buf, n, 0);
			if (err < 0)
				goto end_thread;
			break;
		}
		case CMD_GET_STATS: {
			unsigned int key = 0, val;
			size_t n;

			err = bpf_map__lookup_elem(skel->maps.dut_stats,
						   &key, sizeof(key),
						   &val, sizeof(val), 0);
			if (err) {
				fprintf(stderr, "bpf_map_lookup_elem failed\n");
				goto end_thread;
			}

			tlv->type = htons(CMD_ACK);
			n = sizeof(*tlv) + sizeof(val);
			tlv->len = htons(n);
			tlv->data[0] = htonl(val);

			err = send(ctrl_sockfd, buf, n, 0);
			if (err < 0)
				goto end_thread;
			break;
		}
		default:
			break;
		}
	}

end_thread:
	pthread_join(dut_thread, NULL);
out:
	bpf_xdp_detach(env.ifindex, flags, NULL);
	close(ctrl_sockfd);
	free_fds(sockfd, 1);

	return err;
}

static bool tester_collect_advertised_cap(unsigned int cap)
{
	switch (env.feature) {
	case XDP_FEATURE_ABORTED:
	case XDP_FEATURE_DROP:
	case XDP_FEATURE_PASS:
	case XDP_FEATURE_TX:
		return cap & NETDEV_XDP_ACT_BASIC;
	case XDP_FEATURE_REDIRECT:
		return cap & NETDEV_XDP_ACT_REDIRECT;
	case XDP_FEATURE_NDO_XMIT:
		return cap & NETDEV_XDP_ACT_NDO_XMIT;
	default:
		return false;
	}
}

static bool tester_collect_detected_cap(struct xdp_features *skel,
					unsigned int dut_stats)
{
	unsigned int err, key = 0, val;

	if (!dut_stats)
		return false;

	err = bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key),
				   &val, sizeof(val), 0);
	if (err) {
		fprintf(stderr, "bpf_map_lookup_elem failed\n");
		return false;
	}

	switch (env.feature) {
	case XDP_FEATURE_PASS:
	case XDP_FEATURE_TX:
	case XDP_FEATURE_REDIRECT:
	case XDP_FEATURE_NDO_XMIT:
		return val > 0;
	case XDP_FEATURE_DROP:
	case XDP_FEATURE_ABORTED:
		return val == 0;
	default:
		return false;
	}
}

static int __send_and_recv_msg(int sockfd, enum test_commands cmd,
			       unsigned int *val, unsigned int val_size)
{
	unsigned char buf[BUFSIZE] = {};
	struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
	int n = sizeof(*tlv), err;

	tlv->type = htons(cmd);
	switch (cmd) {
	case CMD_START:
		tlv->data[0] = htonl(env.feature);
		n += sizeof(*val);
		break;
	default:
		break;
	}
	tlv->len = htons(n);

	err = send(sockfd, buf, n, 0);
	if (err < 0)
		return err;

	err = __recv_msg(sockfd, buf, BUFSIZE, val, val_size);
	if (err < 0)
		return err;

	return ntohs(tlv->type) == CMD_ACK ? 0 : -EINVAL;
}

static int send_and_recv_msg(int sockfd, enum test_commands cmd)
{
	return __send_and_recv_msg(sockfd, cmd, NULL, 0);
}

static int send_echo_msg(void)
{
	unsigned char buf[sizeof(struct tlv_hdr)];
	struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
	int sockfd, n;

	sockfd = socket(env.family, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Failed to create echo socket\n");
		return -errno;
	}

	tlv->type = htons(CMD_ECHO);
	tlv->len = htons(sizeof(*tlv));

	n = sendto(sockfd, buf, sizeof(*tlv), MSG_NOSIGNAL | MSG_CONFIRM,
		   (struct sockaddr *)&env.dut.addr, env.dut.addrlen);
	close(sockfd);

	return n == ntohs(tlv->len) ? 0 : -EINVAL;
}

static int tester_run(struct xdp_features *skel)
{
	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	bool advertised_cap;
	unsigned int val[1];
	int i, err, sockfd;
	bool detected_cap;

	sockfd = socket(env.family, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Failed to create tester socket\n");
		return -errno;
	}

	if (settimeo(sockfd, 1000) < 0)
		return -EINVAL;

	err = connect(sockfd, (struct sockaddr *)&env.dut_ctrl.addr,
		      env.dut_ctrl.addrlen);
	if (err) {
		fprintf(stderr, "Failed to connect to the DUT\n");
		return -errno;
	}

	err = __send_and_recv_msg(sockfd, CMD_GET_XDP_CAP, val,
				  ARRAY_SIZE(val));
	if (err < 0) {
		close(sockfd);
		return err;
	}

	advertised_cap = tester_collect_advertised_cap(val[0]);

	err = bpf_xdp_attach(env.ifindex,
			     bpf_program__fd(skel->progs.xdp_tester),
			     flags, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach XDP program to ifindex %d\n",
			env.ifindex);
		goto out;
	}

	err = send_and_recv_msg(sockfd, CMD_START);
	if (err)
		goto out;

	for (i = 0; i < 10 && !exiting; i++) {
		err = send_echo_msg();
		if (err < 0)
			goto out;

		sleep(1);
	}

	err = __send_and_recv_msg(sockfd, CMD_GET_STATS, val, ARRAY_SIZE(val));
	if (err)
		goto out;

	/* stop the test */
	err = send_and_recv_msg(sockfd, CMD_STOP);
	/* send a new echo message to wake echo thread of the dut */
	send_echo_msg();

	detected_cap = tester_collect_detected_cap(skel, val[0]);

	fprintf(stdout, "Feature %s: [%s][%s]\n", get_xdp_feature_str(env.feature),
		detected_cap ? GREEN("DETECTED") : RED("NOT DETECTED"),
		advertised_cap ? GREEN("ADVERTISED") : RED("NOT ADVERTISED"));
out:
	bpf_xdp_detach(env.ifindex, flags, NULL);
	close(sockfd);
	return err < 0 ? err : 0;
}

static void set_skel_rodata(struct xdp_features *skel)
{
	skel->rodata->expected_feature = env.feature;
	if (env.family == AF_INET6) {
		struct sockaddr_in6 *tester_addr = (void *)&env.tester.addr;
		struct sockaddr_in6 *dut_addr = (void *)&env.dut.addr;

		skel->rodata->tester_addr.ip6 = tester_addr->sin6_addr;
		skel->rodata->dut_addr.ip6 = dut_addr->sin6_addr;
	} else {
		struct sockaddr_in *tester_addr = (void *)&env.tester.addr;
		struct sockaddr_in *dut_addr = (void *)&env.dut.addr;

		skel->rodata->tester_addr.ip = tester_addr->sin_addr;
		skel->rodata->dut_addr.ip = dut_addr->sin_addr;
	}
}

int main(int argc, char **argv)
{
	struct xdp_features *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	set_env_defaul();

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.ifindex < 0) {
		fprintf(stderr, "Invalid ifindex\n");
		return -ENODEV;
	}

	/* Load and verify BPF application */
	skel = xdp_features__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -EINVAL;
	}

	set_skel_rodata(skel);

	/* Load & verify BPF programs */
	err = xdp_features__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = xdp_features__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (env.is_tester) {
		/* Tester */
		fprintf(stdout, "Starting tester on device %d\n", env.ifindex);
		err = tester_run(skel);
	} else {
		/* DUT */
		fprintf(stdout, "Starting DUT on device %d\n", env.ifindex);
		err = dut_run(skel);
	}

cleanup:
	xdp_features__destroy(skel);

	return err < 0 ? -err : 0;
}
