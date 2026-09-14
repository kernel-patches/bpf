// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/inet_common.h>
#include <linux/proc_fs.h>
#include <net/protocol.h>
#include <net/rps.h>
#include <net/tls.h>

#include "socket.h"

static unsigned int quic_net_id __read_mostly;

struct percpu_counter quic_sockets_allocated;
struct workqueue_struct *quic_wq;

DEFINE_STATIC_KEY_FALSE(quic_alpn_demux_key);

long sysctl_quic_mem[3];
int sysctl_quic_rmem[3];
int sysctl_quic_wmem[3];

static int quic_inet_connect(struct socket *sock, struct sockaddr_unsized *addr,
			     int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < (int)sizeof(addr->sa_family))
		return -EINVAL;

	return sk->sk_prot->connect(sk, addr, addr_len);
}

static int quic_inet_listen(struct socket *sock, int backlog)
{
	return -EOPNOTSUPP;
}

static int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr,
			     int peer)
{
	return quic_get_sk_addr(sock, uaddr, peer);
}

static __poll_t quic_inet_poll(struct file *file, struct socket *sock,
			       poll_table *wait)
{
	return 0;
}

struct quic_net *quic_net(struct net *net)
{
	return net_generic(net, quic_net_id);
}

#if IS_ENABLED(CONFIG_PROC_FS)
static const struct snmp_mib quic_snmp_list[] = {
	SNMP_MIB_ITEM("QuicConnCurrentEstabs", QUIC_MIB_CONN_CURRENTESTABS),
	SNMP_MIB_ITEM("QuicConnPassiveEstabs", QUIC_MIB_CONN_PASSIVEESTABS),
	SNMP_MIB_ITEM("QuicConnActiveEstabs", QUIC_MIB_CONN_ACTIVEESTABS),
	SNMP_MIB_ITEM("QuicPktRcvFastpaths", QUIC_MIB_PKT_RCVFASTPATHS),
	SNMP_MIB_ITEM("QuicPktDecFastpaths", QUIC_MIB_PKT_DECFASTPATHS),
	SNMP_MIB_ITEM("QuicPktEncFastpaths", QUIC_MIB_PKT_ENCFASTPATHS),
	SNMP_MIB_ITEM("QuicPktRcvBacklogs", QUIC_MIB_PKT_RCVBACKLOGS),
	SNMP_MIB_ITEM("QuicPktDecBacklogs", QUIC_MIB_PKT_DECBACKLOGS),
	SNMP_MIB_ITEM("QuicPktEncBacklogs", QUIC_MIB_PKT_ENCBACKLOGS),
	SNMP_MIB_ITEM("QuicPktInvHdrDrop", QUIC_MIB_PKT_INVHDRDROP),
	SNMP_MIB_ITEM("QuicPktInvNumDrop", QUIC_MIB_PKT_INVNUMDROP),
	SNMP_MIB_ITEM("QuicPktInvFrmDrop", QUIC_MIB_PKT_INVFRMDROP),
	SNMP_MIB_ITEM("QuicPktRcvDrop", QUIC_MIB_PKT_RCVDROP),
	SNMP_MIB_ITEM("QuicPktDecDrop", QUIC_MIB_PKT_DECDROP),
	SNMP_MIB_ITEM("QuicPktEncDrop", QUIC_MIB_PKT_ENCDROP),
	SNMP_MIB_ITEM("QuicFrmRcvBufDrop", QUIC_MIB_FRM_RCVBUFDROP),
	SNMP_MIB_ITEM("QuicFrmRetrans", QUIC_MIB_FRM_RETRANS),
	SNMP_MIB_ITEM("QuicFrmOutCloses", QUIC_MIB_FRM_OUTCLOSES),
	SNMP_MIB_ITEM("QuicFrmInCloses", QUIC_MIB_FRM_INCLOSES),
};

static int quic_snmp_seq_show(struct seq_file *seq, void *v)
{
	unsigned long buff[ARRAY_SIZE(quic_snmp_list)];
	const int cnt = ARRAY_SIZE(quic_snmp_list);
	struct net *net = seq->private;
	u32 idx;

	memset(buff, 0, sizeof(buff));

	snmp_get_cpu_field_batch_cnt(buff, quic_snmp_list, cnt,
				     quic_net(net)->stat);
	for (idx = 0; idx < cnt; idx++)
		seq_printf(seq, "%-32s\t%lu\n", quic_snmp_list[idx].name,
			   buff[idx]);

	return 0;
}

static int quic_net_proc_init(struct net *net)
{
	quic_net(net)->proc_net = proc_net_mkdir(net, "quic", net->proc_net);
	if (!quic_net(net)->proc_net)
		return -ENOMEM;

	if (!proc_create_net_single("snmp", 0444, quic_net(net)->proc_net,
				    quic_snmp_seq_show, NULL))
		goto free;
	return 0;
free:
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
	return -ENOMEM;
}

static void quic_net_proc_exit(struct net *net)
{
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
}
#endif

static const struct proto_ops quic_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = quic_inet_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
};

static struct inet_protosw quic_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static struct inet_protosw quic_dgram_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static const struct proto_ops quicv6_proto_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = quic_inet_poll,
	.ioctl		   = inet6_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
};

static struct inet_protosw quicv6_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static struct inet_protosw quicv6_dgram_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static int quic_protosw_init(void)
{
	int err;

	err = proto_register(&quic_prot, 1);
	if (err)
		return err;

	err = proto_register(&quicv6_prot, 1);
	if (err) {
		proto_unregister(&quic_prot);
		return err;
	}

	inet_register_protosw(&quic_stream_protosw);
	inet_register_protosw(&quic_dgram_protosw);
	inet6_register_protosw(&quicv6_stream_protosw);
	inet6_register_protosw(&quicv6_dgram_protosw);

	return 0;
}

static void quic_protosw_exit(void)
{
	inet_unregister_protosw(&quic_dgram_protosw);
	inet_unregister_protosw(&quic_stream_protosw);
	proto_unregister(&quic_prot);

	inet6_unregister_protosw(&quicv6_dgram_protosw);
	inet6_unregister_protosw(&quicv6_stream_protosw);
	proto_unregister(&quicv6_prot);
}

static int __net_init quic_net_init(struct net *net)
{
	struct quic_net *qn = quic_net(net);
	int err = 0;

	qn->stat = alloc_percpu(struct quic_mib);
	if (!qn->stat)
		return -ENOMEM;

#if IS_ENABLED(CONFIG_PROC_FS)
	err = quic_net_proc_init(net);
	if (err) {
		free_percpu(qn->stat);
		qn->stat = NULL;
	}
#endif
	return err;
}

static void __net_exit quic_net_exit(struct net *net)
{
	struct quic_net *qn = quic_net(net);

#if IS_ENABLED(CONFIG_PROC_FS)
	quic_net_proc_exit(net);
#endif
	free_percpu(qn->stat);
	qn->stat = NULL;
}

static struct pernet_operations quic_net_ops = {
	.init = quic_net_init,
	.exit = quic_net_exit,
	.id   = &quic_net_id,
	.size = sizeof(struct quic_net),
};

#if IS_ENABLED(CONFIG_SYSCTL)
static struct ctl_table_header *quic_sysctl_header;

static struct ctl_table quic_table[] = {
	{
		.procname	= "quic_mem",
		.data		= &sysctl_quic_mem,
		.maxlen		= sizeof(sysctl_quic_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax
	},
	{
		.procname	= "quic_rmem",
		.data		= &sysctl_quic_rmem,
		.maxlen		= sizeof(sysctl_quic_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "quic_wmem",
		.data		= &sysctl_quic_wmem,
		.maxlen		= sizeof(sysctl_quic_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
};

static void quic_sysctl_register(void)
{
	quic_sysctl_header = register_net_sysctl(&init_net, "net/quic",
						 quic_table);
}

static void quic_sysctl_unregister(void)
{
	unregister_net_sysctl_table(quic_sysctl_header);
}
#endif

static __init int quic_init(void)
{
	int max_share, err = -ENOMEM;
	unsigned long limit;

	BUILD_BUG_ON(sizeof(struct quic_skb_cb) >
		     sizeof_field(struct sk_buff, cb));

	/* Set QUIC memory limits based on available system memory, similar to
	 * sctp_init().
	 */
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_quic_mem[0] = (long)limit / 4 * 3;
	sysctl_quic_mem[1] = (long)limit;
	sysctl_quic_mem[2] = sysctl_quic_mem[0] * 2;

	limit = (sysctl_quic_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL * 1024 * 1024, limit);

	sysctl_quic_rmem[0] = PAGE_SIZE;
	sysctl_quic_rmem[1] = 1024 * 1024;
	sysctl_quic_rmem[2] = max(sysctl_quic_rmem[1], max_share);

	sysctl_quic_wmem[0] = PAGE_SIZE;
	sysctl_quic_wmem[1] = 16 * 1024;
	sysctl_quic_wmem[2] = max(64 * 1024, max_share);

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto err_percpu_counter;

	err = quic_hash_tables_init();
	if (err)
		goto err_hash;

	/* Allocate an unbound workqueue for UDP socket destruction and backlog
	 * packet processing.
	 */
	quic_wq = alloc_workqueue("quic_workqueue", WQ_UNBOUND, 0);
	if (!quic_wq) {
		err = -ENOMEM;
		goto err_wq;
	}

	err = register_pernet_subsys(&quic_net_ops);
	if (err)
		goto err_def_ops;

	err = quic_protosw_init();
	if (err)
		goto err_protosw;

#if IS_ENABLED(CONFIG_SYSCTL)
	quic_sysctl_register();
#endif
	pr_info("quic: init\n");
	return 0;

err_protosw:
	unregister_pernet_subsys(&quic_net_ops);
err_def_ops:
	destroy_workqueue(quic_wq);
err_wq:
	quic_hash_tables_destroy();
err_hash:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	return err;
}

static __exit void quic_exit(void)
{
#if IS_ENABLED(CONFIG_SYSCTL)
	quic_sysctl_unregister();
#endif
	quic_protosw_exit();
	unregister_pernet_subsys(&quic_net_ops);
	flush_workqueue(quic_wq);
	destroy_workqueue(quic_wq);
	quic_hash_tables_destroy();
	percpu_counter_destroy(&quic_sockets_allocated);
	rcu_barrier();
	pr_info("quic: exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS_NET_PF_PROTO(PF_INET, 261); /* IPPROTO_QUIC == 261 */
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, 261);
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
