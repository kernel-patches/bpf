// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  smc_sysctl.c: sysctl interface to SMC subsystem.
 *
 *  Copyright (c) 2022, Alibaba Inc.
 *
 *  Author: Tony Lu <tonylu@linux.alibaba.com>
 *
 */

#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>

#include "smc.h"
#include "smc_core.h"
#include "smc_llc.h"
#include "smc_sysctl.h"
#include "smc_ops.h"

static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;
static int max_sndbuf = INT_MAX / 2;
static int max_rcvbuf = INT_MAX / 2;
static const int net_smc_wmem_init = (64 * 1024);
static const int net_smc_rmem_init = (64 * 1024);
static int links_per_lgr_min = SMC_LINKS_ADD_LNK_MIN;
static int links_per_lgr_max = SMC_LINKS_ADD_LNK_MAX;
static int conns_per_lgr_min = SMC_CONN_PER_LGR_MIN;
static int conns_per_lgr_max = SMC_CONN_PER_LGR_MAX;

#if IS_ENABLED(CONFIG_SMC_OPS)
static int smc_net_replace_smc_ops(struct net *net, const char *name)
{
	struct smc_ops *ops = NULL;

	rcu_read_lock();
	/* null or empty name ask to clear current ops */
	if (name && name[0]) {
		ops = smc_ops_find_by_name(name);
		if (!ops) {
			rcu_read_unlock();
			return -EINVAL;
		}
		/* no change, just return */
		if (ops == rcu_dereference(net->smc.ops)) {
			rcu_read_unlock();
			return 0;
		}
	}
	if (!ops || bpf_try_module_get(ops, ops->owner)) {
		/* xhcg */
		ops = rcu_replace_pointer(net->smc.ops, ops, true);
		/* release old ops */
		if (ops)
			bpf_module_put(ops, ops->owner);
	} else if (ops) {
		rcu_read_unlock();
		return -EBUSY;
	}
	rcu_read_unlock();
	return 0;
}

static int proc_smc_ops(const struct ctl_table *ctl, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net,
				       smc.ops);
	char val[SMC_OPS_NAME_MAX];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = SMC_OPS_NAME_MAX,
	};
	struct smc_ops *ops;
	int ret;

	rcu_read_lock();
	ops = rcu_dereference(net->smc.ops);
	if (ops)
		memcpy(val, ops->name, sizeof(ops->name));
	else
		val[0] = '\0';
	rcu_read_unlock();

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write)
		ret = smc_net_replace_smc_ops(net, val);
	return ret;
}
#endif /* CONFIG_SMC_OPS */

static struct ctl_table smc_table[] = {
	{
		.procname       = "autocorking_size",
		.data           = &init_net.smc.sysctl_autocorking_size,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "smcr_buf_type",
		.data		= &init_net.smc.sysctl_smcr_buf_type,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "smcr_testlink_time",
		.data		= &init_net.smc.sysctl_smcr_testlink_time,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "wmem",
		.data		= &init_net.smc.sysctl_wmem,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_sndbuf,
		.extra2		= &max_sndbuf,
	},
	{
		.procname	= "rmem",
		.data		= &init_net.smc.sysctl_rmem,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_rcvbuf,
		.extra2		= &max_rcvbuf,
	},
	{
		.procname	= "smcr_max_links_per_lgr",
		.data		= &init_net.smc.sysctl_max_links_per_lgr,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &links_per_lgr_min,
		.extra2		= &links_per_lgr_max,
	},
	{
		.procname	= "smcr_max_conns_per_lgr",
		.data		= &init_net.smc.sysctl_max_conns_per_lgr,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &conns_per_lgr_min,
		.extra2		= &conns_per_lgr_max,
	},
	{
		.procname	= "limit_smc_hs",
		.data		= &init_net.smc.limit_smc_hs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#if IS_ENABLED(CONFIG_SMC_OPS)
	{
		.procname	= "ops",
		.data		= &init_net.smc.ops,
		.mode		= 0644,
		.maxlen		= SMC_OPS_NAME_MAX,
		.proc_handler	= proc_smc_ops,
	},
#endif /* CONFIG_SMC_OPS */
};

int __net_init smc_sysctl_net_init(struct net *net)
{
	size_t table_size = ARRAY_SIZE(smc_table);
	struct ctl_table *table;

	table = smc_table;
	if (!net_eq(net, &init_net)) {
		int i;
#if IS_ENABLED(CONFIG_SMC_OPS)
		struct smc_ops *ops;

		rcu_read_lock();
		ops = rcu_dereference(init_net.smc.ops);
		if (ops && ops->flags & SMC_OPS_FLAG_INHERITABLE) {
			if (!bpf_try_module_get(ops, ops->owner)) {
				rcu_read_unlock();
				return -EBUSY;
			}
			rcu_assign_pointer(net->smc.ops, ops);
		}
		rcu_read_unlock();
#endif /* CONFIG_SMC_OPS */

		table = kmemdup(table, sizeof(smc_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < table_size; i++)
			table[i].data += (void *)net - (void *)&init_net;
	}

	net->smc.smc_hdr = register_net_sysctl_sz(net, "net/smc", table,
						  table_size);
	if (!net->smc.smc_hdr)
		goto err_reg;

	net->smc.sysctl_autocorking_size = SMC_AUTOCORKING_DEFAULT_SIZE;
	net->smc.sysctl_smcr_buf_type = SMCR_PHYS_CONT_BUFS;
	net->smc.sysctl_smcr_testlink_time = SMC_LLC_TESTLINK_DEFAULT_TIME;
	WRITE_ONCE(net->smc.sysctl_wmem, net_smc_wmem_init);
	WRITE_ONCE(net->smc.sysctl_rmem, net_smc_rmem_init);
	net->smc.sysctl_max_links_per_lgr = SMC_LINKS_PER_LGR_MAX_PREFER;
	net->smc.sysctl_max_conns_per_lgr = SMC_CONN_PER_LGR_PREFER;
	/* disable handshake limitation by default */
	net->smc.limit_smc_hs = 0;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
#if IS_ENABLED(CONFIG_SMC_OPS)
	smc_net_replace_smc_ops(net, NULL);
#endif /* CONFIG_SMC_OPS */
	return -ENOMEM;
}

void __net_exit smc_sysctl_net_exit(struct net *net)
{
	const struct ctl_table *table;

	table = net->smc.smc_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->smc.smc_hdr);
#if IS_ENABLED(CONFIG_SMC_OPS)
	smc_net_replace_smc_ops(net, NULL);
#endif /* CONFIG_SMC_OPS */

	if (!net_eq(net, &init_net))
		kfree(table);
}
