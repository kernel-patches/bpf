// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <net/sock.h>
#include <net/smc.h>

extern struct bpf_struct_ops smc_sock_negotiator_ops;

DEFINE_RWLOCK(smc_sock_negotiator_ops_rwlock);
struct smc_sock_negotiator_ops *negotiator;

/* convert sk to smc_sock */
static inline struct smc_sock *smc_sk(const struct sock *sk)
{
	return (struct smc_sock *)sk;
}

/* register ops */
static inline void smc_reg_passive_sk_ops(struct smc_sock_negotiator_ops *ops)
{
	write_lock_bh(&smc_sock_negotiator_ops_rwlock);
	negotiator = ops;
	write_unlock_bh(&smc_sock_negotiator_ops_rwlock);
}

/* unregister ops */
static inline void smc_unreg_passive_sk_ops(struct smc_sock_negotiator_ops *ops)
{
	write_lock_bh(&smc_sock_negotiator_ops_rwlock);
	if (negotiator == ops)
		negotiator = NULL;
	write_unlock_bh(&smc_sock_negotiator_ops_rwlock);
}

int smc_sock_should_select_smc(const struct smc_sock *smc)
{
	int ret = SK_PASS;

	read_lock_bh(&smc_sock_negotiator_ops_rwlock);
	if (negotiator && negotiator->negotiate)
		ret = negotiator->negotiate((struct smc_sock *)smc);
	read_unlock_bh(&smc_sock_negotiator_ops_rwlock);
	return ret;
}
EXPORT_SYMBOL_GPL(smc_sock_should_select_smc);

void smc_sock_perform_collecting_info(const struct smc_sock *smc, int timing)
{
	read_lock_bh(&smc_sock_negotiator_ops_rwlock);
	if (negotiator && negotiator->collect_info)
		negotiator->collect_info((struct smc_sock *)smc, timing);
	read_unlock_bh(&smc_sock_negotiator_ops_rwlock);
}
EXPORT_SYMBOL_GPL(smc_sock_perform_collecting_info);

/* define global smc ID for smc_struct_ops */
BTF_ID_LIST_GLOBAL(btf_smc_ids, MAX_BTF_SMC_TYPE)
#define BTF_SMC_TYPE(name, type) BTF_ID(struct, type)
BTF_SMC_TYPE_xxx
#undef BTF_SMC_TYPE

static int bpf_smc_passive_sk_init(struct btf *btf)
{
	return 0;
}

/* register ops by BPF */
static int bpf_smc_passive_sk_ops_reg(void *kdata)
{
	struct smc_sock_negotiator_ops *ops = kdata;

	/* at least one ops need implement */
	if (!ops->negotiate || !ops->collect_info) {
		pr_err("At least one ops need implement.\n");
		return -EINVAL;
	}

	smc_reg_passive_sk_ops(ops);
	/* always success now */
	return 0;
}

/* unregister ops by BPF */
static void bpf_smc_passive_sk_ops_unreg(void *kdata)
{
	smc_unreg_passive_sk_ops(kdata);
}

static int bpf_smc_passive_sk_ops_check_member(const struct btf_type *t,
					       const struct btf_member *member,
					       const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_smc_passive_sk_ops_init_member(const struct btf_type *t,
					      const struct btf_member *member,
					      void *kdata, const void *udata)
{
	return 0;
}

static const struct bpf_func_proto *
smc_passive_sk_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}

static bool smc_passive_sk_ops_prog_is_valid_access(int off, int size, enum bpf_access_type type,
						    const struct bpf_prog *prog,
						    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int smc_passive_sk_ops_prog_struct_access(struct bpf_verifier_log *log,
						 const struct bpf_reg_state *reg,
						 int off, int size, enum bpf_access_type atype,
						 u32 *next_btf_id, enum bpf_type_flag *flag)
{
	/* only allow read now*/
	if (atype == BPF_READ)
		return btf_struct_access(log, reg, off, size, atype, next_btf_id, flag);

	return -EACCES;
}

static const struct bpf_verifier_ops bpf_smc_passive_sk_verifier_ops = {
	.get_func_proto  = smc_passive_sk_prog_func_proto,
	.is_valid_access = smc_passive_sk_ops_prog_is_valid_access,
	.btf_struct_access = smc_passive_sk_ops_prog_struct_access
};

struct bpf_struct_ops bpf_smc_sock_negotiator_ops = {
	.verifier_ops = &bpf_smc_passive_sk_verifier_ops,
	.init = bpf_smc_passive_sk_init,
	.check_member = bpf_smc_passive_sk_ops_check_member,
	.init_member = bpf_smc_passive_sk_ops_init_member,
	.reg = bpf_smc_passive_sk_ops_reg,
	.unreg = bpf_smc_passive_sk_ops_unreg,
	.name = "smc_sock_negotiator_ops",
};
