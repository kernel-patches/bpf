#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

static int fs_readahead_get_max_ra_stub(struct bpf_fs_readahead_state *state)
{
	return 0;
}

static int fs_readahead_get_ra_stub(struct bpf_fs_readahead_state *state)
{
	return 0;
}

struct bpf_fs_readahead_ops knn_readahead = {
	.get_max_ra = fs_readahead_get_max_ra_stub,
	.get_ra = fs_readahead_get_ra_stub,
};

// verifier

static bool fs_readahead_ops_is_valid_access(int off, int size,
					     enum bpf_access_type type,
					     const struct bpf_prog *prog,
					     struct bpf_insn_access_aux *info)
{
	return true;
}

static int fs_readahead_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	return 0;
}

struct bpf_verifier_ops bpf_fs_readahead_verifier_ops = {
	.get_func_proto = NULL,
	.is_valid_access = fs_readahead_ops_is_valid_access,
	.btf_struct_access = fs_readahead_btf_struct_access,
};

// management

static int register_bpf_fs_ra(void *kdata)
{
	printk(KERN_ALERT "register_bpf_fs_ra\n");
	return bpf_fs_ra_register(kdata);
}

static void unregister_bpf_fs_ra(void *kdata)
{
	printk(KERN_ALERT "unregister_bpf_fs_ra\n");
	bpf_fs_ra_unregister(kdata);
}

static int bpf_fs_ra_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_fs_ra_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	// no-op for now
	return 0;
}

static struct btf *bpf_fs_ra_btf;

static int bpf_fs_ra_init(struct btf *btf)
{
	bpf_fs_ra_btf = btf;
	return 0;
}

static struct bpf_struct_ops bpf_fs_readahead_ops_struct = {
	.verifier_ops = &bpf_fs_readahead_verifier_ops,
	.reg = register_bpf_fs_ra,
	.unreg = unregister_bpf_fs_ra,
	.update = NULL, // cannot be updated
	.check_member = bpf_fs_ra_check_member,
	.init_member = bpf_fs_ra_init_member,
	.init = bpf_fs_ra_init,
	.validate = NULL,

	.name = "bpf_fs_readahead_ops",
	.cfi_stubs = &knn_readahead,
	.owner = THIS_MODULE,
};

static void noop(void *p)
{
	// no-op
}

static int __init bpf_fs_ra_kfunc_init(void)
{
	int ret = 0;
	noop(&bpf_fs_readahead_ops_struct);
	ret = register_bpf_struct_ops(&bpf_fs_readahead_ops_struct,
					  bpf_fs_readahead_ops);
	return ret;
}
late_initcall(bpf_fs_ra_kfunc_init);
