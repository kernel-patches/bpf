#include <linux/bpf.h>
#include <linux/vmalloc.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/user_namespace.h>

bool bpf_token_capable(const struct bpf_token *token, int cap)
{
	/* BPF token allows ns_capable() level of capabilities */
	if (token) {
		if (ns_capable(token->userns, cap))
			return true;
		if (cap != CAP_SYS_ADMIN && ns_capable(token->userns, CAP_SYS_ADMIN))
			return true;
	}
	/* otherwise fallback to capable() checks */
	return capable(cap) || (cap != CAP_SYS_ADMIN && capable(CAP_SYS_ADMIN));
}

void bpf_token_inc(struct bpf_token *token)
{
	atomic64_inc(&token->refcnt);
}

static void bpf_token_free(struct bpf_token *token)
{
	put_user_ns(token->userns);
	kvfree(token);
}

static void bpf_token_put_deferred(struct work_struct *work)
{
	struct bpf_token *token = container_of(work, struct bpf_token, work);

	bpf_token_free(token);
}

void bpf_token_put(struct bpf_token *token)
{
	if (!token)
		return;

	if (!atomic64_dec_and_test(&token->refcnt))
		return;

	INIT_WORK(&token->work, bpf_token_put_deferred);
	schedule_work(&token->work);
}

static int bpf_token_release(struct inode *inode, struct file *filp)
{
	struct bpf_token *token = filp->private_data;

	bpf_token_put(token);
	return 0;
}

static ssize_t bpf_dummy_read(struct file *filp, char __user *buf, size_t siz,
			      loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_READ.
	 */
	return -EINVAL;
}

static ssize_t bpf_dummy_write(struct file *filp, const char __user *buf,
			       size_t siz, loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_WRITE.
	 */
	return -EINVAL;
}

static void bpf_token_show_fdinfo(struct seq_file *m, struct file *filp)
{
	struct bpf_token *token = filp->private_data;
	u64 mask;

	mask = (1ULL << __MAX_BPF_CMD) - 1;
	if ((token->allowed_cmds & mask) == mask)
		seq_printf(m, "allowed_cmds:\tany\n");
	else
		seq_printf(m, "allowed_cmds:\t0x%llx\n", token->allowed_cmds);

	mask = (1ULL << __MAX_BPF_MAP_TYPE) - 1;
	if ((token->allowed_maps & mask) == mask)
		seq_printf(m, "allowed_maps:\tany\n");
	else
		seq_printf(m, "allowed_maps:\t0x%llx\n", token->allowed_maps);
}

static const struct file_operations bpf_token_fops = {
	.release	= bpf_token_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
	.show_fdinfo	= bpf_token_show_fdinfo,
};

static struct bpf_token *bpf_token_alloc(void)
{
	struct bpf_token *token;

	token = kvzalloc(sizeof(*token), GFP_USER);
	if (!token)
		return NULL;

	atomic64_set(&token->refcnt, 1);

	return token;
}

int bpf_token_create(union bpf_attr *attr)
{
	struct path path;
	struct bpf_mount_opts *mnt_opts;
	struct bpf_token *token;
	int ret;

	ret = user_path_at(attr->token_create.bpffs_path_fd,
			   u64_to_user_ptr(attr->token_create.bpffs_pathname),
			   LOOKUP_FOLLOW | LOOKUP_EMPTY, &path);
	if (ret)
		return ret;

	if (path.mnt->mnt_root != path.dentry) {
		ret = -EINVAL;
		goto out;
	}
	ret = path_permission(&path, MAY_ACCESS);
	if (ret)
		goto out;

	token = bpf_token_alloc();
	if (!token) {
		ret = -ENOMEM;
		goto out;
	}

	/* remember bpffs owning userns for future ns_capable() checks */
	token->userns = get_user_ns(path.dentry->d_sb->s_user_ns);

	mnt_opts = path.dentry->d_sb->s_fs_info;
	token->allowed_cmds = mnt_opts->delegate_cmds;
	token->allowed_maps = mnt_opts->delegate_maps;

	ret = bpf_token_new_fd(token);
	if (ret < 0)
		bpf_token_free(token);
out:
	path_put(&path);
	return ret;
}

#define BPF_TOKEN_INODE_NAME "bpf-token"

/* Alloc anon_inode and FD for prepared token.
 * Returns fd >= 0 on success; negative error, otherwise.
 */
int bpf_token_new_fd(struct bpf_token *token)
{
	return anon_inode_getfd(BPF_TOKEN_INODE_NAME, &bpf_token_fops, token, O_CLOEXEC);
}

struct bpf_token *bpf_token_get_from_fd(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_token *token;

	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_token_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	token = f.file->private_data;
	bpf_token_inc(token);
	fdput(f);

	return token;
}

bool bpf_token_allow_cmd(const struct bpf_token *token, enum bpf_cmd cmd)
{
	if (!token)
		return false;

	return token->allowed_cmds & (1ULL << cmd);
}

bool bpf_token_allow_map_type(const struct bpf_token *token, enum bpf_map_type type)
{
	if (!token || type >= __MAX_BPF_MAP_TYPE)
		return false;

	return token->allowed_maps & (1ULL << type);
}
