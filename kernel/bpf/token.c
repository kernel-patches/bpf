#include <linux/bpf.h>
#include <linux/vmalloc.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/namei.h>

DEFINE_IDR(token_idr);
DEFINE_SPINLOCK(token_idr_lock);

void bpf_token_inc(struct bpf_token *token)
{
	atomic64_inc(&token->refcnt);
}

static void bpf_token_put_deferred(struct work_struct *work)
{
	struct bpf_token *token = container_of(work, struct bpf_token, work);

	kvfree(token);
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

static const struct file_operations bpf_token_fops = {
	.release	= bpf_token_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
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

static bool is_bit_subset_of(u32 subset, u32 superset)
{
	return (superset & subset) == subset;
}

int bpf_token_create(union bpf_attr *attr)
{
	struct bpf_token *new_token, *token = NULL;
	int ret;

	if (attr->token_create.token_fd) {
		token = bpf_token_get_from_fd(attr->token_create.token_fd);
		if (IS_ERR(token))
			return PTR_ERR(token);
		/* if provided BPF token doesn't allow creating new tokens,
		 * then use system-wide capability checks only
		 */
		if (!bpf_token_allow_cmd(token, BPF_TOKEN_CREATE)) {
			bpf_token_put(token);
			token = NULL;
		}
	}

	ret = -EPERM;
	if (!bpf_token_capable(token, CAP_SYS_ADMIN))
		goto out;

	/* requested cmds should be a subset of associated token's set */
	if (token && !is_bit_subset_of(attr->token_create.allowed_cmds, token->allowed_cmds))
		goto out;
	/* requested map types should be a subset of associated token's set */
	if (token && !is_bit_subset_of(attr->token_create.allowed_map_types,
				       token->allowed_map_types))
		goto out;

	new_token = bpf_token_alloc();
	if (!new_token) {
		ret = -ENOMEM;
		goto out;
	}

	new_token->allowed_cmds = attr->token_create.allowed_cmds;
	new_token->allowed_map_types = attr->token_create.allowed_map_types;

	ret = bpf_obj_pin_any(attr->token_create.pin_path_fd,
			      u64_to_user_ptr(attr->token_create.pin_pathname),
			      new_token, BPF_TYPE_TOKEN);
	if (ret < 0)
		bpf_token_put(new_token);
out:
	bpf_token_put(token);
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

	return token->allowed_map_types & (1ULL << type);
}
