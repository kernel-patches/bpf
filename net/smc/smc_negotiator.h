/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Support eBPF for Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Author(s):  D. Wythe <alibuda@linux.alibaba.com>
 */

#include <linux/types.h>
#include <net/smc.h>

/* Max length of negotiator name */
#define SMC_NEGOTIATOR_NAME_MAX	(16)

/* closing time */
#define SMC_SOCK_CLOSED_TIMING	(0)

#ifdef CONFIG_SMC_BPF

/* Register a new SMC socket negotiator ops
 * The registered ops can then be assigned to SMC sockets using
 * smc_sock_assign_negotiator_ops() via name
 * Return: 0 on success, negative error code on failure
 */
int smc_sock_register_negotiator_ops(struct smc_sock_negotiator_ops *ops);

/* Update an existing SMC socket negotiator ops
 * This function is used to update an existing SMC socket negotiator ops. The new ops will
 * replace the old ops who has the same name.
 * Return: 0 on success, negative error code on failure.
 */
int smc_sock_update_negotiator_ops(struct smc_sock_negotiator_ops *ops,
				   struct smc_sock_negotiator_ops *old_ops);

/* Validate SMC negotiator operations
 * This function is called to validate an SMC negotiator operations structure
 * before it is assigned to a socket. It checks that all necessary function
 * pointers are defined and not null.
 * Returns 0 if the @ops argument is valid, or a negative error code otherwise.
 */
int smc_sock_validate_negotiator_ops(struct smc_sock_negotiator_ops *ops);

/* Unregister an SMC socket negotiator ops
 * This function is used to unregister an existing SMC socket negotiator ops.
 * The ops will no longer be available for assignment to SMC sockets immediately.
 */
void smc_sock_unregister_negotiator_ops(struct smc_sock_negotiator_ops *ops);

/* Get registered negotiator ops via name, caller should invoke it
 * with RCU protected.
 */
struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_name(const char *name);

/* Assign a negotiator ops to an SMC socket
 * This function is used to assign a negotiator ops to an SMC socket.
 * The ops must have been previously registered with
 * smc_sock_register_negotiator_ops().
 * Return: 0 on success, negative error code on failure.
 */
int smc_sock_assign_negotiator_ops(struct smc_sock *smc, const char *name);

/* Remove negotiator ops who had assigned to @smc.
 * @no_more implies that the caller explicitly states that the @smc have no references
 * to the negotiator ops to be removed. This is not a mandatory option.
 * When it sets to false, we will use RCU to protect ops, but in this case we have to
 * always call synchronize_rcu(), which has a significant performance impact.
 */
void smc_sock_cleanup_negotiator_ops(struct smc_sock *smc, bool no_more);

/* Clone negotiator ops of parnet sock to
 * child sock.
 */
void smc_sock_clone_negotiator_ops(struct sock *parent, struct sock *child);

/* Check if sock should use smc */
int smc_sock_should_select_smc(const struct smc_sock *smc);

/* Collect information to assigned ops */
void smc_sock_perform_collecting_info(const struct smc_sock *smc, int timing);

#else
static inline int smc_sock_register_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	return 0;
}

static inline int smc_sock_update_negotiator_ops(struct smc_sock_negotiator_ops *ops,
						 struct smc_sock_negotiator_ops *old_ops)
{
	return 0;
}

static inline int smc_sock_validate_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	return 0;
}

static inline void smc_sock_unregister_negotiator_ops(struct smc_sock_negotiator_ops *ops) {}

static inline struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_name(const char *name)
{
	return NULL;
}

static inline int smc_sock_assign_negotiator_ops(struct smc_sock *smc, const char *name)
{
	return -EOPNOTSUPP;
}

static inline void smc_sock_cleanup_negotiator_ops(struct smc_sock *smc, bool no_more) {}

static inline void smc_sock_clone_negotiator_ops(struct sock *parent, struct sock *child) {}

static inline int smc_sock_should_select_smc(const struct smc_sock *smc) { return SK_PASS; }

static inline void smc_sock_perform_collecting_info(const struct smc_sock *smc, int timing) {}
#endif
