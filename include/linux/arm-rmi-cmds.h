/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#ifndef __LINUX_ARM_RMI_CMDS_H_
#define __LINUX_ARM_RMI_CMDS_H_

#include <linux/arm-smccc-rmi.h>
#include <linux/bug.h>
#include <linux/gfp.h>
#include <linux/processor.h>
#include <linux/string.h>
#include <linux/types.h>

#define RMI_MAX_ADDR_LIST	256

struct rmi_sro_state {
	struct arm_smccc_1_2_regs regs;
	int addr_count;
	unsigned long addr_list[RMI_MAX_ADDR_LIST];
};

#define RMM_BLOCKED_RETRY_COUNT		2
/*
 * rmi_smccc_invoke: Invoke the RMI call and return the results, retrying the
 * command when status is RMI_BUSY. If we encounter RMI_BLOCKED, we retry
 * it one more time before we give up. The caller is supposed to handle the
 * result and reissue if required.
 *
 * We don't expect to see RMI_BLOCKED on a practical system, except when
 * there are parallel requests that results in long standing operation,
 * with one blocking the other.
 *
 * @regs: Input parameters filled in. Updated with the output results
 * after the call.
 */
static inline void rmi_smccc_invoke(struct arm_smccc_1_2_regs *regs)
{
	struct arm_smccc_1_2_regs args = *regs;
	long status;
	int i = 0;

	while (i < RMM_BLOCKED_RETRY_COUNT) {
		arm_smccc_1_2_smc(&args, regs);

		status = RMI_RESULT_STATUS(regs->a0);
		if (status != RMI_BUSY && status != RMI_BLOCKED)
			break;
		if (status == RMI_BLOCKED)
			i++;
		cpu_relax();
	}
}

unsigned long rmi_feat_reg(unsigned int index);

int rmi_delegate_range(phys_addr_t phys, unsigned long size,
		       phys_addr_t *out_phys);
int rmi_undelegate_range(phys_addr_t phys, unsigned long size);
int rmi_free_delegated_page(phys_addr_t phys);

static inline int rmi_delegate_page(phys_addr_t phys)
{
	return rmi_delegate_range(phys, PAGE_SIZE, NULL);
}

static inline int rmi_undelegate_page(phys_addr_t phys)
{
	return rmi_undelegate_range(phys, PAGE_SIZE);
}

long rmi_sro_memxfer_execute(struct rmi_sro_state *sro, gfp_t gfp);
void rmi_sro_free(struct rmi_sro_state *sro);
long rmi_sro_execute(struct arm_smccc_1_2_regs *regs);

/*
 * Resetting the addr_count is sufficient to ignore the addr_list contents.
 */
#define rmi_sro_memxfer_cmd(sro, gfp, ...) ({				\
	struct rmi_sro_state *__sro = (sro);				\
	__sro->addr_count = 0;						\
	__sro->regs = (struct arm_smccc_1_2_regs){ __VA_ARGS__ };	\
	long __ret = rmi_sro_memxfer_execute(__sro, gfp);		\
	rmi_sro_free(__sro);						\
	__ret;								\
})

#ifdef CONFIG_ARM_RMM_RMI

bool is_rmm_active(void);
bool is_rmi_available(void);

#else

static inline bool is_rmm_active(void)
{
	return false;
}

static inline bool is_rmi_available(void)
{
	return false;
}
#endif	/* CONFIG_ARM_RMM_RMI */

#endif	/* __LINUX_ARM_RMI_CMDS_H_ */
