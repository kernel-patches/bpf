/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#ifndef __LINUX_ARM_RMI_CMDS_H_
#define __LINUX_ARM_RMI_CMDS_H_

#include <linux/arm-smccc-rmi.h>
#include <linux/bug.h>
#include <linux/processor.h>
#include <linux/types.h>

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

#endif	/* __LINUX_ARM_RMI_CMDS_H_ */
