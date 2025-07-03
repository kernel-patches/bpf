/*
 * Copyright 2025 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#ifndef __IRQSRCS_GFX_13_0_1_H__
#define __IRQSRCS_GFX_13_0_1_H__

#define GFX_13_0_1__SRCID__UTCL2_FAULT 				0	// 0x0 UTCL2 has encountered a fault scenario
#define GFX_13_0_1__SRCID__UTCL2_RETRY 				1	// 0x1 UTCL2 has encountered a retry scenario
#define GFX_13_0_1__SRCID__UTCL2_DATA_POISONING 		2	// 0x2 UTCL2 for data poisoning
#define GFX_13_0_1__SRCID__UTCL2_Halt_On_Access 		3	// 0x3 UTCL2 Halt on Access
#define GFX_13_0_1__SRCID__SDMA_ATOMIC_RTN_DONE			48	// 0x30 SDMA atomic*_rtn ops complete
#define GFX_13_0_1__SRCID__SDMA_TRAP				49	// 0x31 Trap
#define GFX_13_0_1__SRCID__SDMA_SRBMWRITE			50	// 0x32 SRBM write Protection
#define GFX_13_0_1__SRCID__SDMA_CTXEMPTY			51	// 0x33 Context Empty
#define GFX_13_0_1__SRCID__SDMA_PREEMPT				52	// 0x34 SDMA New Run List
#define GFX_13_0_1__SRCID__SDMA_IB_PREEMPT			53	// 0x35 sdma mid - command buffer preempt interrupt
#define GFX_13_0_1__SRCID__SDMA_DOORBELL_INVALID		54	// 0x36 Doorbell BE invalid
#define GFX_13_0_1__SRCID__SDMA_QUEUE_HANG			55	// 0x37 Queue hang or Command timeout
#define GFX_13_0_1__SRCID__SDMA_ATOMIC_TIMEOUT			56	// 0x38 SDMA atomic CMPSWAP loop timeout
#define GFX_13_0_1__SRCID__SDMA_POLL_TIMEOUT			57	// 0x39 SRBM read poll timeout
#define GFX_13_0_1__SRCID__SDMA_PAGE_TIMEOUT			58	// 0x3A Page retry  timeout after UTCL2 return nack = 1
#define GFX_13_0_1__SRCID__SDMA_PAGE_NULL			59	// 0x3B Page Null from UTCL2 when nack = 2
#define GFX_13_0_1__SRCID__SDMA_PAGE_FAULT			60	// 0x3C Page Fault Error from UTCL2 when nack = 3
#define GFX_13_0_1__SRCID__SDMA_VM_HOLE				61	// 0x3D MC or SEM address in VM hole
#define GFX_13_0_1__SRCID__SDMA_ECC				62	// 0x3E ECC Error
#define GFX_13_0_1__SRCID__SDMA_FROZEN				63	// 0x3F SDMA Frozen
#define GFX_13_0_1__SRCID__SDMA_SRAM_ECC			64	// 0x40 SRAM ECC Error
#define GFX_13_0_1__SRCID__SDMA_SEM_INCOMPLETE_TIMEOUT		65	// 0x41 GPF(Sem incomplete timeout)
#define GFX_13_0_1__SRCID__SDMA_SEM_WAIT_FAIL_TIMEOUT		66	// 0x42 Semaphore wait fail timeout
#define GFX_13_0_1__SRCID__SDMA_FENCE				70	// 0x46 User fence
#define GFX_13_0_1__SRCID__CP_RB_INTERRUPT 			176	// 0xB0 CP_INTERRUPT pkt in RB
#define GFX_13_0_1__SRCID__CP_IB1_INTERRUPT 			177	// 0xB1 CP_INTERRUPT pkt in IB1
#define GFX_13_0_1__SRCID__CP_IB2_INTERRUPT 			178	// 0xB2 CP_INTERRUPT pkt in IB1
#define GFX_13_0_1__SRCID__CP_DMA_WATCH_INTERRUPT 		179	// 0xB3 CP DMA Watch interrupt
#define GFX_13_0_1__SRCID__CP_PM4_PKT_RSVD_BIT_ERROR		180	// 0xB4 PM4 Pkt Rsvd Bits Error
#define GFX_13_0_1__SRCID__CP_EOP_INTERRUPT			181	// 0xB5 End-of-Pipe Interrupt
#define GFX_13_0_1__SRCID__CP_BAD_OPCODE_ERROR			183	// 0xB7 Bad Opcode Error
#define GFX_13_0_1__SRCID__CP_PRIV_REG_FAULT			184	// 0xB8 Privileged Register Fault
#define GFX_13_0_1__SRCID__CP_PRIV_INSTR_FAULT			185	// 0xB9 Privileged Instr Fault
#define GFX_13_0_1__SRCID__CP_WAIT_MEM_SEM_FAULT		186	// 0xBA Wait Memory Semaphore Fault (Sync Object Fault)
#define GFX_13_0_1__SRCID__CP_CTX_EMPTY_INTERRUPT		187	// 0xBB Context Empty Interrupt
#define GFX_13_0_1__SRCID__CP_CTX_BUSY_INTERRUPT		188	// 0xBC Context Busy Interrupt
#define GFX_13_0_1__SRCID__CP_ME_WAIT_REG_MEM_POLL_TIMEOUT	192	// 0xC0 CP.ME Wait_Reg_Mem Poll Timeout
#define GFX_13_0_1__SRCID__CP_SIG_INCOMPLETE			193	// 0xC1 "Surface Probe Fault Signal Incomplete"
#define GFX_13_0_1__SRCID__CP_PREEMPT_ACK			194	// 0xC2 Preemption Ack-wledge
#define GFX_13_0_1__SRCID__CP_GPF				195	// 0xC3 General Protection Fault (GPF)
#define GFX_13_0_1__SRCID__CP_GDS_ALLOC_ERROR			196	// 0xC4 GDS Alloc Error
#define GFX_13_0_1__SRCID__CP_ECC_ERROR				197	// 0xC5 ECC  Error
#define GFX_13_0_1__SRCID__CP_VM_DOORBELL			200	// 0xC8 Unattached VM Doorbell Received
#define GFX_13_0_1__SRCID__CP_FUE_ERROR				201	// 0xC9 ECC FUE Error
#define GFX_13_0_1__SRCID__CP_SUSPEND_REQ_INTERRUPT 		202	// 0xCA CP Suspend Completion interrupt
#define GFX_13_0_1__SRCID__CP_RESUME_REQ_INTERRUPT 		203	// 0xCB CP Resume Completion Interrupt
#define GFX_13_0_1__SRCID__RLC_STRM_PERF_MONITOR_INTERRUPT	202	// 0xCA RLC Streaming Perf Monitor Interrupt
#define GFX_13_0_1__SRCID__GRBM_RD_TIMEOUT_ERROR		232	// 0xE8 CRead timeout error
#define GFX_13_0_1__SRCID__GRBM_REG_GUI_IDLE			233	// 0xE9 Register GUI Idle
#define GFX_13_0_1__SRCID__SQ_INTERRUPT_ID			239	// 0xEF SQ Interrupt (ttrace wrap, errors)

#endif
