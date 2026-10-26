// SPDX-License-Identifier: GPL-2.0
/*
 * Cache error handling for the R10000, R12000, R14000 and R16000.
 *
 * Copyright (C) 2026 Imre Kaloz <kaloz@kernel.org>
 */
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/hardirq.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/panic.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/sched/debug.h>
#include <linux/smp.h>

#include <asm/mipsregs.h>
#include <asm/ptrace.h>
#include <asm/traps.h>

#define CE_UNIT		GENMASK(31, 30)
#define CE_UNIT_I	0
#define CE_UNIT_D	1
#define CE_UNIT_S	2
#define CE_UNIT_SYS	3
#define CE_EW		BIT(29)		/* second error before one was taken */
#define CE_EE		BIT(28)		/* D-cache, system interface */
#define CE_D		GENMASK(27, 26)	/* data array, way 1 and way 0 */
#define CE_TA		GENMASK(25, 24)	/* tag address array */
#define CE_TS		GENMASK(23, 22)	/* tag state array */
#define CE_TM		GENMASK(21, 20)	/* D-cache tag mod array */
#define CE_SA		BIT(25)		/* system address bus */
#define CE_SC		BIT(24)		/* system command bus */
#define CE_SR		BIT(23)		/* system response bus */
#define CE_IIDX		GENMASK(13, 6)
#define CE_DIDX		GENMASK(13, 3)
#define CE_SIDX		GENMASK(22, 6)

/* A line that keeps failing would otherwise be refetched forever. */
#define CE_STORM	10

struct cerr_r10k {
	unsigned long count;
	unsigned long window;
	unsigned int recent;
	bool active;
};

static DEFINE_PER_CPU(struct cerr_r10k, cerr_r10k);
static DEFINE_RATELIMIT_STATE(cerr_r10k_rs, 5 * HZ, 10);

static void cerr_r10k_decode(char *buf, size_t len, u32 cerr)
{
	const char *ew = cerr & CE_EW ? ", EW" : "";
	const char *ee = cerr & CE_EE ? ", EE" : "";

	switch (FIELD_GET(CE_UNIT, cerr)) {
	case CE_UNIT_I:
		scnprintf(buf, len,
			  "I-cache error %08x: data %lu tag %lu state %lu, index %#lx%s",
			  cerr, FIELD_GET(CE_D, cerr), FIELD_GET(CE_TA, cerr),
			  FIELD_GET(CE_TS, cerr), cerr & CE_IIDX, ew);
		break;
	case CE_UNIT_D:
		scnprintf(buf, len,
			  "D-cache error %08x: data %lu tag %lu state %lu mod %lu, index %#lx%s%s",
			  cerr, FIELD_GET(CE_D, cerr), FIELD_GET(CE_TA, cerr),
			  FIELD_GET(CE_TS, cerr), FIELD_GET(CE_TM, cerr),
			  cerr & CE_DIDX, ee, ew);
		break;
	case CE_UNIT_S:
		scnprintf(buf, len,
			  "S-cache error %08x: data %lu tag %lu, index %#lx%s",
			  cerr, FIELD_GET(CE_D, cerr), FIELD_GET(CE_TA, cerr),
			  cerr & CE_SIDX, ew);
		break;
	default:
		scnprintf(buf, len,
			  "system interface error %08x: data %lu%s%s%s, index %#lx%s%s",
			  cerr, FIELD_GET(CE_D, cerr),
			  cerr & CE_SA ? ", address" : "",
			  cerr & CE_SC ? ", command" : "",
			  cerr & CE_SR ? ", response" : "",
			  cerr & CE_SIDX, ee, ew);
		break;
	}
}

/*
 * Only I-cache errors are recovered, by the set rewrite in the entry code;
 * every other cache error is fatal.
 */
asmlinkage void do_cache_error_r10k(struct pt_regs *regs, int resumable)
{
	struct cerr_r10k *ce = this_cpu_ptr(&cerr_r10k);
	unsigned long errorepc = read_c0_errorepc();
	u32 cerr = read_c0_cacheerr();
	const char *why = "Unrecoverable cache error";
	char desc[112];

	if (!resumable) {
		why = "Cache error in an exception handler";
		goto fatal;
	}
	if (FIELD_GET(CE_UNIT, cerr) != CE_UNIT_I || (cerr & CE_EW))
		goto fatal;
	if (ce->active) {
		why = "Nested cache error";
		goto fatal;
	}
	if (time_after(jiffies, ce->window + HZ)) {
		ce->window = jiffies;
		ce->recent = 0;
	}
	if (++ce->recent > CE_STORM) {
		why = "Cache error storm";
		goto fatal;
	}

	ce->active = true;
	nmi_enter();
	ce->count++;
	if (__ratelimit(&cerr_r10k_rs)) {
		cerr_r10k_decode(desc, sizeof(desc), cerr);
		pr_warn("CPU%u: %s, ErrorEPC %pS: recovered, %lu so far\n",
			smp_processor_id(), desc, (void *)errorepc, ce->count);
	}
	nmi_exit();
	ce->active = false;
	return;

fatal:
	set_c0_status(ST0_DE);
	cerr_r10k_decode(desc, sizeof(desc), cerr);
	pr_emerg("CPU%u: %s, ErrorEPC %pS\n", smp_processor_id(), desc,
		 (void *)errorepc);
	show_regs(regs);
	panic("%s", why);
}
