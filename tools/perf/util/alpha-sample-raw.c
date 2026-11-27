// SPDX-License-Identifier: GPL-2.0
/*
 * Alpha specific. Provide textual annotation for ProfileMe raw sample data.
 */

#include <stdio.h>
#include <string.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>

/* -Wpacked objects to the packed fields where __u64 is 4-byte aligned. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"
#include "../../arch/alpha/include/uapi/asm/perf_event.h"
#pragma GCC diagnostic pop

#include "evlist.h"
#include "evsel.h"
#include "sample-raw.h"
#include "util/sample.h"

/* I_STAT */
#define I_STAT_OVR(x)		(((x) >> 30) & 0x7)
#define I_STAT_ICM(x)		(((x) >> 33) & 0x1)
#define I_STAT_TRAP_TYPE(x)	(((x) >> 34) & 0xf)
#define I_STAT_LSO(x)		(((x) >> 38) & 0x1)
#define I_STAT_TRP(x)		(((x) >> 39) & 0x1)
#define I_STAT_MIS(x)		(((x) >> 40) & 0x1)

/* PCTR_CTL */
#define PCTR_CTL_TAK(x)		((x) & 0x1)
#define PCTR_CTL_VAL(x)		(((x) >> 1) & 0x1)
#define PCTR_CTL_SL1(x)		(((x) >> 2) & 0x3)
#define PCTR_CTL_SL0(x)		(((x) >> 4) & 0x1)
#define PCTR_CTL_PCTR1(x)	(((x) >> 6) & 0xfffff)
#define PCTR_CTL_KILLED(x)	(((x) >> 26) & 0x1)
#define PCTR_CTL_STALLED(x)	(((x) >> 27) & 0x1)
#define PCTR_CTL_PCTR0(x)	(((x) >> 28) & 0xfffff)

/* PMPC */
#define PMPC_PAL(x)		((x) & 0x1)
#define PMPC_PAL_OFFSET(x)	((x) & 0x7fff)

static const char * const trap_type_names[16] = {
	[0]  = "replay",
	[2]  = "DTB double miss (3 level)",
	[3]  = "DTB double miss (4 level)",
	[4]  = "FP disabled",
	[5]  = "unaligned",
	[6]  = "DTB single miss",
	[7]  = "Dstream fault",
	[8]  = "OPCDEC",
	[10] = "machine check",
	[12] = "arithmetic",
	[14] = "MT_FPCR",
	[15] = "reset",
};

/* What PCTR1 counts during the window, by SL1. */
static const char * const pctr1_names[4] = {
	"cycles",
	"retire delay",
	"bcache misses",
	"mbox replays",
};

/* TRP, and MIS and the trap type with it, are stale for a killed insn. */
static bool trapped(__u64 i_stat, __u64 ctl)
{
	return I_STAT_TRP(i_stat) && !PCTR_CTL_KILLED(ctl);
}

static const char *trap_name(__u64 i_stat, __u64 ctl, __u64 pmpc)
{
	const char *name;

	/* Redirect traps leave TRAP_TYPE alone and are named by PMPC. */
	if (PMPC_PAL(pmpc)) {
		switch (PMPC_PAL_OFFSET(pmpc)) {
		case 0x481:
			return "Istream access violation";
		case 0x581:
			return "ITB miss";
		case 0x681:
			return "interrupt";
		default:
			break;
		}
	}
	if (!trapped(i_stat, ctl) || I_STAT_MIS(i_stat))
		return "none";
	name = trap_type_names[I_STAT_TRAP_TYPE(i_stat)];
	return name ? name : "other (see PMPC)";
}

/*
 * Copy the payload out of the sample, since nothing guarantees its
 * alignment in the buffer, and convert it from the little-endian byte
 * order it was recorded in.
 */
static bool is_profileme_sample(struct evlist *evlist, union perf_event *event,
				struct perf_sample *sample,
				struct alpha_profileme_sample *pm)
{
	struct evsel *evsel;

	if (sample->raw_size < sizeof(*pm))
		return false;

	evsel = evlist__event2evsel(evlist, event);
	if (!evsel)
		return false;
	if (evsel->core.attr.type != PERF_TYPE_HARDWARE &&
	    evsel->core.attr.type != PERF_TYPE_RAW)
		return false;

	memcpy(pm, sample->raw_data, sizeof(*pm));
	pm->version = le32_to_cpu(pm->version);
	pm->pmpc = le64_to_cpu(pm->pmpc);
	pm->i_stat = le64_to_cpu(pm->i_stat);
	pm->pctr_ctl = le64_to_cpu(pm->pctr_ctl);

	return pm->version >= ALPHA_PROFILEME_SAMPLE_VERSION;
}

void evlist__alpha_sample_raw(struct evlist *evlist, union perf_event *event,
			      struct perf_sample *sample)
{
	struct alpha_profileme_sample pm;
	unsigned long long i_stat, ctl, pmpc;

	if (event->header.type != PERF_RECORD_SAMPLE ||
	    !is_profileme_sample(evlist, event, sample, &pm))
		return;

	i_stat = pm.i_stat;
	ctl = pm.pctr_ctl;
	pmpc = pm.pmpc;

	printf("ProfileMe PMPC:\t%016llx %s trap %s%s\n",
	       pmpc, PMPC_PAL(pmpc) ? "PAL" : (pmpc >> 63 ? "kernel" : "user"),
	       trap_name(i_stat, ctl, pmpc),
	       trapped(i_stat, ctl) && I_STAT_MIS(i_stat) ? " mispredicted" : "");
	printf("ProfileMe I_STAT:\t%016llx TRP %d MIS %d LSO %d TrapType %d ICM %d OVR %d\n",
	       i_stat, (int)I_STAT_TRP(i_stat), (int)I_STAT_MIS(i_stat),
	       (int)I_STAT_LSO(i_stat), (int)I_STAT_TRAP_TYPE(i_stat),
	       (int)I_STAT_ICM(i_stat), (int)I_STAT_OVR(i_stat));
	printf("ProfileMe PCTR_CTL:\t%016llx VAL %d TAK %d Stalled %d Killed %d",
	       ctl, (int)PCTR_CTL_VAL(ctl), (int)PCTR_CTL_TAK(ctl),
	       (int)PCTR_CTL_STALLED(ctl), (int)PCTR_CTL_KILLED(ctl));
	printf(" SL0 %d SL1 %d PCTR0 %d PCTR1 %d (%s)\n",
	       (int)PCTR_CTL_SL0(ctl), (int)PCTR_CTL_SL1(ctl),
	       (int)PCTR_CTL_PCTR0(ctl), (int)PCTR_CTL_PCTR1(ctl),
	       pctr1_names[PCTR_CTL_SL1(ctl)]);
}
