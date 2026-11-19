// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test vsie validity interceptions raised while the shadow SCB is set up.
 *
 * A validity interception raised by prepare_cpuflags() happens before any
 * guest 3 state is copied into the shadow SCB. Only icptcode, ipa and ipb
 * may change in the guest 2 SCB; the guest 3 state, icptstatus and ihcpu
 * must not be overwritten with the contents of the shadow SCB.
 */
#include <stdio.h>
#include <string.h>

#include "kvm_util.h"
#include "test_util.h"
#include "kselftest.h"
#include "sie.h"
#include "facility.h"
#include "ucall_common.h"

#define G3_MEM_LEN	0x100000UL
/* mso/msl have 1MB granularity */
#define G3_MSO		0x10000000UL

#define FAC_CRYPTO_KEYS	76
#define FAC_GED2	78

#define ADDR_BELOW_2_PAGES	0x1000UL

#define G3_START	(2 * 0x1000UL)
#define G3_CODE_LEN	12

static u64 scb_real;

static void guest_code(void)
{
	while (1) {
		asm volatile("	sie	0(%[scb])\n"
			     :
			     : [scb] "a" (scb_real)
			     : "memory", "cc");
		GUEST_SYNC(0);
	}
}

struct ctx {
	struct kvm_s390_sie_block *scb;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	u64 scb_real;
	void *code;
};

static void get_machine_feat(struct kvm_s390_vm_cpu_feat *feat)
{
	struct kvm_vm *vm = vm_create_barebones();

	kvm_device_attr_get(vm->fd, KVM_S390_VM_CPU_MODEL,
			    KVM_S390_VM_CPU_MACHINE_FEAT, feat);
	kvm_vm_free(vm);
}

static int machine_has_sief2(void)
{
	struct kvm_s390_vm_cpu_feat feat = {};

	get_machine_feat(&feat);
	return !!(feat.feat[0] & (1ULL << (63 - KVM_S390_VM_CPU_FEAT_SIEF2)));
}

static bool machine_has_facility(int nr)
{
	struct kvm_s390_vm_cpu_processor proc = {};
	struct kvm_vm *vm = vm_create_barebones();
	bool ret;

	kvm_device_attr_get(vm->fd, KVM_S390_VM_CPU_MODEL,
			    KVM_S390_VM_CPU_PROCESSOR, &proc);
	ret = test_bit_inv(nr, (unsigned long *)proc.fac_list);
	kvm_vm_free(vm);
	return ret;
}

/*
 * Without the prefix pages mapped, vsie cannot shadow them and raises
 * validity 0x0037.
 */
static struct ctx *ctx_create(bool map_prefix)
{
	struct kvm_s390_vm_cpu_feat feat = {};
	struct ctx *c = calloc(1, sizeof(*c));
	gva_t scb_gva;
	int i;

	/* SIEF2 must be enabled before the first vcpu is created */
	get_machine_feat(&feat);

	c->vm = vm_create(1);
	kvm_device_attr_set(c->vm->fd, KVM_S390_VM_CPU_MODEL,
			    KVM_S390_VM_CPU_PROCESSOR_FEAT, &feat);
	c->vcpu = vm_vcpu_add(c->vm, 0, guest_code);

	scb_gva = vm_alloc_page(c->vm);
	c->scb = addr_gva2hva(c->vm, scb_gva);
	memset(c->scb, 0, getpagesize());
	c->scb_real = addr_gva2gpa(c->vm, scb_gva);
	scb_real = c->scb_real;
	sync_global_to_guest(c->vm, scb_real);

	for (i = 0; i < 3; i++) {
		gpa_t gpa;

		if (i < 2 && !map_prefix)
			continue;
		gpa = vm_phy_page_alloc(c->vm, MEM_REGION_TEST_DATA);
		virt_pg_map(c->vm, G3_MSO + i * getpagesize(), gpa);
		if (i == 2)
			c->code = addr_gpa2hva(c->vm, gpa);
	}
	return c;
}

static void ctx_destroy(struct ctx *c)
{
	kvm_vm_free(c->vm);
	free(c);
}

static void run_sie(struct ctx *c)
{
	struct ucall uc;

	vcpu_run(c->vcpu);
	TEST_ASSERT_EQ(get_ucall(c->vcpu, &uc), UCALL_SYNC);
}

static void setup_guest3(struct ctx *c)
{
	static const u8 g3_code[G3_CODE_LEN] = {
		0xc6, 0x00, 0x00, 0x00, 0x00, 0x04,	/* exrl %r0,.+8 */
		0x07, 0x07,
		0x83, 0x00, 0x00, 0x44,			/* diag %r0,%r0,0x44 */
	};

	memcpy(c->code, g3_code, sizeof(g3_code));
	memset(c->scb, 0, sizeof(*c->scb));
	c->scb->cpuflags = CPUSTAT_ZARCH | CPUSTAT_RUNNING;
	c->scb->ihcpu = 0xffff;
	c->scb->mso = G3_MSO;
	c->scb->msl = G3_MSO + ((G3_MEM_LEN - 1) & ~0xfffffUL);
	c->scb->psw_mask = 0x180000000ULL;
	c->scb->psw_addr = G3_START;
	c->scb->gg14 = 0xccccccccccccccccULL;
	c->scb->gg15 = 0xddddddddddddddddULL;
	c->scb->gcr[0] = 0x40000;
	c->scb->cputm = 0x00ffffffffffffffULL;
	c->scb->ckc = 0x00eeeeeeeeeeeeeeULL;
	c->scb->todpr = 0x12345678;
	c->scb->pp = 0x0badc0de0badc0deULL;
	c->scb->gbea = 0x0123456789abcdefULL;
	c->scb->fpf = FPF_BPBC;
}

/* The intercept is reported for the EXECUTE target and sets icptstatus. */
static void run_guest3(struct ctx *c)
{
	setup_guest3(c);
	run_sie(c);
	TEST_ASSERT(c->scb->icptcode == ICPT_INST,
		    "guest 3 run: icptcode 0x%02x ipa 0x%04x ipb 0x%08x",
		    c->scb->icptcode, c->scb->ipa, c->scb->ipb);
	TEST_ASSERT(c->scb->icptstatus,
		    "guest 3 run: expected a non-zero icptstatus, got 0");
}

static void fill_state(struct kvm_s390_sie_block *s, u64 seed)
{
	int i;

	s->psw_mask = 0x1111111111111111ULL ^ seed;
	s->psw_addr = 0x2222222222222222ULL ^ seed;
	s->gg14 = 0x4444444444444444ULL ^ seed;
	s->gg15 = 0x5555555555555555ULL ^ seed;
	for (i = 0; i < 16; i++)
		s->gcr[i] = 0x1000000000000000ULL + i + seed;
	s->cputm = 0x6666666666666666ULL ^ seed;
	s->ckc = 0x7777777777777777ULL ^ seed;
	s->todpr = 0x88888888 ^ (u32)seed;
	s->pp = 0x9999999999999999ULL ^ seed;
	s->gbea = 0x3333333333333333ULL ^ seed;
	s->fpf = FPF_BPBC;
	s->ihcpu = 0x7b3d ^ (u16)seed;
}

static int field_changed(const char *name, const void *act, const void *exp,
			 size_t len)
{
	if (!memcmp(act, exp, len))
		return 0;

	ksft_print_msg("%s changed unexpectedly\n", name);
	return 1;
}

/*
 * icptstatus is not set by a validity interception raised by vsie itself and
 * must not carry over from an earlier interception of a cached shadow SCB.
 */
static int check_preserved(struct kvm_s390_sie_block *act,
			   struct kvm_s390_sie_block *saved)
{
	struct kvm_s390_sie_block exp = *saved;
	int bad = 0;

	exp.icptcode = act->icptcode;
	exp.ipa = act->ipa;
	exp.ipb = act->ipb;

	if (act->icptstatus) {
		ksft_print_msg("icptstatus 0x%02x, expected 0\n", act->icptstatus);
		bad++;
	}
	exp.icptstatus = act->icptstatus;

	bad += field_changed("psw_mask", &act->psw_mask, &exp.psw_mask,
			     sizeof(exp.psw_mask));
	bad += field_changed("psw_addr", &act->psw_addr, &exp.psw_addr,
			     sizeof(exp.psw_addr));
	bad += field_changed("gg14", &act->gg14, &exp.gg14, sizeof(exp.gg14));
	bad += field_changed("gg15", &act->gg15, &exp.gg15, sizeof(exp.gg15));
	bad += field_changed("gcr", act->gcr, exp.gcr, sizeof(exp.gcr));
	bad += field_changed("cputm", &act->cputm, &exp.cputm,
			     sizeof(exp.cputm));
	bad += field_changed("ckc", &act->ckc, &exp.ckc, sizeof(exp.ckc));
	bad += field_changed("todpr", &act->todpr, &exp.todpr,
			     sizeof(exp.todpr));
	bad += field_changed("pp", &act->pp, &exp.pp, sizeof(exp.pp));
	bad += field_changed("gbea", &act->gbea, &exp.gbea, sizeof(exp.gbea));
	bad += field_changed("fpf", &act->fpf, &exp.fpf, sizeof(exp.fpf));
	bad += field_changed("ihcpu", &act->ihcpu, &exp.ihcpu,
			     sizeof(exp.ihcpu));

	if (!bad && memcmp(&exp, act, sizeof(exp))) {
		ksft_print_msg("SCB modified outside the checked fields\n");
		bad++;
	}
	return bad;
}

static int check_validity(struct kvm_s390_sie_block *scb, u16 reason)
{
	if (scb->icptcode == ICPT_VALIDITY && scb->ipa == 0x1000 &&
	    (scb->ipb >> 16) == reason)
		return 0;

	ksft_print_msg("expected validity 0x%04x, got icptcode 0x%02x ipa 0x%04x ipb 0x%08x\n",
		       reason, scb->icptcode, scb->ipa, scb->ipb);
	return 1;
}

static int run_early_validity(struct ctx *c, u32 cpuflags, u16 reason, u64 seed)
{
	struct kvm_s390_sie_block saved;

	fill_state(c->scb, seed);
	c->scb->cpuflags = cpuflags | CPUSTAT_RUNNING;
	saved = *c->scb;

	run_sie(c);
	return check_validity(c->scb, reason) + check_preserved(c->scb, &saved);
}

static int test_new_page(int cpuflags)
{
	struct ctx *c = ctx_create(true);
	u16 reason = 0x0001;
	int bad;

	if (cpuflags & CPUSTAT_SLSV)
		reason = 0x0007;
	bad = run_early_validity(c, cpuflags, reason, cpuflags);
	ctx_destroy(c);
	return bad;
}

static int test_cached(int unused)
{
	struct ctx *c = ctx_create(true);
	int bad;

	run_guest3(c);
	bad = run_early_validity(c, CPUSTAT_ZARCH | CPUSTAT_RRF, 0x0001,
				 0xa5a5a5a5a5a5a5a5ULL);

	run_guest3(c);
	ctx_destroy(c);
	return bad;
}

static int test_writeback(int unused)
{
	struct ctx *c = ctx_create(true);
	struct kvm_s390_sie_block saved;
	int bad = 0;

	setup_guest3(c);
	saved = *c->scb;
	run_sie(c);

	if (c->scb->icptcode != ICPT_INST || c->scb->ipa != 0x8300) {
		ksft_print_msg("expected DIAG intercept, got icptcode 0x%02x ipa 0x%04x\n",
			       c->scb->icptcode, c->scb->ipa);
		bad++;
	}
	if (!c->scb->icptstatus) {
		ksft_print_msg("expected icptstatus of the EXECUTE target, got 0\n");
		bad++;
	}
	if (c->scb->psw_addr <= G3_START ||
	    c->scb->psw_addr > G3_START + G3_CODE_LEN) {
		ksft_print_msg("psw_addr 0x%llx, expected 0x%lx < addr <= 0x%lx\n",
			       c->scb->psw_addr, G3_START, G3_START + G3_CODE_LEN);
		bad++;
	}
	if (c->scb->gg14 != saved.gg14 || c->scb->gg15 != saved.gg15 ||
	    memcmp(c->scb->gcr, saved.gcr, sizeof(saved.gcr))) {
		ksft_print_msg("gg14, gg15 or gcr differ from what guest 3 ran with\n");
		bad++;
	}
	ctx_destroy(c);
	return bad;
}

/*
 * Late validity interceptions are raised after the state was shadowed, so
 * unshadow_scb() copies it back and must not alter what guest 2 provided.
 */
static int test_late_crycb(int cached)
{
	struct ctx *c = ctx_create(true);
	struct kvm_s390_sie_block saved;
	int bad;

	if (cached)
		run_guest3(c);

	fill_state(c->scb, 0x5a5a5a5a5a5a5a5aULL);
	c->scb->cpuflags = CPUSTAT_ZARCH | CPUSTAT_RUNNING;
	c->scb->crycbd = CRYCB_FORMAT1;
	saved = *c->scb;

	run_sie(c);
	bad = check_validity(c->scb, 0x0039) + check_preserved(c->scb, &saved);
	ctx_destroy(c);
	return bad;
}

static int test_late_pin_blocks(int unused)
{
	struct ctx *c = ctx_create(true);
	struct kvm_s390_sie_block saved;
	int bad;

	fill_state(c->scb, 0x6b6b6b6b6b6b6b6bULL);
	c->scb->cpuflags = CPUSTAT_ZARCH | CPUSTAT_RUNNING;
	c->scb->scaol = ADDR_BELOW_2_PAGES;
	saved = *c->scb;

	run_sie(c);
	bad = check_validity(c->scb, 0x0038) + check_preserved(c->scb, &saved);
	ctx_destroy(c);
	return bad;
}

static int test_prefix_unmapped(int unused)
{
	struct ctx *c = ctx_create(false);
	struct kvm_s390_sie_block saved;
	int bad;

	setup_guest3(c);
	saved = *c->scb;

	run_sie(c);
	bad = check_validity(c->scb, 0x0037) + check_preserved(c->scb, &saved);
	ctx_destroy(c);
	return bad;
}

static const struct testdef {
	const char *name;
	int (*test)(int arg);
	int arg;
	int facility;
} testlist[] = {
	{ "early validity icpt (RRF) with a new vsie page", test_new_page,
	  CPUSTAT_ZARCH | CPUSTAT_RRF },
	{ "early validity icpt (SLSV) with a new vsie page", test_new_page,
	  CPUSTAT_ZARCH | CPUSTAT_SLSV },
	{ "early validity icpt (GED+GED2) with a new vsie page", test_new_page,
	  CPUSTAT_ZARCH | CPUSTAT_GED | CPUSTAT_GED2, FAC_GED2 },
	{ "early validity icpt (ESA mode) with a new vsie page", test_new_page, 0 },
	{ "early validity icpt with a cached vsie page", test_cached },
	{ "valid guest 3 has its state written back", test_writeback },
	{ "late validity icpt (CRYCB) with a new vsie page", test_late_crycb, 0,
	  FAC_CRYPTO_KEYS },
	{ "late validity icpt (CRYCB) with a cached vsie page", test_late_crycb, 1,
	  FAC_CRYPTO_KEYS },
	{ "late validity icpt (pin_blocks)", test_late_pin_blocks },
	{ "late validity icpt (prefix not mapped)", test_prefix_unmapped },
};

int main(int argc, char *argv[])
{
	int idx, bad;

	TEST_REQUIRE(machine_has_sief2());

	ksft_print_header();

	ksft_set_plan(ARRAY_SIZE(testlist));

	for (idx = 0; idx < ARRAY_SIZE(testlist); idx++) {
		if (testlist[idx].facility &&
		    !machine_has_facility(testlist[idx].facility)) {
			ksft_test_result_skip("%s - facility %d not available\n",
					      testlist[idx].name,
					      testlist[idx].facility);
			continue;
		}
		bad = testlist[idx].test(testlist[idx].arg);
		ksft_test_result(!bad, "%s\n", testlist[idx].name);
	}

	ksft_finished();
}
