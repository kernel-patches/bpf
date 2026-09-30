// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmx_nested_tsc_scaling_test
 *
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This test case verifies that nested TSC scaling behaves as expected when
 * both L1 and L2 are scaled using different ratios. For this test we scale
 * L1 down and scale L2 up.
 */
#include <linux/math64.h>
#include <time.h>

#include "kvm_util.h"
#include "vmx.h"
#include "svm_util.h"
#include "kselftest.h"

/* L2's TSC multiplier, relative to L1. */
static u64 l2_multiplier;

#define TSC_OFFSET_L2 ((u64)-33125236320908)

enum { USLEEP, UCHECK_L1, UCHECK_L2 };
#define GUEST_SLEEP(sec)         ucall(UCALL_SYNC, 2, USLEEP, sec)
#define GUEST_CHECK(level, freq) ucall(UCALL_SYNC, 2, level, freq)


/*
 * This function checks whether the "actual" TSC frequency of a guest matches
 * its expected frequency. In order to account for delays in taking the TSC
 * measurements, a difference of 1% between the actual and the expected value
 * is tolerated.
 */
static void host_check_tsc_freq(int level, u64 actual, u64 expected)
{
	u64 tolerance, thresh_low, thresh_high;

	tolerance = max(expected / 100, (u64)1);
	thresh_low = expected - tolerance;
	thresh_high = expected + tolerance;

	TEST_ASSERT(thresh_low <= actual && thresh_high >= actual,
		    "L%u TSC freq is '%lu', expected to be between %lu and %lu",
		    level, actual, thresh_low, thresh_high);
}

static void guest_check_tsc_freq(int level)
{
	u64 tsc_start, tsc_end, tsc_freq;

	/*
	 * Reading the TSC twice with about a second's difference should give
	 * us an approximation of the TSC frequency from the guest's
	 * perspective. Now, this won't be completely accurate, but it should
	 * be good enough for the purposes of this test.
	 */
	tsc_start = rdmsr(MSR_IA32_TSC);
	GUEST_SLEEP(1);
	tsc_end = rdmsr(MSR_IA32_TSC);

	tsc_freq = tsc_end - tsc_start;

	GUEST_CHECK(level, tsc_freq);
}

static void l2_guest_code(void)
{
	guest_check_tsc_freq(UCHECK_L2);

	/* exit to L1 */
	__asm__ __volatile__("vmcall");
}

static void l1_svm_code(struct svm_test_data *svm)
{
	/* check that L1's frequency looks alright before launching L2 */
	guest_check_tsc_freq(UCHECK_L1);

	generic_svm_setup(svm, l2_guest_code);

	/* enable TSC scaling for L2 */
	wrmsr(MSR_AMD64_TSC_RATIO, l2_multiplier);

	/* launch L2 */
	run_guest(svm->vmcb, svm->vmcb_gpa);
	GUEST_ASSERT(svm->vmcb->control.exit_code == SVM_EXIT_VMMCALL);

	/* check that L1's frequency still looks good */
	guest_check_tsc_freq(UCHECK_L1);

	GUEST_DONE();
}

static void l1_vmx_code(struct vmx_pages *vmx_pages)
{
	u32 control;

	/* check that L1's frequency looks alright before launching L2 */
	guest_check_tsc_freq(UCHECK_L1);

	prepare_for_vmx_operation(vmx_pages);
	load_vmcs(vmx_pages);

	/* prepare the VMCS for L2 execution */
	prepare_vmcs(vmx_pages, l2_guest_code);

	/* enable TSC offsetting and TSC scaling for L2 */
	control = vmread(CPU_BASED_VM_EXEC_CONTROL);
	control |= CPU_BASED_USE_MSR_BITMAPS | CPU_BASED_USE_TSC_OFFSETTING;
	vmwrite(CPU_BASED_VM_EXEC_CONTROL, control);

	control = vmread(SECONDARY_VM_EXEC_CONTROL);
	control |= SECONDARY_EXEC_TSC_SCALING;
	vmwrite(SECONDARY_VM_EXEC_CONTROL, control);

	vmwrite(TSC_OFFSET, TSC_OFFSET_L2);
	vmwrite(TSC_MULTIPLIER, l2_multiplier);

	/* launch L2 */
	vmlaunch();
	GUEST_ASSERT(vmread(VM_EXIT_REASON) == EXIT_REASON_VMCALL);

	/* check that L1's frequency still looks good */
	guest_check_tsc_freq(UCHECK_L1);

	GUEST_DONE();
}

static void l1_guest_code(void *data)
{
	if (this_cpu_has(X86_FEATURE_VMX))
		l1_vmx_code(data);
	else
		l1_svm_code(data);
}

static void test_tsc_scaling(u64 l0_tsc_freq, u64 l1_tsc_freq, u64 l2_tsc_freq,
			     u64 __l2_multiplier)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t guest_gva;

	printf("Testing L0 freq = %lu, L1 freq = %lu, L2 freq = %lu, L2 mult = 0x%lx\n",
	       l0_tsc_freq, l1_tsc_freq, l2_tsc_freq, __l2_multiplier);

	vm = vm_create_with_one_vcpu(&vcpu, l1_guest_code);

	l2_multiplier = __l2_multiplier;
	sync_global_to_guest(vm, l2_multiplier);

	if (kvm_cpu_has(X86_FEATURE_VMX))
		vcpu_alloc_vmx(vm, &guest_gva);
	else
		vcpu_alloc_svm(vm, &guest_gva);

	vcpu_args_set(vcpu, 1, guest_gva);

	vcpu_ioctl(vcpu, KVM_SET_TSC_KHZ, (void *)(l1_tsc_freq / 1000));

	for (;;) {
		struct ucall uc;

		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		case UCALL_SYNC:
			switch (uc.args[0]) {
			case USLEEP:
				sleep(uc.args[1]);
				break;
			case UCHECK_L1:
				printf("L1's observed TSC frequency: %lu\n", uc.args[1]);
				host_check_tsc_freq(1, uc.args[1], l1_tsc_freq);
				break;
			case UCHECK_L2:
				printf("L2's observed TSC frequency: %lu\n", uc.args[1]);
				host_check_tsc_freq(2, uc.args[1], l2_tsc_freq);
				break;
			}
			break;
		case UCALL_DONE:
			goto done;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	}

done:
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	u64 l0_tsc_freq, tsc_start, tsc_end, l1_scale, l2_scale;
	u8 frac_bits = kvm_cpu_has(X86_FEATURE_VMX) ? 48 : 32;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_VMX) ||
		     kvm_cpu_has(X86_FEATURE_SVM));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_TSC_CONTROL));
	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());

	/*
	 * Create a dummy VM to get KVM's default TSC frequency.  All CPUs that
	 * support TSC scaling should have a constant TSC, i.e. there's no need
	 * to calibrate the "real" TSC.  But do sanity check that the observed
	 * TSC is within range of KVM's reported TSC frequency.
	 */
	vm = vm_create_barebones();
	l0_tsc_freq = (u64)__vm_ioctl(vm, KVM_GET_TSC_KHZ, NULL) * 1000;
	TEST_ASSERT(l0_tsc_freq, "vcpu ioctl KVM_GET_TSC_KHZ failed");
	kvm_vm_free(vm);

	printf("L0 TSC frequency is: %lu\n", l0_tsc_freq);

	tsc_start = rdtsc();
	sleep(1);
	tsc_end = rdtsc();
	host_check_tsc_freq(0, tsc_end - tsc_start, l0_tsc_freq);

	/* Sanity check the frequency reported by KVM_GET_TSC_KHZ. */
	test_tsc_scaling(l0_tsc_freq, l0_tsc_freq, l0_tsc_freq, BIT_ULL(frac_bits));

	/* Scale L1 "down" and L2 "up" at a random factor from 2 to 10. */
	l1_scale = (kvm_random_u32(&kvm_rng) % 9) + 2;
	l2_scale = (kvm_random_u32(&kvm_rng) % 9) + 2;

	test_tsc_scaling(l0_tsc_freq, l0_tsc_freq / l1_scale,
			 mul_u64_u64_div64(l0_tsc_freq, l2_scale, l1_scale),
			 (l2_scale << frac_bits));

	return 0;
}
