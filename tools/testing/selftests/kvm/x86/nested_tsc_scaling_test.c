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

static void test_tsc_scaling(u64 l0_tsc_freq, u64 l1_scale_factor, u64 l2_scale_factor)
{
	u64 tsc_khz, l1_tsc_freq, l2_tsc_freq;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t guest_gva;
	u8 frac_bits;

	printf("L1's scale down factor is: %lu\n", l1_scale_factor);
	printf("L2's scale up factor is: %lu\n", l2_scale_factor);

	frac_bits = kvm_cpu_has(X86_FEATURE_VMX) ? 48 : 32;
	l2_multiplier = l2_scale_factor << frac_bits;

	vm = vm_create_with_one_vcpu(&vcpu, l1_guest_code);
	sync_global_to_guest(vm, l2_multiplier);

	if (kvm_cpu_has(X86_FEATURE_VMX))
		vcpu_alloc_vmx(vm, &guest_gva);
	else
		vcpu_alloc_svm(vm, &guest_gva);

	vcpu_args_set(vcpu, 1, guest_gva);

	tsc_khz = __vcpu_ioctl(vcpu, KVM_GET_TSC_KHZ, NULL);
	TEST_ASSERT(tsc_khz != -1, "vcpu ioctl KVM_GET_TSC_KHZ failed");

	/* scale down L1's TSC frequency */
	vcpu_ioctl(vcpu, KVM_SET_TSC_KHZ, (void *) (tsc_khz / l1_scale_factor));

	/* L1 will communicate its frequency before the L2 check.*/
	l1_tsc_freq = 0;

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
				l1_tsc_freq = uc.args[1];
				printf("L1's TSC frequency is around: %lu\n", l1_tsc_freq);

				host_check_tsc_freq(1, l1_tsc_freq,
						 l0_tsc_freq / l1_scale_factor);
				break;
			case UCHECK_L2:
				l2_tsc_freq = uc.args[1];
				printf("L2's TSC frequency is around: %lu\n", l2_tsc_freq);

				host_check_tsc_freq(2, l2_tsc_freq,
						 l1_tsc_freq * l2_scale_factor);
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

	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_VMX) ||
		     kvm_cpu_has(X86_FEATURE_SVM));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_TSC_CONTROL));
	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());

	tsc_start = rdtsc();
	sleep(1);
	tsc_end = rdtsc();

	l0_tsc_freq = tsc_end - tsc_start;
	printf("real TSC frequency is around: %lu\n", l0_tsc_freq);

	/* Scale L1 "down" and L2 "up" at a random factor from 2 to 10. */
	l1_scale = (kvm_random_u32(&kvm_rng) % 9) + 2;
	l2_scale = (kvm_random_u32(&kvm_rng) % 9) + 2;
	test_tsc_scaling(l0_tsc_freq, l1_scale, l2_scale);

	return 0;
}
