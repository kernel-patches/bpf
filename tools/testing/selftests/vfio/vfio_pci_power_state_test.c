// SPDX-License-Identifier: GPL-2.0-only
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/pci_regs.h>

#include <libvfio.h>

#include "kselftest_harness.h"

/* PCI_PM_CTRL_STATE_MASK values */
#define D0	0
#define D3HOT	3

static const char *device_bdf;

static u16 power_state_get(struct vfio_pci_device *device, u8 pm_cap)
{
	return vfio_pci_config_readw(device, pm_cap + PCI_PM_CTRL) &
	       PCI_PM_CTRL_STATE_MASK;
}

static void power_state_set(struct vfio_pci_device *device, u8 pm_cap,
			    u16 state)
{
	u16 pmcsr = vfio_pci_config_readw(device, pm_cap + PCI_PM_CTRL);

	pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
	pmcsr |= state;

	vfio_pci_config_writew(device, pm_cap + PCI_PM_CTRL, pmcsr);
}

/*
 * Set by test cases that enable VFs, so that disable_vfs() can disable any VFs
 * left enabled if the test case fails. Only set in the child process that runs
 * the test case.
 */
static bool test_enabled_vfs;

/*
 * Disable VFs left enabled by a failed test case, so they don't affect later
 * test cases. Called from fixture teardown, which runs when an ASSERT fails,
 * and from an atexit() handler, which runs when a library helper exits the
 * test process early (e.g. on a VFIO_ASSERT() failure).
 */
static void disable_vfs(void)
{
	if (test_enabled_vfs && sysfs_sriov_numvfs_get(device_bdf) > 0)
		__sysfs_sriov_numvfs_set(device_bdf, 0);
}

/*
 * Check whether the test can enable VFs on the device, briefly enabling one VF
 * to find out. Returns the reason to skip the test, or NULL if it can run.
 */
static const char *sriov_skip_reason(void)
{
	int ret;

	if (sysfs_sriov_totalvfs_get(device_bdf) <= 0)
		return "Device does not support SR-IOV";

	if (sysfs_sriov_numvfs_get(device_bdf) != 0)
		return "SR-IOV is already enabled on the device";

	/* From here on, any VFs on the device were enabled by this test. */
	test_enabled_vfs = true;

	/* -ENOENT means SR-IOV cannot be configured on the device. */
	ret = __sysfs_sriov_numvfs_set(device_bdf, 1);
	if (ret == -ENOENT)
		return "Cannot enable SR-IOV on the device (vfio-pci requires enable_sriov=1)";

	VFIO_ASSERT_EQ(ret, 0);
	sysfs_sriov_numvfs_set(device_bdf, 0);
	return NULL;
}

FIXTURE(vfio_pci_power_state_test) {
	struct iommu *iommu;
	struct vfio_pci_device *device;
	u8 pm_cap;
	int warn_count;
	int kmsg_fd;
};

FIXTURE_SETUP(vfio_pci_power_state_test)
{
	/*
	 * Snapshot the kernel's warning count so that teardown can check that
	 * the test did not trigger any kernel warnings, which are otherwise
	 * invisible to the test. Open /dev/kmsg first so that any warning
	 * counted after the snapshot can be printed if the check fails.
	 */
	self->kmsg_fd = kmsg_open();
	self->warn_count = sysfs_kernel_warn_count_get();

	self->iommu = iommu_init(NULL);
	self->device = vfio_pci_device_init(device_bdf, self->iommu);

	self->pm_cap = vfio_pci_find_capability(self->device, PCI_CAP_ID_PM);
	if (!self->pm_cap)
		SKIP(return, "Device does not have a PM capability\n");

	ASSERT_EQ(power_state_get(self->device, self->pm_cap), D0);
}

FIXTURE_TEARDOWN(vfio_pci_power_state_test)
{
	disable_vfs();

	if (self->device)
		vfio_pci_device_cleanup(self->device);

	iommu_cleanup(self->iommu);

	if (self->warn_count >= 0) {
		int warn_count = sysfs_kernel_warn_count_get();

		if (warn_count != self->warn_count && self->kmsg_fd >= 0)
			kmsg_print_warnings(self->kmsg_fd);

		EXPECT_EQ(warn_count, self->warn_count);
	}

	if (self->kmsg_fd >= 0)
		close(self->kmsg_fd);
}

/*
 * Put the device into D3hot via config space, close it, and then reopen it.
 * Closing the device while it is in D3hot must not trigger any kernel warnings
 * (checked during fixture teardown), and the device must be in D0 when it is
 * reopened.
 *
 * Note that this does not verify that VFIO returns the device to D0 during
 * close, since that is not reliably observable from userspace: the device may
 * runtime suspend after it is closed, and opening it also transitions it to
 * D0.
 */
TEST_F(vfio_pci_power_state_test, reopen_after_close_in_d3hot)
{
	power_state_set(self->device, self->pm_cap, D3HOT);
	ASSERT_EQ(power_state_get(self->device, self->pm_cap), D3HOT);

	vfio_pci_device_cleanup(self->device);

	self->device = vfio_pci_device_init(device_bdf, self->iommu);
	ASSERT_EQ(power_state_get(self->device, self->pm_cap), D0);
}

/*
 * Put the device into D3hot via config space and then enable SR-IOV. VFIO
 * must return the PF to D0 before enabling VFs, and must not allow the PF to
 * leave D0 while VFs are enabled.
 */
TEST_F(vfio_pci_power_state_test, sriov_enable_in_d3hot)
{
	const char *skip_reason = sriov_skip_reason();

	if (skip_reason)
		SKIP(return, "%s", skip_reason);

	power_state_set(self->device, self->pm_cap, D3HOT);
	ASSERT_EQ(power_state_get(self->device, self->pm_cap), D3HOT);

	sysfs_sriov_numvfs_set(device_bdf, 1);
	EXPECT_EQ(power_state_get(self->device, self->pm_cap), D0);

	power_state_set(self->device, self->pm_cap, D3HOT);
	EXPECT_EQ(power_state_get(self->device, self->pm_cap), D0);

	sysfs_sriov_numvfs_set(device_bdf, 0);

	power_state_set(self->device, self->pm_cap, D3HOT);
	EXPECT_EQ(power_state_get(self->device, self->pm_cap), D3HOT);

	power_state_set(self->device, self->pm_cap, D0);
	EXPECT_EQ(power_state_get(self->device, self->pm_cap), D0);
}

struct sriov_enable_args {
	pthread_barrier_t barrier;
	int delay_us;
};

static void *sriov_enable_thread(void *arg)
{
	struct sriov_enable_args *args = arg;

	pthread_barrier_wait(&args->barrier);
	usleep(args->delay_us);
	sysfs_sriov_numvfs_set(device_bdf, 1);
	return NULL;
}

/*
 * Race closing the device while it is in D3hot against enabling SR-IOV. Both
 * paths transition the device back to D0, which must be serialized by VFIO,
 * e.g. to avoid restoring the PF's BARs after VFs have been enabled or
 * double-freeing the saved PM state.
 *
 * The D3hot->D0 transition during close includes a delay (10ms by default)
 * before the device's state is restored. Use a barrier to start closing the
 * device and enabling SR-IOV at the same time, and then delay enabling SR-IOV
 * by a few milliseconds so that it lands inside that window. Vary the delay
 * across iterations to account for differences in timing across systems and
 * kernel configs.
 */
TEST_F(vfio_pci_power_state_test, close_in_d3hot_races_sriov_enable)
{
	struct sriov_enable_args args;
	pthread_t thread;
	const char *skip_reason;
	int i;

	skip_reason = sriov_skip_reason();
	if (skip_reason)
		SKIP(return, "%s", skip_reason);

	ASSERT_EQ(pthread_barrier_init(&args.barrier, NULL, 2), 0);

	/*
	 * Keep the number of iterations low since each one enables and
	 * disables SR-IOV, which can take over a second.
	 */
	for (i = 0; i < 10; i++) {
		args.delay_us = 2000 + i * 500;

		power_state_set(self->device, self->pm_cap, D3HOT);
		ASSERT_EQ(power_state_get(self->device, self->pm_cap), D3HOT);

		ASSERT_EQ(pthread_create(&thread, NULL, sriov_enable_thread, &args), 0);
		pthread_barrier_wait(&args.barrier);
		vfio_pci_device_cleanup(self->device);
		self->device = NULL;
		ASSERT_EQ(pthread_join(thread, NULL), 0);

		sysfs_sriov_numvfs_set(device_bdf, 0);

		self->device = vfio_pci_device_init(device_bdf, self->iommu);
		ASSERT_EQ(power_state_get(self->device, self->pm_cap), D0);
	}

	ASSERT_EQ(pthread_barrier_destroy(&args.barrier), 0);
}

int main(int argc, char *argv[])
{
	device_bdf = vfio_selftests_get_bdf(&argc, argv);
	VFIO_ASSERT_EQ(atexit(disable_vfs), 0);

	return test_harness_run(argc, argv);
}
