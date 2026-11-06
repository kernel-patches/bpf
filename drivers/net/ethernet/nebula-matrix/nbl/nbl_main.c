// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include "nbl_include/nbl_include.h"
#include "nbl_include/nbl_def_channel.h"
#include "nbl_include/nbl_def_hw.h"
#include "nbl_include/nbl_def_common.h"
#include "nbl_core.h"

/*
 * Budget for the device_trylock() loop that takes func 0's device lock in
 * nbl_probe_chip_deps().  See the comment there for why a single failed
 * trylock must not defer the probe, and why the wait has to stay bounded.
 */
#define NBL_MGT_LOCK_RETRY_MIN_US	1000
#define NBL_MGT_LOCK_RETRY_MAX_US	2000
#define NBL_MGT_LOCK_MAX_RETRIES	50

struct nbl_adapter *nbl_core_init(struct pci_dev *pdev,
				  struct nbl_init_param *param)
{
	struct nbl_common_info *common;
	struct nbl_adapter *adapter;
	int ret;

	adapter = devm_kzalloc(&pdev->dev, sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return ERR_PTR(-ENOMEM);

	adapter->pdev = pdev;
	common = &adapter->common;

	common->pdev = pdev;
	common->dev = &pdev->dev;
	common->has_ctrl = param->caps.has_ctrl;
	common->has_net = param->caps.has_net;
	common->function = PCI_FUNC(pdev->devfn);
	common->devid = PCI_SLOT(pdev->devfn);
	common->bus = pdev->bus->number;

	ret = nbl_hw_init_leonis(adapter);
	if (ret)
		goto out;

	ret = nbl_chan_init_common(adapter);
	if (ret)
		goto out_hw_remove;
	return adapter;
out_hw_remove:
	nbl_hw_remove_leonis(adapter);
out:
	return ERR_PTR(ret);
}

void nbl_core_remove(struct nbl_adapter *adapter)
{
	nbl_chan_remove_common(adapter);
	nbl_hw_remove_leonis(adapter);
}

static void nbl_get_func_param(struct pci_dev *pdev, kernel_ulong_t driver_data,
			       struct nbl_init_param *param)
{
	param->caps.has_net = !!(driver_data & BIT(NBL_CAP_HAS_NET_BIT));

	/*
	 * Hardware fixed rule: physical PF0 is the only management PF with
	 * global ctrl capability. All PFs share identical PCI device ID, so
	 * distinguish control PF via physical function ID.
	 *
	 * Hardware & firmware design FORBID passing any PF through to virtual
	 * machines, there is no scenario where a non-management PF appears
	 * as Func 0 inside guest. Thus using PCI_FUNC(pdev->devfn) to identify
	 *  control PF is safe on our platform.
	 */
	if ((PCI_FUNC(pdev->devfn) == 0) && !pdev->is_virtfn)
		param->caps.has_ctrl = 1;
}

/*
 * Establish chip-wide dependencies for this PF:
 *  - for every non-management PF, add a consumer->management PF device
 *    link. The driver core then guarantees (sysfs unbind, driver
 *    unregister, hot-unplug alike) that this consumer is released
 *    BEFORE the func 0 supplier, which is the only teardown order in
 *    which the chip-global firmware deinit is safe.
 *
 * The management PF is addressed by the deterministic identity
 * (domain, bus, slot, func 0) instead of any name-based scan: hardware
 * guarantees PFs are contiguous from func 0 in the same slot.
 *
 * The func 0 device must already be bound to this driver.  While func 0
 * is still probing, its chip-global init (mailbox QINFO map programming,
 * datapath setup) can race a sibling's mailbox setup, and a link created
 * while the supplier has no driver starts DORMANT and is force-promoted
 * (with a WARN backtrace) by device_links_driver_bound() when this probe
 * ends, so it never delivers the unbind-order guarantee.
 *
 * The link is a persistent managed link with DL_FLAG_AUTOPROBE_CONSUMER:
 * the core force-unbinds this consumer when func 0 unbinds (keeping the
 * teardown order) and re-queues it for probe when func 0 binds again, so
 * the sibling PFs and their ports come back without a manual rebind.
 * AUTOREMOVE_CONSUMER would delete the link on unbind and cannot be
 * combined with AUTOPROBE_CONSUMER (device_link_add() returns NULL for
 * that pair).  The link is therefore not auto-purged on a failed probe:
 * it lives with the two devices and is dropped when either is removed.
 * The pointer device_link_add() returns is never dereferenced.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int nbl_probe_chip_deps(struct pci_dev *pdev, bool has_ctrl)
{
	struct pci_dev *mgt;
	int retries;

	if (has_ctrl)
		return 0;

	mgt = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
					  pdev->bus->number,
					  PCI_DEVFN(PCI_SLOT(pdev->devfn), 0));
	if (!mgt) {
		dev_err(&pdev->dev,
			"management PF (func 0) not found on this chip\n");
		return -ENODEV;
	}

	/*
	 * That identity is meaningless for a VF: under ARI a VF's devfn
	 * decodes to function 0 of a slot, so the lookup can resolve to the
	 * VF itself.  A VF is never the management PF, so stop here instead
	 * of taking our own device lock below.
	 */
	if (mgt == pdev) {
		dev_err(&pdev->dev,
			"management PF lookup matched this device\n");
		pci_dev_put(mgt);
		return -ENODEV;
	}

	/*
	 * func 0's device lock is taken with a trylock.  This probe already
	 * runs under device_lock(funcN), so a blocking device_lock(func0)
	 * would establish the N -> 0 order, while __pci_bus_lock() (AER
	 * recovery, slot reset) walks the bus in devfn order, i.e. 0 -> N,
	 * and dev->mutex is lockdep_set_novalidate_class(), so lockdep
	 * cannot report that inversion.  A trylock never blocks, so it
	 * cannot take part in a deadlock cycle.
	 *
	 * Holding the lock is what makes the check and the link creation
	 * below atomic with respect to func 0: it both gains its driver
	 * (driver_bound() -> device_links_driver_bound()) and loses it
	 * (__device_release_driver() -> device_links_driver_cleanup())
	 * under device_lock(func0), so func 0 can change neither driver nor
	 * links.status while we hold it.
	 *
	 * One failed trylock is nevertheless not enough to defer on.  Func 0
	 * binds with device_lock(func0) held, and driver_bound() calls
	 * driver_deferred_probe_trigger() before it releases that lock, so
	 * the deferred probe work it queues can re-probe this PF while func
	 * 0's lock is still taken.  driver_probe_device() only re-arms that
	 * work when deferred_trigger_count changes *during* the probe, which
	 * it does not here: func 0's increment happened before this probe
	 * read the count.  A bare -EPROBE_DEFER would therefore leave this
	 * PF on deferred_probe_pending_list with nothing scheduled to run
	 * it again.  Retrying closes that window - driver_bound() has only a
	 * bus_notify() and a kobject_uevent() left before it drops the lock.
	 *
	 * The retry budget is what keeps this safe.  device_lock(funcN) is
	 * held for the whole loop, so waiting indefinitely would deadlock
	 * against __pci_bus_lock(); giving up and deferring releases it and
	 * lets the other side make progress.  A holder that is not part of a
	 * bind - __pci_bus_lock() during AER recovery or a bus/slot reset,
	 * pci_reset_function() through sysfs, an sriov_numvfs write - can
	 * outlast the budget, and no bind event follows those, so this PF
	 * then stays deferred until some later deferred-probe trigger from
	 * anywhere in the system.  There is no way to force one from here.
	 */
	for (retries = 0; !device_trylock(&mgt->dev); retries++) {
		if (retries == NBL_MGT_LOCK_MAX_RETRIES) {
			dev_dbg(&pdev->dev,
				"management PF device lock busy after %u retries, deferring probe\n",
				retries);
			pci_dev_put(mgt);
			return -EPROBE_DEFER;
		}
		usleep_range(NBL_MGT_LOCK_RETRY_MIN_US,
			     NBL_MGT_LOCK_RETRY_MAX_US);
	}

	/*
	 * The management PF must be bound to *this* driver, with its probe
	 * completed.  links.status == DL_DEV_DRIVER_BOUND alone only says
	 * "bound to some driver", so func 0 on vfio-pci or pci-stub
	 * (driver_override) would pass it and this PF would run with func
	 * 0's chip-global init never performed.  pdev->dev.driver is our
	 * own driver, set by the core before ->probe() is called.
	 *
	 * Deferring is what recovers from this: a successful bind
	 * re-triggers deferred probing for every pending device
	 * (driver_bound() -> driver_deferred_probe_trigger()), so this PF is
	 * retried once func 0 is bound to this driver.  That covers a func 0
	 * that is not bound yet.  It does not cover a func 0 that is bound
	 * while something else holds its device lock, which is what the
	 * retry loop above is for and what its budget cannot fully rule out.
	 */
	if (mgt->dev.driver != pdev->dev.driver ||
	    mgt->dev.links.status != DL_DEV_DRIVER_BOUND) {
		device_unlock(&mgt->dev);
		pci_dev_put(mgt);
		return -EPROBE_DEFER;
	}

	/*
	 * Create the link while func 0's lock is still held, so that func 0
	 * cannot change state in between.  With the supplier bound and this
	 * consumer PROBING, device_link_init_status() starts the link in
	 * DL_STATE_CONSUMER_PROBE: that is the state
	 * device_links_driver_bound() expects when this probe finishes, and
	 * it is what device_links_busy() reports to func 0's own unbind, so
	 * func 0 cannot be released underneath this PF.
	 */
	if (!device_link_add(&pdev->dev, &mgt->dev,
			     DL_FLAG_AUTOPROBE_CONSUMER)) {
		device_unlock(&mgt->dev);
		dev_err(&pdev->dev,
			"failed to create device link to management PF\n");
		pci_dev_put(mgt);
		return -ENOMEM;
	}

	device_unlock(&mgt->dev);
	pci_dev_put(mgt);

	return 0;
}

static int nbl_probe(struct pci_dev *pdev,
		     const struct pci_device_id *id)
{
	struct nbl_init_param param = { { 0 } };
	struct device *dev = &pdev->dev;
	struct nbl_adapter *adapter;
	int err;

	nbl_get_func_param(pdev, id->driver_data, &param);
	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI dev, err=%d\n", err);
		return err;
	}

	/* never return fail when DMA_BIT_MASK(64) */
	dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));

	pci_set_master(pdev);

	err = nbl_probe_chip_deps(pdev, param.caps.has_ctrl);
	if (err)
		goto out_clear_master;

	adapter = nbl_core_init(pdev, &param);
	if (IS_ERR(adapter)) {
		dev_err(dev, "Nbl adapter init fail: %pe\n", adapter);
		err = PTR_ERR(adapter);
		goto out_clear_master;
	}
	pci_set_drvdata(pdev, adapter);

	return 0;
out_clear_master:
	pci_clear_master(pdev);
	return err;
}

static void nbl_remove(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter)
		return;
	pci_set_drvdata(pdev, NULL);
	nbl_core_remove(adapter);

	pci_clear_master(pdev);
}

/*
 * PCI Device IDs for Leonis/NBL Network Controllers
 *
 * Vendor ID: 0x1F0F
 * SNIC v3r1 product Device IDs range: 0x3403-0x3412
 */
#define NBL_VENDOR_ID				0x1F0F

#define NBL_DEVICE_ID_M18110			0x3403
#define NBL_DEVICE_ID_M18110_LX			0x3404
#define NBL_DEVICE_ID_M18110_BASE_T		0x3405
#define NBL_DEVICE_ID_M18110_LX_BASE_T		0x3406
#define NBL_DEVICE_ID_M18110_OCP		0x3407
#define NBL_DEVICE_ID_M18110_LX_OCP		0x3408
#define NBL_DEVICE_ID_M18110_BASE_T_OCP		0x3409
#define NBL_DEVICE_ID_M18110_LX_BASE_T_OCP	0x340a
#define NBL_DEVICE_ID_M18000			0x340b
#define NBL_DEVICE_ID_M18000_LX			0x340c
#define NBL_DEVICE_ID_M18000_BASE_T		0x340d
#define NBL_DEVICE_ID_M18000_LX_BASE_T		0x340e
#define NBL_DEVICE_ID_M18000_OCP		0x340f
#define NBL_DEVICE_ID_M18000_LX_OCP		0x3410
#define NBL_DEVICE_ID_M18000_BASE_T_OCP		0x3411
#define NBL_DEVICE_ID_M18000_LX_BASE_T_OCP	0x3412

/* All below IDs belong to Leonis ASIC family, different form-factor variants,
 * share the same hardware initialization flow without differentiated ops.
 */
static const struct pci_device_id nbl_id_table[] = {
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_BASE_T),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_BASE_T),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_BASE_T_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_BASE_T_OCP),
	  .driver_data = BIT(NBL_CAP_HAS_NET_BIT) },
	/* required as sentinel */
	{ }
};
MODULE_DEVICE_TABLE(pci, nbl_id_table);

static struct pci_driver nbl_driver = {
	.name = NBL_DRIVER_NAME,
	.id_table = nbl_id_table,
	.probe = nbl_probe,
	.remove = nbl_remove,
};

module_pci_driver(nbl_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Nebula Matrix Network Driver");
MODULE_AUTHOR("Illusion Wang <illusion.wang@nebula-matrix.com>");
