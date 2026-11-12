// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/bits.h>
#include "nbl_include/nbl_include.h"
#include "nbl_include/nbl_def_channel.h"
#include "nbl_include/nbl_def_hw.h"
#include "nbl_include/nbl_def_resource.h"
#include "nbl_include/nbl_def_common.h"
#include "nbl_core.h"

struct nbl_adapter *nbl_core_init(struct pci_dev *pdev,
				  struct nbl_init_param *param)
{
	struct nbl_common_info *common;
	struct nbl_adapter *adapter;
	int ret;

	adapter = devm_kzalloc_obj(&pdev->dev, *adapter);
	if (!adapter)
		return ERR_PTR(-ENOMEM);

	adapter->pdev = pdev;
	common = &adapter->common;

	common->mgt_pf = 0;
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

	ret = nbl_res_init_leonis(adapter);
	if (ret)
		goto out_chan_remove;
	return adapter;
out_chan_remove:
	nbl_chan_remove_common(adapter);
out_hw_remove:
	nbl_hw_remove_leonis(adapter);
out:
	return ERR_PTR(ret);
}

void nbl_core_remove(struct nbl_adapter *adapter)
{
	nbl_res_remove_leonis(adapter);
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
 * ends, so it never delivers the unbind-order guarantee.  This function
 * therefore defers until func 0 is bound, and re-checks right after
 * device_link_add() in case func 0 started unbinding in between.
 *
 * The link is a persistent managed link with DL_FLAG_AUTOPROBE_CONSUMER:
 * the core force-unbinds this consumer when func 0 unbinds (keeping the
 * teardown order) and re-queues it for probe when func 0 binds again, so
 * the sibling PFs and their ports come back without a manual rebind.
 * AUTOREMOVE_CONSUMER would delete the link on unbind and cannot be
 * combined with AUTOPROBE_CONSUMER (device_link_add() returns NULL for
 * that pair).  A link created on a successful probe is therefore not
 * auto-purged: it lives with the two devices and is dropped when either
 * is removed.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int nbl_probe_chip_deps(struct pci_dev *pdev, bool has_ctrl)
{
	struct device_link *link;
	struct pci_dev *mgt;

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
	 * of building a device link from this device to itself.
	 */
	if (mgt == pdev) {
		dev_err(&pdev->dev,
			"management PF lookup matched this device\n");
		pci_dev_put(mgt);
		return -ENODEV;
	}

	/*
	 * Deliberately lock-free.  This probe already runs under
	 * device_lock(funcN), while __pci_bus_lock() (AER recovery, slot
	 * reset) walks the bus in devfn order, i.e. 0 -> N: taking
	 * device_lock(func0) here would establish the opposite order, and
	 * dev->mutex is lockdep_set_novalidate_class(), so lockdep cannot
	 * report the inversion.  Not taking the lock at all is the only way
	 * to stay out of that cycle.
	 *
	 * Neither state read below needs the lock to be safe.  Missing a
	 * transition only costs this probe a deferral, and the deferred probe
	 * work is re-armed by the core: driver_bound() marks func 0 bound
	 * (klist_add_tail(), which is what device_is_bound() reads) before it
	 * calls driver_deferred_probe_trigger(), so the retried probe already
	 * sees device_is_bound(mgt) true.  Since nothing is held across the
	 * deferral, no retry can fail again on account of func 0's probe
	 * still being in flight, which is what made the trylock-and-retry
	 * scheme necessary before.
	 *
	 * The management PF must be bound to *this* driver, with its probe
	 * completed.  device_is_bound() alone only says "bound to some
	 * driver", so func 0 on vfio-pci or pci-stub (driver_override) would
	 * pass it and this PF would run with func 0's chip-global init never
	 * performed.  pdev->dev.driver is our own driver, set by the core
	 * before ->probe() is called.
	 */
	if (READ_ONCE(mgt->dev.driver) != pdev->dev.driver ||
	    !device_is_bound(&mgt->dev)) {
		dev_dbg(&pdev->dev,
			"management PF not ready, deferring probe\n");
		pci_dev_put(mgt);
		return -EPROBE_DEFER;
	}

	/*
	 * With the supplier bound and this consumer PROBING,
	 * device_link_init_status() starts the link in DL_STATE_CONSUMER_PROBE:
	 * that is the state device_links_driver_bound() expects when this probe
	 * finishes, and it is what device_links_busy() reports to func 0's own
	 * unbind, so func 0 cannot be released underneath this PF.
	 */
	link = device_link_add(&pdev->dev, &mgt->dev,
			       DL_FLAG_AUTOPROBE_CONSUMER);
	if (!link) {
		dev_err(&pdev->dev,
			"failed to create device link to management PF\n");
		pci_dev_put(mgt);
		return -ENOMEM;
	}

	/*
	 * func 0 can start unbinding between the check above and
	 * device_link_add(), which leaves the link DORMANT and not what this
	 * probe should succeed with.  Drop it and defer instead: the next
	 * bind of func 0 re-arms deferred probing.
	 */
	if (READ_ONCE(mgt->dev.driver) != pdev->dev.driver ||
	    !device_is_bound(&mgt->dev)) {
		device_link_del(link);
		dev_dbg(&pdev->dev,
			"management PF went away, deferring probe\n");
		pci_dev_put(mgt);
		return -EPROBE_DEFER;
	}

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

	/*
	 * Bus mastering is enabled only after nbl_core_init() returns.
	 *
	 * FUNCTION_MSIX_MAP survives a kexec or a forced unload without
	 * FLR and there is no .shutdown callback to scrub it, so at this
	 * point every map entry left VALID by a previous kernel still
	 * holds a DMA address that this kernel has already reallocated.
	 * Those entries tag their table fetches as bus-master reads, and
	 * the only thing standing between such a fetch and a read of
	 * reused memory is Bus Master Enable, which the PCI core cleared
	 * on the way into this kernel.  nbl_intr_setup_mgt() invalidates
	 * the entries from inside nbl_core_init(); enabling bus mastering
	 * before that would re-open the window.  Everything up to that
	 * point is host-side setup plus MMIO and nothing in it waits for
	 * the device, so it does not need bus mastering.
	 */
	err = nbl_probe_chip_deps(pdev, param.caps.has_ctrl);
	if (err)
		return err;

	adapter = nbl_core_init(pdev, &param);
	if (IS_ERR(adapter)) {
		dev_err(dev, "Nbl adapter init fail: %pe\n", adapter);
		return PTR_ERR(adapter);
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, adapter);

	return 0;
}

static void nbl_remove(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter)
		return;
	pci_set_drvdata(pdev, NULL);

	/*
	 * Stop bus mastering before the teardown in nbl_core_remove()
	 * releases the map tables.
	 *
	 * nbl_core_remove() releases the coherent MSI-X map tables whose
	 * DMA addresses are still programmed in FUNCTION_MSIX_MAP, and the
	 * only thing standing between a late pcompleter fetch and a read
	 * of freed memory is a bounded best-effort delay - the chip
	 * exposes no completion status for those fetches (see
	 * nbl_intr_quiesce_wait()).  Clearing Bus Master Enable first
	 * keeps the device from starting a new fetch at all, so that
	 * residual window only covers requests already in flight.
	 */
	pci_clear_master(pdev);

	nbl_core_remove(adapter);
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
