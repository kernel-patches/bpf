// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/slab.h>

#include "common/xsc_core.h"

static const struct pci_device_id xsc_pci_id_table[] = {
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_SOC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_SOC_PF_DEV_ID) },
	{ 0 }
};

static int xsc_set_dma_caps(struct pci_dev *pdev)
{
	int err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (!err)
		dma_set_max_seg_size(&pdev->dev, SZ_2G);

	return err;
}

static int xsc_pci_init(struct xsc_core_device *xdev,
			const struct pci_device_id *id)
{
	struct pci_dev *pdev = xdev->pdev;
	void __iomem *bar_base;
	int bar_num = 0;
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		pci_err(pdev, "failed to enable PCI device: err=%d\n", err);
		goto err_out;
	}

	err = pci_request_region(pdev, bar_num, KBUILD_MODNAME);
	if (err) {
		pci_err(pdev, "failed to request %s pci_region=%d: err=%d\n",
			KBUILD_MODNAME, bar_num, err);
		goto err_disable;
	}

	pci_set_master(pdev);

	err = xsc_set_dma_caps(pdev);
	if (err) {
		pci_err(pdev, "failed to set DMA capabilities mask: err=%d\n",
			err);
		goto err_clr_master;
	}

	bar_base = pci_ioremap_bar(pdev, bar_num);
	if (!bar_base) {
		pci_err(pdev, "failed to ioremap %s bar%d\n", KBUILD_MODNAME,
			bar_num);
		err = -ENOMEM;
		goto err_clr_master;
	}

	err = pci_save_state(pdev);
	if (err) {
		pci_err(pdev, "pci_save_state failed: err=%d\n", err);
		goto err_io_unmap;
	}

	xdev->bar_num = bar_num;
	xdev->bar = bar_base;

	return 0;

err_io_unmap:
	pci_iounmap(pdev, bar_base);
err_clr_master:
	pci_clear_master(pdev);
	pci_release_region(pdev, bar_num);
err_disable:
	pci_disable_device(pdev);
err_out:
	return err;
}

static void xsc_pci_fini(struct xsc_core_device *xdev)
{
	struct pci_dev *pdev = xdev->pdev;

	pci_iounmap(pdev, xdev->bar);
	pci_clear_master(pdev);
	pci_release_region(pdev, xdev->bar_num);
	pci_disable_device(pdev);
}

static int xsc_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *id)
{
	struct xsc_core_device *xdev;
	int err;

	xdev = kzalloc_obj(*xdev, GFP_KERNEL);
	if (!xdev)
		return -ENOMEM;

	xdev->pdev = pci_dev;
	xdev->device = &pci_dev->dev;

	pci_set_drvdata(pci_dev, xdev);
	err = xsc_pci_init(xdev, id);
	if (err) {
		pci_err(pci_dev, "xsc_pci_init failed %d\n", err);
		goto err_unset_pci_drvdata;
	}

	return 0;

err_unset_pci_drvdata:
	pci_set_drvdata(pci_dev, NULL);
	kfree(xdev);

	return err;
}

static void xsc_pci_remove(struct pci_dev *pci_dev)
{
	struct xsc_core_device *xdev = pci_get_drvdata(pci_dev);

	xsc_pci_fini(xdev);
	pci_set_drvdata(pci_dev, NULL);
	kfree(xdev);
}

static struct pci_driver xsc_pci_driver = {
	.name		= "xsc-pci",
	.id_table	= xsc_pci_id_table,
	.probe		= xsc_pci_probe,
	.remove		= xsc_pci_remove,
};

static int __init xsc_init(void)
{
	int err;

	err = pci_register_driver(&xsc_pci_driver);
	if (err) {
		pr_err("failed to register pci driver\n");
		return err;
	}

	return 0;
}

static void __exit xsc_fini(void)
{
	pci_unregister_driver(&xsc_pci_driver);
}

module_init(xsc_init);
module_exit(xsc_fini);

MODULE_DEVICE_TABLE(pci, xsc_pci_id_table);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Yunsilicon XSC PCI driver");
