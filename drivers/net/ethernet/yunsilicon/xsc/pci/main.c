// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/slab.h>

#include "common/xsc_cmd.h"
#include "common/xsc_core.h"
#include "eq.h"
#include "pci_irq.h"

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

static int xsc_cmd_query_hca_cap(struct xsc_core_device *xdev,
				 struct xsc_caps *caps)
{
	struct xsc_cmd_query_hca_cap_mbox_out *out;
	struct xsc_cmd_query_hca_cap_mbox_in in;
	int err;

	out = kzalloc_obj(*out, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HCA_CAP);
	in.cpu_num = cpu_to_be16(num_online_cpus());

	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		goto err_free;

	xdev->glb_func_id = be32_to_cpu(out->hca_cap.glb_func_id);

	caps->max_cqes = 1 << out->hca_cap.log_max_cq_sz;
	caps->send_ds_num = out->hca_cap.send_seg_num;
	caps->recv_ds_num = out->hca_cap.recv_seg_num;

	caps->nic_caps = (caps->nic_caps & ~XSC_CAP_MAC_PORT_MASK) |
			 FIELD_PREP(XSC_CAP_MAC_PORT_MASK,
				    out->hca_cap.mac_port & 0xff);
	xdev->mac_port = FIELD_GET(XSC_CAP_MAC_PORT_MASK, caps->nic_caps);

	caps->msix_base = be16_to_cpu(out->hca_cap.msix_base);
	caps->msix_num = be16_to_cpu(out->hca_cap.msix_num);

	caps->log_max_qp_depth = out->hca_cap.log_max_qp_depth & 0xff;

	xdev->pcie_no = out->hca_cap.pcie_no;
	xdev->pf_id = out->hca_cap.pf_id;

	kfree(out);
	return 0;
err_free:
	kfree(out);
	return err;
}

static int xsc_reset_function_resource(struct xsc_core_device *xdev)
{
	struct xsc_function_reset_mbox_out out;
	struct xsc_function_reset_mbox_in in;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_FUNCTION_RESET);
	in.glb_func_id = cpu_to_be16(xdev->glb_func_id);

	return xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
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

	err = xsc_cmd_init(xdev);
	if (err) {
		pci_err(pdev, "failed to initialize command interface: err=%d\n",
			err);
		goto err_io_unmap;
	}

	err = xsc_cmd_version_check(xdev);
	if (err) {
		pci_err(pdev, "failed to check command queue version: err=%d\n",
			err);
		goto err_cmd_cleanup;
	}

	err = xsc_cmd_query_hca_cap(xdev, &xdev->caps);
	if (err) {
		pci_err(pdev, "failed to query hca caps: err=%d\n", err);
		goto err_cmd_cleanup;
	}

	err = xsc_reset_function_resource(xdev);
	if (err) {
		pci_err(pdev, "failed to reset function resource: err=%d\n",
			err);
		goto err_cmd_cleanup;
	}

	err = xsc_irq_eq_create(xdev);
	if (err) {
		pci_err(pdev, "failed to create irq/eq: err=%d\n", err);
		goto err_cmd_cleanup;
	}

	return 0;

err_cmd_cleanup:
	xsc_cmd_cleanup(xdev);
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

	xsc_irq_eq_destroy(xdev);
	xsc_cmd_cleanup(xdev);
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
