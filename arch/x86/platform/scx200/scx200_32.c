// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (c) 2001,2002 Christer Weinigel <wingel@nano-system.com>
 *
 *  National Semiconductor SCx200 support.
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#include <linux/scx200.h>

/* Verify that the configuration block really is there */
#define scx200_cb_probe(base) (inw((base) + SCx200_CBA) == (base))

MODULE_AUTHOR("Christer Weinigel <wingel@nano-system.com>");
MODULE_DESCRIPTION("NatSemi SCx200 Driver");
MODULE_LICENSE("GPL");

unsigned scx200_cb_base = 0;

static struct pci_device_id scx200_tbl[] = {
	{ PCI_VDEVICE(NS, PCI_DEVICE_ID_NS_SCx200_BRIDGE) },
	{ PCI_VDEVICE(NS, PCI_DEVICE_ID_NS_SC1100_BRIDGE) },
	{ PCI_VDEVICE(NS, PCI_DEVICE_ID_NS_SCx200_XBUS)   },
	{ PCI_VDEVICE(NS, PCI_DEVICE_ID_NS_SC1100_XBUS)   },
	{ },
};
MODULE_DEVICE_TABLE(pci,scx200_tbl);

static int scx200_probe(struct pci_dev *, const struct pci_device_id *);

static struct pci_driver scx200_pci_driver = {
	.name = "scx200",
	.id_table = scx200_tbl,
	.probe = scx200_probe,
};

static void scx200_unregister_gpio(void *data)
{
	platform_device_unregister(data);
}

static int scx200_register_gpio(struct pci_dev *pdev)
{
	struct resource res = DEFINE_RES_IO(pci_resource_start(pdev, 0),
					     SCx200_GPIO_SIZE);
	struct platform_device *gpio;

	if (!IS_ENABLED(CONFIG_SCx200_GPIO))
		return 0;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_IO) || !res.start ||
	    pci_resource_len(pdev, 0) < SCx200_GPIO_SIZE)
		return -ENODEV;

	gpio = platform_device_register_resndata(&pdev->dev, "gpio-scx200",
						 PLATFORM_DEVID_NONE, &res, 1,
						 NULL, 0);
	if (IS_ERR(gpio))
		return PTR_ERR(gpio);

	return devm_add_action_or_reset(&pdev->dev, scx200_unregister_gpio, gpio);
}

static int scx200_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	unsigned base;

	if (pdev->device == PCI_DEVICE_ID_NS_SCx200_BRIDGE ||
	    pdev->device == PCI_DEVICE_ID_NS_SC1100_BRIDGE)
		return scx200_register_gpio(pdev);

	/* Find the base of the configuration block. */
	if (scx200_cb_probe(SCx200_CB_BASE_FIXED)) {
		scx200_cb_base = SCx200_CB_BASE_FIXED;
	} else {
		pci_read_config_dword(pdev, SCx200_CBA_SCRATCH, &base);
		if (!scx200_cb_probe(base)) {
			pr_warn("Configuration Block not found\n");
			return -ENODEV;
		}
		scx200_cb_base = base;
	}
	pr_info("Configuration Block base 0x%x\n", scx200_cb_base);

	return 0;
}

static int __init scx200_init(void)
{
	pr_info("NatSemi SCx200 Driver\n");
	return pci_register_driver(&scx200_pci_driver);
}

static void __exit scx200_cleanup(void)
{
	pci_unregister_driver(&scx200_pci_driver);
}

module_init(scx200_init);
module_exit(scx200_cleanup);

EXPORT_SYMBOL(scx200_cb_base);
