// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Driver for the onsemi FUSB15201 dual-port USB Type-C and Power Delivery
 * controller.
 *
 * The FUSB15201 runs the Type-C state machine and the Power Delivery policy
 * engine on an integrated microcontroller. The host only observes the
 * resulting state and may ask for role swaps, so this is a plain Type-C class
 * driver rather than a TCPC on the Type-C Port Manager.
 */

#include <linux/bits.h>
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/usb/role.h>
#include <linux/usb/typec.h>

#define FUSB15201_NUM_PORTS		2

#define FUSB15201_REG_VENDID		0x00
#define FUSB15201_REG_PRODID		0x01
#define FUSB15201_REG_DEVID		0x02
#define FUSB15201_REG_HWVER		0x03
#define FUSB15201_REG_FWVER		0x04

#define FUSB15201_VENDID		0xaa
#define FUSB15201_PRODID		0x65
#define FUSB15201_DEVID			0x01

/* Per-port status block, port A at 0x06 and port B at 0x0c */
#define FUSB15201_PORT_BASE(p)		(0x06 + (p) * 0x06)
#define FUSB15201_REG_STATUS(p)		(FUSB15201_PORT_BASE(p) + 0x02)
#define FUSB15201_REG_RESET_STATUS(p)	(FUSB15201_PORT_BASE(p) + 0x03)
#define FUSB15201_REG_FAULT_STATUS(p)	(FUSB15201_PORT_BASE(p) + 0x04)

#define FUSB15201_STATUS_ATTACHED	BIT(0)
#define FUSB15201_STATUS_USBPD		BIT(1)
#define FUSB15201_STATUS_CC2		BIT(2)
#define FUSB15201_STATUS_DFP		BIT(3)
#define FUSB15201_STATUS_SINK		BIT(4)

#define FUSB15201_RESET_ERR_RECOVERY	BIT(2)

#define FUSB15201_FAULT_VBUS_OVP	BIT(0)
#define FUSB15201_FAULT_OTP		BIT(1)
#define FUSB15201_FAULT_CC_OVP		BIT(2)
#define FUSB15201_FAULT_VCONN_OCP	BIT(3)

/* Per-port command block, port A at 0x11 and port B at 0x13 */
#define FUSB15201_REG_COMMANDS(p)	(0x11 + (p) * 0x02)
#define FUSB15201_REG_INT_MASK(p)	(0x12 + (p) * 0x02)

/*
 * The swap command bits are named after the role the port is in when the swap
 * is requested, not the role it ends up in.
 */
#define FUSB15201_CMD_UFP_TO_DFP	BIT(4)
#define FUSB15201_CMD_DFP_TO_UFP	BIT(5)
#define FUSB15201_CMD_SINK_TO_SOURCE	BIT(6)
#define FUSB15201_CMD_SOURCE_TO_SINK	BIT(7)

#define FUSB15201_REG_MASTER_CONTROL	0x15
#define FUSB15201_MASTER_DRP_DISABLE	BIT(1)

/* Per-port interrupt status, write one to clear */
#define FUSB15201_REG_INTERRUPT(p)	(0x16 + (p))
#define FUSB15201_INT_FAULT		BIT(0)
#define FUSB15201_INT_RESET_STATUS	BIT(1)
#define FUSB15201_INT_PORT_STATUS	BIT(2)
#define FUSB15201_INT_ALL		(FUSB15201_INT_FAULT | \
					 FUSB15201_INT_RESET_STATUS | \
					 FUSB15201_INT_PORT_STATUS)

#define FUSB15201_REG_MAX		FUSB15201_REG_INTERRUPT(1)

struct fusb15201;

struct fusb15201_port {
	struct fusb15201 *chip;
	unsigned int index;
	struct typec_port *port;
	struct typec_partner *partner;
	struct usb_role_switch *role_sw;
	struct typec_capability cap;
	unsigned int status;
};

struct fusb15201 {
	struct device *dev;
	struct regmap *regmap;
	struct mutex lock;	/* serialises access to the shared registers */
	struct fusb15201_port ports[FUSB15201_NUM_PORTS];
};

static enum typec_role fusb15201_default_pwr_role(struct fusb15201_port *port)
{
	switch (port->cap.type) {
	case TYPEC_PORT_SRC:
		return TYPEC_SOURCE;
	case TYPEC_PORT_SNK:
		return TYPEC_SINK;
	default:
		if (is_source(port->cap.prefer_role))
			return TYPEC_SOURCE;
		return TYPEC_SINK;
	}
}

static void fusb15201_set_roles(struct fusb15201_port *port,
				enum typec_role pwr_role,
				enum typec_data_role data_role, bool attached)
{
	typec_set_pwr_role(port->port, pwr_role);
	typec_set_vconn_role(port->port, pwr_role);
	typec_set_data_role(port->port, data_role);

	if (!port->role_sw)
		return;

	if (!attached)
		usb_role_switch_set_role(port->role_sw, USB_ROLE_NONE);
	else if (data_role == TYPEC_HOST)
		usb_role_switch_set_role(port->role_sw, USB_ROLE_HOST);
	else
		usb_role_switch_set_role(port->role_sw, USB_ROLE_DEVICE);
}

static void fusb15201_hw_update(struct fusb15201_port *port)
{
	struct fusb15201 *chip = port->chip;
	enum typec_data_role data_role = TYPEC_DEVICE;
	enum typec_role pwr_role;
	unsigned int status;
	int ret;

	ret = regmap_read(chip->regmap, FUSB15201_REG_STATUS(port->index), &status);
	if (ret) {
		dev_warn(chip->dev, "port%u: failed to read status: %d\n",
			 port->index, ret);
		return;
	}

	if (!(status & FUSB15201_STATUS_ATTACHED)) {
		if (port->partner) {
			typec_unregister_partner(port->partner);
			port->partner = NULL;
		}

		/*
		 * None of the remaining status bits are valid while detached,
		 * so fall back to what the port is configured to do.
		 */
		typec_set_orientation(port->port, TYPEC_ORIENTATION_NONE);
		typec_set_pwr_opmode(port->port, TYPEC_PWR_MODE_USB);

		pwr_role = fusb15201_default_pwr_role(port);
		if (is_source(pwr_role))
			data_role = TYPEC_HOST;

		fusb15201_set_roles(port, pwr_role, data_role, false);

		port->status = status;
		return;
	}

	if (!(port->status & FUSB15201_STATUS_ATTACHED)) {
		struct typec_partner_desc desc = {
			.usb_pd = !!(status & FUSB15201_STATUS_USBPD),
		};

		port->partner = typec_register_partner(port->port, &desc);
		if (IS_ERR(port->partner)) {
			dev_err(chip->dev,
				"port%u: failed to register partner: %pe\n",
				port->index, port->partner);
			port->partner = NULL;
		}
	}

	typec_set_orientation(port->port, status & FUSB15201_STATUS_CC2 ?
			      TYPEC_ORIENTATION_REVERSE :
			      TYPEC_ORIENTATION_NORMAL);

	/*
	 * The controller only tells us whether the partner is PD capable. The
	 * Type-C current advertisement is not reported, so 1.5A and 3.0A
	 * operation cannot be distinguished from the default.
	 */
	typec_set_pwr_opmode(port->port, status & FUSB15201_STATUS_USBPD ?
			     TYPEC_PWR_MODE_PD : TYPEC_PWR_MODE_USB);

	pwr_role = status & FUSB15201_STATUS_SINK ? TYPEC_SINK : TYPEC_SOURCE;
	data_role = status & FUSB15201_STATUS_DFP ? TYPEC_HOST : TYPEC_DEVICE;
	fusb15201_set_roles(port, pwr_role, data_role, true);

	port->status = status;
}

static void fusb15201_report_faults(struct fusb15201_port *port)
{
	struct fusb15201 *chip = port->chip;
	unsigned int fault;
	int ret;

	ret = regmap_read(chip->regmap, FUSB15201_REG_FAULT_STATUS(port->index), &fault);
	if (ret)
		return;

	/*
	 * The controller protects itself, so there is nothing to do here
	 * beyond making the fault visible.
	 */
	if (fault & FUSB15201_FAULT_VBUS_OVP)
		dev_warn_ratelimited(chip->dev, "port%u: VBUS overvoltage\n",
				     port->index);
	if (fault & FUSB15201_FAULT_OTP)
		dev_warn_ratelimited(chip->dev, "port%u: over temperature\n",
				     port->index);
	if (fault & FUSB15201_FAULT_CC_OVP)
		dev_warn_ratelimited(chip->dev, "port%u: CC overvoltage\n",
				     port->index);
	if (fault & FUSB15201_FAULT_VCONN_OCP)
		dev_warn_ratelimited(chip->dev, "port%u: VCONN overcurrent\n",
				     port->index);
}

static void fusb15201_report_reset(struct fusb15201_port *port)
{
	struct fusb15201 *chip = port->chip;
	unsigned int reset;
	int ret;

	ret = regmap_read(chip->regmap, FUSB15201_REG_RESET_STATUS(port->index), &reset);
	if (ret)
		return;

	dev_dbg(chip->dev, "port%u: reset status 0x%02x\n", port->index, reset);

	if (reset & FUSB15201_RESET_ERR_RECOVERY)
		dev_warn_ratelimited(chip->dev,
				     "port%u: entered error recovery\n",
				     port->index);
}

static irqreturn_t fusb15201_irq(int irq, void *data)
{
	struct fusb15201 *chip = data;
	irqreturn_t ret = IRQ_NONE;
	unsigned int i;

	guard(mutex)(&chip->lock);

	for (i = 0; i < FUSB15201_NUM_PORTS; i++) {
		struct fusb15201_port *port = &chip->ports[i];
		unsigned int pending;

		if (!port->port)
			continue;

		if (regmap_read(chip->regmap, FUSB15201_REG_INTERRUPT(i), &pending))
			continue;

		pending &= FUSB15201_INT_ALL;
		if (!pending)
			continue;

		/* Write one to clear */
		regmap_write(chip->regmap, FUSB15201_REG_INTERRUPT(i), pending);

		if (pending & FUSB15201_INT_PORT_STATUS)
			fusb15201_hw_update(port);
		if (pending & FUSB15201_INT_FAULT)
			fusb15201_report_faults(port);
		if (pending & FUSB15201_INT_RESET_STATUS)
			fusb15201_report_reset(port);

		ret = IRQ_HANDLED;
	}

	return ret;
}

/*
 * Role swaps are asynchronous: the command only asks the controller to start
 * the swap, and the outcome arrives later as a port status interrupt.
 */
static int fusb15201_command(struct fusb15201_port *port, unsigned int cmd)
{
	struct fusb15201 *chip = port->chip;

	guard(mutex)(&chip->lock);

	if (!(port->status & FUSB15201_STATUS_ATTACHED))
		return -ENOTCONN;

	return regmap_write(chip->regmap, FUSB15201_REG_COMMANDS(port->index), cmd);
}

static int fusb15201_dr_set(struct typec_port *p, enum typec_data_role role)
{
	struct fusb15201_port *port = typec_get_drvdata(p);
	unsigned int cmd = FUSB15201_CMD_DFP_TO_UFP;

	if (role == TYPEC_HOST)
		cmd = FUSB15201_CMD_UFP_TO_DFP;

	return fusb15201_command(port, cmd);
}

static int fusb15201_pr_set(struct typec_port *p, enum typec_role role)
{
	struct fusb15201_port *port = typec_get_drvdata(p);
	unsigned int cmd = FUSB15201_CMD_SOURCE_TO_SINK;

	if (is_source(role))
		cmd = FUSB15201_CMD_SINK_TO_SOURCE;

	return fusb15201_command(port, cmd);
}

static const struct typec_operations fusb15201_typec_ops = {
	.dr_set = fusb15201_dr_set,
	.pr_set = fusb15201_pr_set,
};

/*
 * Nearly every register is either volatile or write-only, and the interrupt
 * registers are write-one-to-clear, so the register map is not cached.
 */
static const struct regmap_config fusb15201_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = FUSB15201_REG_MAX,
};

static void fusb15201_unregister_port(void *data)
{
	struct fusb15201_port *port = data;

	if (port->partner)
		typec_unregister_partner(port->partner);
	typec_unregister_port(port->port);
}

static void fusb15201_put_role_sw(void *data)
{
	usb_role_switch_put(data);
}

static int fusb15201_check_id(struct fusb15201 *chip)
{
	static const struct {
		unsigned int reg;
		unsigned int expected;
		const char *name;
	} ids[] = {
		{ FUSB15201_REG_VENDID, FUSB15201_VENDID, "vendor" },
		{ FUSB15201_REG_PRODID, FUSB15201_PRODID, "product" },
		{ FUSB15201_REG_DEVID, FUSB15201_DEVID, "device" },
	};
	unsigned int val, hwver, fwver;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		ret = regmap_read(chip->regmap, ids[i].reg, &val);
		if (ret)
			return dev_err_probe(chip->dev, ret,
					     "failed to read %s id\n",
					     ids[i].name);

		if (val != ids[i].expected)
			return dev_err_probe(chip->dev, -ENODEV,
					     "bad %s id 0x%02x, expected 0x%02x\n",
					     ids[i].name, val, ids[i].expected);
	}

	/*
	 * The register semantics are defined by the firmware image, so record
	 * the versions to make mismatches easier to spot.
	 */
	if (!regmap_read(chip->regmap, FUSB15201_REG_HWVER, &hwver) &&
	    !regmap_read(chip->regmap, FUSB15201_REG_FWVER, &fwver))
		dev_dbg(chip->dev, "hardware version %u, firmware version %u\n",
			hwver, fwver);

	return 0;
}

static int fusb15201_register_port(struct fusb15201 *chip,
				   struct fwnode_handle *fwnode)
{
	struct fusb15201_port *port;
	unsigned int index;
	int ret;

	ret = fwnode_property_read_u32(fwnode, "reg", &index);
	if (ret)
		return dev_err_probe(chip->dev, ret,
				     "missing reg property of %pfwP\n", fwnode);

	if (index >= FUSB15201_NUM_PORTS)
		return dev_err_probe(chip->dev, -EINVAL,
				     "invalid connector index %u\n", index);

	port = &chip->ports[index];
	if (port->port)
		return dev_err_probe(chip->dev, -EINVAL,
				     "duplicate connector for port %u\n", index);

	port->chip = chip;
	port->index = index;

	ret = typec_get_fw_cap(&port->cap, fwnode);
	if (ret)
		return dev_err_probe(chip->dev, ret,
				     "port%u: failed to get capabilities\n",
				     index);

	port->cap.revision = USB_TYPEC_REV_2_0;
	port->cap.orientation_aware = true;
	port->cap.driver_data = port;
	port->cap.ops = &fusb15201_typec_ops;

	port->port = typec_register_port(chip->dev, &port->cap);
	if (IS_ERR(port->port)) {
		ret = PTR_ERR(port->port);
		port->port = NULL;
		return dev_err_probe(chip->dev, ret,
				     "port%u: failed to register\n", index);
	}

	ret = devm_add_action_or_reset(chip->dev, fusb15201_unregister_port, port);
	if (ret)
		return ret;

	port->role_sw = fwnode_usb_role_switch_get(fwnode);
	if (IS_ERR(port->role_sw))
		return dev_err_probe(chip->dev, PTR_ERR(port->role_sw),
				     "port%u: failed to get role switch\n",
				     index);

	if (port->role_sw) {
		ret = devm_add_action_or_reset(chip->dev, fusb15201_put_role_sw,
					       port->role_sw);
		if (ret)
			return ret;
	}

	return 0;
}

static int fusb15201_hw_init(struct fusb15201 *chip)
{
	bool source_only = true;
	unsigned int i;
	int ret;

	for (i = 0; i < FUSB15201_NUM_PORTS; i++) {
		struct fusb15201_port *port = &chip->ports[i];

		if (!port->port) {
			/* Nothing describes this port, keep it quiet. */
			ret = regmap_write(chip->regmap,
					   FUSB15201_REG_INT_MASK(i),
					   FUSB15201_INT_ALL);
			if (ret)
				return ret;

			continue;
		}

		if (port->cap.type != TYPEC_PORT_SRC)
			source_only = false;

		ret = regmap_write(chip->regmap, FUSB15201_REG_INT_MASK(i), 0);
		if (ret)
			return ret;

		/* Discard anything that happened before we got here */
		ret = regmap_write(chip->regmap, FUSB15201_REG_INTERRUPT(i),
				   FUSB15201_INT_ALL);
		if (ret)
			return ret;
	}

	/*
	 * Dual role toggling is the only configurable part of the Type-C state
	 * machine, and it is chip wide rather than per port, which is why it is
	 * set up here instead of from a port_type_set() callback.
	 */
	ret = regmap_update_bits(chip->regmap, FUSB15201_REG_MASTER_CONTROL,
				 FUSB15201_MASTER_DRP_DISABLE,
				 source_only ? FUSB15201_MASTER_DRP_DISABLE : 0);
	if (ret)
		return ret;

	/*
	 * Seed the Type-C class with the current state before arming the IRQ.
	 * The port attributes are already visible, so hold the lock to keep
	 * role swap commands from seeing a port that is not yet marked attached.
	 */
	guard(mutex)(&chip->lock);

	for (i = 0; i < FUSB15201_NUM_PORTS; i++) {
		if (chip->ports[i].port)
			fusb15201_hw_update(&chip->ports[i]);
	}

	return 0;
}

static int fusb15201_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct fusb15201 *chip;
	unsigned int nports = 0;
	int ret;

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->dev = dev;
	i2c_set_clientdata(client, chip);

	ret = devm_mutex_init(dev, &chip->lock);
	if (ret)
		return ret;

	chip->regmap = devm_regmap_init_i2c(client, &fusb15201_regmap_config);
	if (IS_ERR(chip->regmap))
		return dev_err_probe(dev, PTR_ERR(chip->regmap),
				     "failed to initialise register map\n");

	ret = fusb15201_check_id(chip);
	if (ret)
		return ret;

	device_for_each_child_node_scoped(dev, fwnode) {
		ret = fusb15201_register_port(chip, fwnode);
		if (ret)
			return ret;

		nports++;
	}

	if (!nports)
		return dev_err_probe(dev, -ENODEV, "no connector described\n");

	ret = fusb15201_hw_init(chip);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialise\n");

	ret = devm_request_threaded_irq(dev, client->irq, NULL, fusb15201_irq,
					IRQF_ONESHOT, dev_name(dev), chip);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request irq\n");

	return 0;
}

static const struct of_device_id fusb15201_of_match[] = {
	{ .compatible = "onnn,fusb15201" },
	{ }
};
MODULE_DEVICE_TABLE(of, fusb15201_of_match);

static struct i2c_driver fusb15201_driver = {
	.driver = {
		.name = "fusb15201",
		.of_match_table = fusb15201_of_match,
	},
	.probe = fusb15201_probe,
};
module_i2c_driver(fusb15201_driver);

MODULE_AUTHOR("Shawn Guo <shengchao.guo@oss.qualcomm.com>");
MODULE_DESCRIPTION("onsemi FUSB15201 Type-C and Power Delivery controller");
MODULE_LICENSE("GPL");
