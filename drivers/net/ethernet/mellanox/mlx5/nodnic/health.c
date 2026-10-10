// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/types.h>

#include "en.h"
#include "nodnic_ifc.h"
#include "nodnic.h"

#define MLX5_NODNIC_HEALTH_POLL_INTERVAL_MS 2000
#define MLX5_NODNIC_MAX_MISSES	3

enum nodnic_rfr_severity_bit_offsets {
	NODNIC_CRR_BIT_OFFSET = 0x6,
	NODNIC_RFR_BIT_OFFSET = 0x7,
};

enum {
	MLX5_NODNIC_SEVERITY_MASK	= 0x7,
	MLX5_NODNIC_SEVERITY_VALID_MASK	= 0x8,
};

enum  {
	MLX5_NODNIC_SENSOR_NO_ERR,
	MLX5_NODNIC_SENSOR_PCI_COMM_ERR,
	MLX5_NODNIC_SENSOR_PCI_ERR,
	MLX5_NODNIC_SENSOR_NIC_DISABLED,
	MLX5_NODNIC_SENSOR_NIC_SW_RESET,
	MLX5_NODNIC_SENSOR_FW_SYND_RFR,
};

static unsigned long get_next_poll_jiffies(void)
{
	return jiffies + msecs_to_jiffies(MLX5_NODNIC_HEALTH_POLL_INTERVAL_MS) +
	       get_random_u32_below(HZ);
}

static bool sensor_pci_not_working(struct mlx5_nodnic_health *health)
{
	struct health_buffer __iomem *h = health->health;

	return (ioread32be(&h->fw_ver) == 0xffffffff);
}

static u8 mlx5_nodnic_get_nic_state(struct mlx5_nodnic_core_dev *dev)
{
	return (ioread32be(&dev->iseg->cmdq_addr_l_sz) >> 8) & 7;
}

static int mlx5_nodnic_health_get_rfr(u8 rfr_severity)
{
	return rfr_severity >> NODNIC_RFR_BIT_OFFSET;
}

static bool sensor_fw_synd_rfr(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_health *health = &dev->priv->health;
	struct health_buffer __iomem *h = health->health;
	u8 synd = ioread8(&h->synd);
	u8 rfr;

	rfr = mlx5_nodnic_health_get_rfr(ioread8(&h->rfr_severity));

	if (rfr && synd)
		mlx5_nodnic_core_dbg(dev, "FW requests reset, synd: %d\n",
				     synd);

	return rfr && synd;
}

static
u32 mlx5_nodnic_health_check_fatal_sensors(struct mlx5_nodnic_core_dev *dev)
{
	u32 nic_state;

	if (pci_channel_offline(dev->pdev))
		return MLX5_NODNIC_SENSOR_PCI_ERR;
	if (sensor_pci_not_working(&dev->priv->health))
		return MLX5_NODNIC_SENSOR_PCI_COMM_ERR;

	nic_state = mlx5_nodnic_get_nic_state(dev);
	if (nic_state == MLX5_NODNIC_ISEG_NIC_INTERFACE_DISABLED)
		return MLX5_NODNIC_SENSOR_NIC_DISABLED;
	if (nic_state == MLX5_NODNIC_ISEG_NIC_INTERFACE_SW_RESET)
		return MLX5_NODNIC_SENSOR_NIC_SW_RESET;

	if (sensor_fw_synd_rfr(dev))
		return MLX5_NODNIC_SENSOR_FW_SYND_RFR;

	return MLX5_NODNIC_SENSOR_NO_ERR;
}

static const char *mlx5_nodnic_fatal_error_str(u32 err)
{
	switch (err) {
	case MLX5_NODNIC_SENSOR_PCI_COMM_ERR: return "PCI communication error";
	case MLX5_NODNIC_SENSOR_PCI_ERR:      return "PCI error";
	case MLX5_NODNIC_SENSOR_NIC_DISABLED: return "NIC disabled";
	case MLX5_NODNIC_SENSOR_NIC_SW_RESET: return "NIC SW reset";
	case MLX5_NODNIC_SENSOR_FW_SYND_RFR:  return "FW synd RFR";
	default:                       return "unknown";
	}
}

static int mlx5_nodnic_health_get_crr(u8 rfr_severity)
{
	return (rfr_severity >> NODNIC_CRR_BIT_OFFSET) & 0x01;
}

static int mlx5_nodnic_health_get_severity(u8 rfr_severity)
{
	return rfr_severity & MLX5_NODNIC_SEVERITY_VALID_MASK ?
	       rfr_severity & MLX5_NODNIC_SEVERITY_MASK : LOGLEVEL_ERR;
}

/* Syndrome values from health buffer (same as mlx5_ifc.h) */
static const char *mlx5_nodnic_hsynd_str(u8 synd)
{
	switch (synd) {
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FW_INTERNAL_ERR:
		return "firmware internal error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_DEAD_IRISC:
		return "irisc not responding";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_HW_FATAL_ERR:
		return "unrecoverable hardware error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FW_CRC_ERR:
		return "firmware CRC error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_FETCH_PCI_ERR:
		return "ICM fetch PCI error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_PAGE_ERR:
		return "HW fatal error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ASYNCHRONOUS_EQ_BUF_OVERRUN:
		return "async EQ buffer overrun";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_EQ_IN_ERR:
		return "EQ error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_EQ_INV:
		return "Invalid EQ referenced";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FFSER_ERR:
		return "FFSER error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_HIGH_TEMP_ERR:
		return "High temperature";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_PCI_POISONED_ERR:
		return "ICM fetch PCI data poisoned error";
	case MLX5_NODNIC_ISEG_HEALTH_SYNDROME_TRUST_LOCKDOWN_ERR:
		return "Trust lockdown error";
	default:
		return "unrecognized error";
	}
}

static const char *mlx5_nodnic_loglevel_str(int level)
{
	switch (level) {
	case LOGLEVEL_EMERG:
		return "EMERGENCY";
	case LOGLEVEL_ALERT:
		return "ALERT";
	case LOGLEVEL_CRIT:
		return "CRITICAL";
	case LOGLEVEL_ERR:
		return "ERROR";
	case LOGLEVEL_WARNING:
		return "WARNING";
	case LOGLEVEL_NOTICE:
		return "NOTICE";
	case LOGLEVEL_INFO:
		return "INFO";
	case LOGLEVEL_DEBUG:
		return "DEBUG";
	}
	return "Unknown log level";
}

static const char *mlx5_nodnic_severity_to_kern(int severity)
{
	if (severity <= LOGLEVEL_ERR)
		return KERN_ERR;

	if (severity <= LOGLEVEL_WARNING)
		return KERN_WARNING;

	return KERN_INFO;
}

static void mlx5_nodnic_print_health_info(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_health *health = &dev->priv->health;
	struct health_buffer __iomem *h = health->health;
	struct device *device = dev->device;
	u8 synd = ioread8(&h->synd);
	const char *kern_severity;
	u8 rfr_severity;
	int severity;
	int i;

	if (!synd)
		return;

	if (sensor_pci_not_working(&dev->priv->health)) {
		mlx5_nodnic_core_err(dev, "PCI slot is unavailable\n");
		return;
	}

	rfr_severity = ioread8(&h->rfr_severity);
	severity = mlx5_nodnic_health_get_severity(rfr_severity);
	kern_severity = mlx5_nodnic_severity_to_kern(severity);

	dev_printk(kern_severity, device,
		   "Health issue observed, %s, severity(%d) %s:\n",
		   mlx5_nodnic_hsynd_str(synd), severity,
		   mlx5_nodnic_loglevel_str(severity));

	for (i = 0; i < ARRAY_SIZE(h->assert_var); i++)
		dev_printk(kern_severity, device, "assert_var[%d] 0x%08x\n", i,
			   ioread32be(h->assert_var + i));

	dev_printk(kern_severity, device, "assert_exit_ptr 0x%08x\n",
		   ioread32be(&h->assert_exit_ptr));
	dev_printk(kern_severity, device, "assert_callra 0x%08x\n",
		   ioread32be(&h->assert_callra));
	dev_printk(kern_severity, device, "raw fw_ver 0x%08x\n",
		   ioread32be(&h->fw_ver));
	dev_printk(kern_severity, device, "time %u\n", ioread32be(&h->time));
	dev_printk(kern_severity, device, "hw_id 0x%08x\n",
		   ioread32be(&h->hw_id));
	dev_printk(kern_severity, device, "rfr %d\n",
		   mlx5_nodnic_health_get_rfr(rfr_severity));
	dev_printk(kern_severity, device, "crr %d\n",
		   mlx5_nodnic_health_get_crr(rfr_severity));
	dev_printk(kern_severity, device, "severity %d (%s)\n", severity,
		   mlx5_nodnic_loglevel_str(severity));
	dev_printk(kern_severity, device, "irisc_index %d\n",
		   ioread8(&h->irisc_index));
	dev_printk(kern_severity, device, "synd 0x%x: %s\n", synd,
		   mlx5_nodnic_hsynd_str(synd));
	dev_printk(kern_severity, device, "ext_synd 0x%04x\n",
		   ioread16be(&h->ext_synd));

	if (mlx5_nodnic_health_get_crr(rfr_severity))
		mlx5_nodnic_core_warn(dev, "Cold reset is required\n");
}

static void mlx5_nodnic_poll_health(struct timer_list *t)
{
	struct mlx5_nodnic_priv *priv = timer_container_of(priv, t,
							   health.timer);
	struct mlx5_nodnic_core_dev *dev = priv->core_dev;
	struct mlx5_nodnic_health *health = &priv->health;
	struct health_buffer __iomem *h = health->health;
	u32 fatal_error, count;
	u8 prev_synd;

	if (dev->state == NODNIC_DEVICE_STATE_INTERNAL_ERROR)
		return;

	fatal_error = mlx5_nodnic_health_check_fatal_sensors(dev);

	if (fatal_error && !health->fatal_error) {
		mlx5_nodnic_core_err(dev, "fatal error detected: %s (%u)\n",
				     mlx5_nodnic_fatal_error_str(fatal_error),
				     fatal_error);
		priv->health.fatal_error = fatal_error;
		dev->state = NODNIC_DEVICE_STATE_INTERNAL_ERROR;
		mlx5_nodnic_print_health_info(dev);
		return;
	}

	count = ioread32be(health->health_counter);
	if (count == health->prev_counter)
		++health->miss_counter;
	else
		health->miss_counter = 0;

	health->prev_counter = count;
	if (health->miss_counter == MLX5_NODNIC_MAX_MISSES) {
		mlx5_nodnic_core_err(dev,
				     "device's health compromised - reached miss count\n");
		health->synd = ioread8(&h->synd);
		mlx5_nodnic_print_health_info(dev);
	}

	prev_synd = health->synd;
	health->synd = ioread8(&h->synd);
	if (health->synd && health->synd != prev_synd)
		mlx5_nodnic_print_health_info(dev);

	mod_timer(&health->timer, get_next_poll_jiffies());
}

void mlx5_nodnic_start_health_poll(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_health *health = &dev->priv->health;

	timer_setup(&health->timer, mlx5_nodnic_poll_health, 0);
	health->fatal_error = MLX5_NODNIC_SENSOR_NO_ERR;
	health->miss_counter = 0;
	health->prev_counter = 0;
	health->synd = 0;
	health->health = &dev->iseg->health;
	health->health_counter = &dev->iseg->health_counter;

	health->timer.expires = jiffies +
			msecs_to_jiffies(MLX5_NODNIC_HEALTH_POLL_INTERVAL_MS);
	add_timer(&health->timer);
}

void mlx5_nodnic_stop_health_poll(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_health *health = &dev->priv->health;

	timer_delete_sync(&health->timer);
}
