// SPDX-License-Identifier: GPL-2.0
//
// TI LM51772 I2C regulator driver
//
// Datasheet: SNVSC22D (September 2025)
//
// Copyright (c) 2026 Bootlin

#include <linux/array_size.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/find.h>
#include <linux/i2c.h>
#include <linux/linear_range.h>
#include <linux/math.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/coupler.h>
#include <linux/regulator/driver.h>
#include <linux/string.h>
#include <linux/units.h>

#define LM51772_SENSE_RES_DEFAULT_UOHM		10000

#define LM51772_OVP_MIN				0x00
#define LM51772_OVP_DEFAULT			0x3F

#define LM51772_VCC1_LDO_UV			5000000
#define LM51772_VCC1_LDO_NV			1

#define LM51772_DISCHARGE_STRENGTH_MIN_UA	25000
#define LM51772_DISCHARGE_STRENGTH_STEP_UA	25000
#define LM51772_DISCHARGE_STRENGTH_MAX_UA	75000

#define LM51772_ILIM_MIN_UV			5000
#define LM51772_ILIM_STEP_UV			500
#define LM51772_ILIM_MIN_SEL			0x0A
#define LM51772_ILIM_MAX_SEL			0x8C
#define LM51772_ILIM_NSEL			0x100

#define LM51772_ILIM_UV_TO_UA(rsns_uohm, uv)	(div_u64((u64)(uv) * MICRO, (rsns_uohm)))

#define LM51772_PCM_WINDOW_LOW_MAX		0x1F
#define LM51772_PCM_WINDOW_LOW_DFLT		0xC
#define LM51772_PCM_WINDOW_LOW_STEP_PERMILLE	25

#define LM51772_IVP_VOLTAGE_DEFAULT		0xFF

#define LM51772_DIV10_MIN_UV			1000000
#define LM51772_DIV10_STEP_UV			10000

#define LM51772_DIV20_MIN_UV			3300000
#define LM51772_DIV20_STEP_UV			20000

#define LM51772_N_REGS				2

/* Register map (datasheet table 8-1) */
#define LM51772_REG_CLEAR_FAULTS		0x03
#define LM51772_REG_ILIM_THRESHOLD		0x0A
#define LM51772_REG_VOUT_TARGET1_LSB		0x0C
#define LM51772_REG_VOUT_TARGET1_MSB		0x0D
#define LM51772_REG_USB_PD_STATUS_0		0x21
#define LM51772_REG_STATUS_BYTE			0x78
#define LM51772_REG_USB_PD_CONTROL_0		0x81
#define LM51772_REG_MFR_SPECIFIC_D0		0xD0
#define LM51772_REG_MFR_SPECIFIC_D1		0xD1
#define LM51772_REG_MFR_SPECIFIC_D2		0xD2
#define LM51772_REG_MFR_SPECIFIC_D3		0xD3
#define LM51772_REG_MFR_SPECIFIC_D5		0xD5
#define LM51772_REG_MFR_SPECIFIC_D6		0xD6
#define LM51772_REG_MFR_SPECIFIC_D8		0xD8
#define LM51772_REG_MFR_SPECIFIC_D9		0xD9
#define LM51772_REG_IVP_VOLTAGE			0xDA

#define LM51772_ILIM_THRESHOLD_MASK		GENMASK(7, 0)

#define LM51772_VOUT_TARGET1_MASK		GENMASK(11, 0)

/* USB_PD_CONTROL_0 bits */
#define LM51772_CONV_EN2			BIT(0)

/* STATUS_BYTE bits */
#define LM51772_STAT_OTHER			BIT(0)
#define LM51772_STAT_CML			BIT(1)
#define LM51772_STAT_TEMP			BIT(2)
#define LM51772_STAT_IOUT			BIT(4)
#define LM51772_STAT_VOUT			BIT(5)
#define LM51772_STAT_OFF			BIT(6)

/* MFR_SPECIFIC_D0 bits */
#define LM51772_IMON_LIMITER_EN			BIT(6)
#define LM51772_EN_VCC1				BIT(5)
#define LM51772_CONV_EN				BIT(0)

/* MFR_SPECIFIC_D1 bits */
#define LM51772_EN_THER_WARN			BIT(7)
#define LM51772_THW_THRESHOLD_MASK		GENMASK(6, 5)
#define LM51772_EN_NINT				BIT(4)

/* MFR_SPECIFIC_D2 bits */
#define LM51772_EN_ACTIVE_DVS			BIT(6)
#define LM51772_DVS_SLEW_RAMP_MASK		GENMASK(5, 4)
#define LM51772_DISCHARGE_STRENGTH_MASK		GENMASK(3, 2)
/* Discharge when either CONV_EN or CONV_EN2 is disabled. */
#define LM51772_DISCHARGE_CONFIG0		BIT(1)
/* Stop discharging when Vout approaches the threshold (Vout ~= 0.5V). */
#define LM51772_DISCHARGE_CONFIG1		BIT(0)

/* MFR_SPECIFIC_D3 bits */
#define LM51772_EN_IVP				BIT(7)
#define LM51772_SEL_IVR				BIT(6)

/* MFR_SPECIFIC_D6 bits */
#define LM51772_CONFIG_SYNC_PIN_MASK		GENMASK(7, 6)

/* MFR_SPECIFIC_D8 bits */
#define LM51772_SEL_FB_DIV20			BIT(7)
#define LM51772_EN_CDC				BIT(6)

/* MFR_SPECIFIC_D9 bits */
#define LM51772_SEL_ISET_PIN			BIT(5)
#define LM51772_PCM_WINDOW_LOW_MASK		GENMASK(4, 0)

struct lm51772_priv {
	bool nint;
	unsigned int ov_lim_uv;
	unsigned int vout_curr_table[LM51772_ILIM_NSEL];
	struct regulator_desc desc[LM51772_N_REGS];
};

static int lm51772_regulator_set_thermal_protection(struct regulator_dev *rdev, int lim,
						    int severity, bool enable)
{
	static const struct linear_range thw_range_celsius = LINEAR_RANGE(95, 0, 3, 15);
	unsigned int regval = 0, mask = 0, selector = 0;
	struct regmap *regmap = rdev_get_regmap(rdev);
	long celsius = 0;
	bool found;
	int ret;

	if (severity != REGULATOR_SEVERITY_WARN)
		return -EOPNOTSUPP;

	if (lim != 0) {
		celsius = kelvin_to_celsius(lim);

		ret = linear_range_get_selector_low_array(&thw_range_celsius, 1, celsius, &selector,
							  &found);
		if (ret || !found)
			return -EINVAL;

		selector = thw_range_celsius.max_sel - selector;

		regval |= FIELD_PREP(LM51772_THW_THRESHOLD_MASK, selector);
		mask |= LM51772_THW_THRESHOLD_MASK;
	}

	regval |= FIELD_PREP(LM51772_EN_THER_WARN, enable ? 1 : 0);
	mask |= LM51772_EN_THER_WARN;

	return regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D1, mask, regval);
}

/*
 * CONV_EN2 and CONV_EN are internally OR'ed, so if one of them if set, the
 * converter operation is enabled.
 * For the get path, also OR the two bits because a previous user might have
 * set just one of them, and we can't know which one.
 * For the set path, set both bits to be consistent.
 */

static int lm51772_set_conv_en(struct regmap *regmap, bool enable)
{
	int ret;

	ret = regmap_update_bits(regmap, LM51772_REG_USB_PD_CONTROL_0, LM51772_CONV_EN2,
				 FIELD_PREP(LM51772_CONV_EN2, enable));
	if (ret)
		return ret;

	return regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D0, LM51772_CONV_EN,
				  FIELD_PREP(LM51772_CONV_EN, enable));
}

static int lm51772_get_conv_en(struct regmap *regmap)
{
	unsigned int pd_ctrl, cfg0;
	int ret;

	ret = regmap_read(regmap, LM51772_REG_USB_PD_CONTROL_0, &pd_ctrl);
	if (ret)
		return ret;

	ret = regmap_read(regmap, LM51772_REG_MFR_SPECIFIC_D0, &cfg0);
	if (ret)
		return ret;

	return FIELD_GET(LM51772_CONV_EN2, pd_ctrl) || FIELD_GET(LM51772_CONV_EN, cfg0);
}

static int lm51772_regulator_enable(struct regulator_dev *rdev)
{
	return lm51772_set_conv_en(rdev_get_regmap(rdev), true);
}

static int lm51772_regulator_disable(struct regulator_dev *rdev)
{
	return lm51772_set_conv_en(rdev_get_regmap(rdev), false);
}

static int lm51772_regulator_is_enabled(struct regulator_dev *rdev)
{
	return lm51772_get_conv_en(rdev_get_regmap(rdev));
}

static int lm51772_regulator_get_ramp_delay(struct regulator_dev *rdev, int old_uV, int new_uV)
{
	struct regmap *regmap = rdev_get_regmap(rdev);
	unsigned int reg, slew_rate_uv_per_us, sel;
	int ret, delay_us;

	ret = regmap_read(regmap, LM51772_REG_MFR_SPECIFIC_D2, &reg);
	if (ret)
		return ret;

	sel = FIELD_GET(LM51772_DVS_SLEW_RAMP_MASK, reg);
	slew_rate_uv_per_us = rdev->desc->ramp_delay_table[sel];

	delay_us = DIV_ROUND_UP(abs(new_uV - old_uV), slew_rate_uv_per_us);

	return delay_us;
}

static int lm51772_regulator_set_voltage_time(struct regulator_dev *rdev, int old_uV, int new_uV)
{
	struct lm51772_priv *priv = rdev_get_drvdata(rdev);

	if (!priv->ov_lim_uv)
		return lm51772_regulator_get_ramp_delay(rdev, old_uV, new_uV);

	/* set_voltage_sel() already waited for the ramp when OVP is used. */

	return 0;
}

static int lm51772_set_ov(struct regulator_dev *rdev, int lim_uV)
{
	static const struct linear_range ovp_ranges[] = {
		LINEAR_RANGE(4000000, 0, 0x18, 500000),
		LINEAR_RANGE(16000000, 0x18, 0x3F, 1000000),
	};
	struct regmap *regmap = rdev_get_regmap(rdev);
	unsigned int sel;
	bool found;
	int ret;

	ret = linear_range_get_selector_high_array(ovp_ranges, ARRAY_SIZE(ovp_ranges), lim_uV, &sel,
						   &found);
	if (ret)
		return ret;

	if (!found)
		sel = LM51772_OVP_MIN;

	return regmap_write(regmap, LM51772_REG_MFR_SPECIFIC_D5, sel);
}

static int lm51772_regulator_set_voltage_sel(struct regulator_dev *rdev, unsigned int sel)
{
	struct lm51772_priv *priv = rdev_get_drvdata(rdev);
	struct device *dev = rdev_get_dev(rdev);
	int curr_uv, new_uv, delay_us, ret;

	if (!priv->ov_lim_uv)
		return regulator_set_voltage_sel_pickable_regmap(rdev, sel);

	curr_uv = regulator_get_voltage_rdev(rdev);
	if (curr_uv < 0)
		return curr_uv;

	new_uv = regulator_list_voltage_pickable_linear_range(rdev, sel);
	if (new_uv < 0)
		return new_uv;

	delay_us = lm51772_regulator_get_ramp_delay(rdev, curr_uv, new_uv);
	if (delay_us < 0)
		return delay_us;

	if (new_uv > curr_uv) {
		ret = lm51772_set_ov(rdev, new_uv + priv->ov_lim_uv);
		if (ret) {
			/* Abort the voltage change, because it will trip the OVP. */
			return ret;
		}
	}

	ret = regulator_set_voltage_sel_pickable_regmap(rdev, sel);
	if (ret)
		return ret;

	fsleep(delay_us);

	if (new_uv < curr_uv) {
		ret = lm51772_set_ov(rdev, new_uv + priv->ov_lim_uv);
		if (ret) {
			/* The OVP is not precise anymore, but it is still > new voltage. */
			dev_warn(dev, "failed to set OVP after voltage change\n");
		}
	}

	return 0;
}

static int lm51772_regulator_set_over_voltage_protection(struct regulator_dev *rdev, int lim_uV,
							 int severity, bool enable)
{
	struct lm51772_priv *priv = rdev_get_drvdata(rdev);
	int ret;

	if (!enable)
		return -EOPNOTSUPP;

	if (severity != REGULATOR_SEVERITY_PROT)
		return -EOPNOTSUPP;

	priv->ov_lim_uv = lim_uV;

	/* Use default OVP threshold when no limit is requested. */
	if (!lim_uV)
		return regmap_write(rdev_get_regmap(rdev), LM51772_REG_MFR_SPECIFIC_D5,
				    LM51772_OVP_DEFAULT);

	ret = regulator_get_voltage_rdev(rdev);
	if (ret < 0)
		return ret;

	return lm51772_set_ov(rdev, ret + lim_uV);
}

static unsigned int lm51772_status2err(unsigned int status_reg)
{
	unsigned int errors = 0;

	/*
	 * The BUSY bit (bit 7) is only meaningful during device startup.
	 * The INPUT bit (bit 3) reports a VIN_UV condition, which is not a
	 * regulator output error. Ignore both.
	 */

	if (status_reg & LM51772_STAT_TEMP)
		errors |= (status_reg & LM51772_STAT_OFF) ? REGULATOR_ERROR_OVER_TEMP :
							    REGULATOR_ERROR_OVER_TEMP_WARN;

	if (status_reg & LM51772_STAT_IOUT)
		errors |= REGULATOR_ERROR_OVER_CURRENT;

	if (status_reg & LM51772_STAT_VOUT)
		errors |= REGULATOR_ERROR_OVER_VOLTAGE_WARN;

	if (status_reg & LM51772_STAT_CML || status_reg & LM51772_STAT_OTHER)
		errors |= REGULATOR_ERROR_FAIL;

	return errors;
}

static int lm51772_get_error_flags(struct regulator_dev *rdev, unsigned int *flags)
{
	struct regmap *regmap = rdev_get_regmap(rdev);
	unsigned int reg;
	int ret;

	ret = regmap_read(regmap, LM51772_REG_STATUS_BYTE, &reg);
	if (ret)
		return ret;

	*flags = lm51772_status2err(reg);

	return 0;
}

static int lm51772_irq_map_event(int irq, struct regulator_irq_data *rid, unsigned long *dev_mask)
{
	struct regmap *regmap = rid->data;
	unsigned int status, reg, errors;
	size_t bit;
	int ret;

	ret = regmap_read(regmap, LM51772_REG_STATUS_BYTE, &status);
	if (ret)
		return REGULATOR_FAILED_RETRY;

	ret = regmap_read(regmap, LM51772_REG_CLEAR_FAULTS, &reg);
	if (ret)
		return REGULATOR_FAILED_RETRY;

	errors = lm51772_status2err(status);

	rid->states[0].notifs = (status & LM51772_STAT_OFF) ? REGULATOR_EVENT_DISABLE : 0;
	rid->states[1].notifs = 0;

	rid->opaque = status;

	for (size_t i = 0; i < rid->num_states; i++) {
		rid->states[i].errors = errors & rid->states[i].possible_errs;

		for_each_set_bit(bit, &rid->states[i].errors, BITS_PER_TYPE(rid->states[i].errors))
			rid->states[i].notifs |= regulator_err2notif(BIT(bit));

		if (rid->states[i].errors || rid->states[i].notifs)
			*dev_mask |= BIT(i);
	}

	return 0;
}

static int lm51772_irq_renable(struct regulator_irq_data *rid)
{
	struct regmap *regmap = rid->data;
	unsigned int reg;
	int ret;

	ret = regmap_read(regmap, LM51772_REG_STATUS_BYTE, &reg);
	if (ret)
		return REGULATOR_FAILED_RETRY;

	if (rid->opaque && rid->opaque == reg) {
		ret = regmap_read(regmap, LM51772_REG_CLEAR_FAULTS, &reg);
		if (ret)
			return REGULATOR_FAILED_RETRY;

		return REGULATOR_ERROR_ON;
	}

	rid->opaque = 0;

	return REGULATOR_ERROR_CLEARED;
}

static int lm51772_vout_of_parse(struct device_node *np, const struct regulator_desc *desc,
				 struct regulator_config *cfg)
{
	u32 active_discharge_strength, pcm_window_low;
	unsigned int mask, val;
	int ret;

	ret = of_property_read_u32(np, "ti,active-discharge-strength-microamp",
				   &active_discharge_strength);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == -EINVAL) {
		active_discharge_strength = 0;
	} else {
		if (active_discharge_strength < LM51772_DISCHARGE_STRENGTH_MIN_UA ||
		    active_discharge_strength > LM51772_DISCHARGE_STRENGTH_MAX_UA ||
		    active_discharge_strength % LM51772_DISCHARGE_STRENGTH_STEP_UA)
			return -EINVAL;

		active_discharge_strength =
			active_discharge_strength / LM51772_DISCHARGE_STRENGTH_STEP_UA - 1;
	}

	ret = of_property_read_u32(np, "ti,pcm-window-low-permille", &pcm_window_low);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == -EINVAL) {
		pcm_window_low = LM51772_PCM_WINDOW_LOW_DFLT;
	} else {
		if (pcm_window_low % LM51772_PCM_WINDOW_LOW_STEP_PERMILLE)
			return -EINVAL;

		pcm_window_low /= LM51772_PCM_WINDOW_LOW_STEP_PERMILLE;
		if (pcm_window_low > LM51772_PCM_WINDOW_LOW_MAX)
			return -EINVAL;
	}

	mask = LM51772_DISCHARGE_STRENGTH_MASK | LM51772_EN_ACTIVE_DVS;
	val = FIELD_PREP(LM51772_DISCHARGE_STRENGTH_MASK, active_discharge_strength) |
	      FIELD_PREP(LM51772_EN_ACTIVE_DVS, 1);

	ret = regmap_update_bits(cfg->regmap, LM51772_REG_MFR_SPECIFIC_D2, mask, val);
	if (ret)
		return ret;

	mask = LM51772_PCM_WINDOW_LOW_MASK;
	val = FIELD_PREP(LM51772_PCM_WINDOW_LOW_MASK, pcm_window_low);

	ret = regmap_update_bits(cfg->regmap, LM51772_REG_MFR_SPECIFIC_D9, mask, val);
	if (ret)
		return ret;

	return 0;
}

static const struct regulator_ops lm51772_reg_default_ops = {
	.list_voltage = regulator_list_voltage_pickable_linear_range,
	.map_voltage = regulator_map_voltage_pickable_linear_range,
	.get_voltage_sel = regulator_get_voltage_sel_pickable_regmap,
	.set_voltage_sel = lm51772_regulator_set_voltage_sel,
	.set_over_voltage_protection = lm51772_regulator_set_over_voltage_protection,
	.set_thermal_protection = lm51772_regulator_set_thermal_protection,
	.set_active_discharge = regulator_set_active_discharge_regmap,
	.get_current_limit = regulator_get_current_limit_regmap,
	.set_current_limit = regulator_set_current_limit_regmap,
	.set_voltage_time = lm51772_regulator_set_voltage_time,
	.get_error_flags = lm51772_get_error_flags,
	.set_ramp_delay = regulator_set_ramp_delay_regmap,
	.is_enabled = lm51772_regulator_is_enabled,
	.enable = lm51772_regulator_enable,
	.disable = lm51772_regulator_disable
};

static const struct regulator_ops lm51772_reg_iset_ops = {
	.list_voltage = regulator_list_voltage_pickable_linear_range,
	.map_voltage = regulator_map_voltage_pickable_linear_range,
	.get_voltage_sel = regulator_get_voltage_sel_pickable_regmap,
	.set_voltage_sel = lm51772_regulator_set_voltage_sel,
	.set_over_voltage_protection = lm51772_regulator_set_over_voltage_protection,
	.set_thermal_protection = lm51772_regulator_set_thermal_protection,
	.set_active_discharge = regulator_set_active_discharge_regmap,
	.set_voltage_time = lm51772_regulator_set_voltage_time,
	.get_error_flags = lm51772_get_error_flags,
	.set_ramp_delay = regulator_set_ramp_delay_regmap,
	.is_enabled = lm51772_regulator_is_enabled,
	.enable = lm51772_regulator_enable,
	.disable = lm51772_regulator_disable
};

static int lm51772_of_parse(struct lm51772_priv *priv, struct device *dev, struct regmap *regmap)
{
	static const char *const sync_pin_modes[] = {
		"input-rising",
		"input-falling",
		"output-rising",
		"output-falling",
	};
	static const char *const input_voltage_modes[] = {
		"protection",
		"regulation",
	};
	static const struct linear_range ivp_ranges[] = {
		LINEAR_RANGE(4750000, 0x00, 0x94, 125000),
		LINEAR_RANGE(23500000, 0x95, 0xff, 250000)
	};
	bool ivp = false, ivr = false, cable_drop_compensation, found, iset_pin;
	const char *input_voltage_mode, *sync_pin_mode;
	struct regulator_desc *vout = &priv->desc[0];
	unsigned int sync_pin, selector, uv;
	u32 ivp_thres, sense_res_micro_ohms;
	int ret;

	ret = device_property_read_string(dev, "ti,input-voltage-mode", &input_voltage_mode);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == 0) {
		ret = match_string(input_voltage_modes, ARRAY_SIZE(input_voltage_modes),
				   input_voltage_mode);
		if (ret < 0)
			return -EINVAL;

		/* IVP is required for IVR to operate. */
		ivp = true;
		ivr = ret == 1;
	}

	iset_pin = device_property_read_bool(dev, "ti,iset-pin");
	priv->nint = device_property_read_bool(dev, "ti,nint");
	cable_drop_compensation = device_property_read_bool(dev, "ti,cable-drop-compensation");

	ret = device_property_read_string(dev, "ti,sync-pin", &sync_pin_mode);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == -EINVAL) {
		sync_pin = 0;
	} else {
		ret = match_string(sync_pin_modes, ARRAY_SIZE(sync_pin_modes), sync_pin_mode);
		if (ret < 0)
			return -EINVAL;

		sync_pin = ret;
	}

	ret = device_property_read_u32(dev, "shunt-resistor-micro-ohms", &sense_res_micro_ohms);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == -EINVAL)
		sense_res_micro_ohms = LM51772_SENSE_RES_DEFAULT_UOHM;
	else
		if (!sense_res_micro_ohms)
			return -EINVAL;

	ret = device_property_read_u32(dev, "ti,ivp-thres-microvolt", &ivp_thres);
	if (ret && ret != -EINVAL)
		return ret;

	if (ret == -EINVAL) {
		ivp_thres = LM51772_IVP_VOLTAGE_DEFAULT;
	} else {
		ret = linear_range_get_selector_low_array(
			ivp_ranges, ARRAY_SIZE(ivp_ranges), ivp_thres,
			&selector, &found);
		if (ret || !found)
			return -EINVAL;

		ret = linear_range_get_value_array(
			ivp_ranges, ARRAY_SIZE(ivp_ranges), selector, &uv);
		if (ret)
			return -EINVAL;

		if (uv != ivp_thres)
			return -EINVAL;

		ivp_thres = selector;
	}

	if (iset_pin) {
		vout->ops = &lm51772_reg_iset_ops;
	} else {
		unsigned int curr_uV = LM51772_ILIM_MIN_UV;

		for (size_t i = 0; i < LM51772_ILIM_NSEL; i++) {
			priv->vout_curr_table[i] =
				LM51772_ILIM_UV_TO_UA(sense_res_micro_ohms, curr_uV);

			if (i >= LM51772_ILIM_MIN_SEL && i < LM51772_ILIM_MAX_SEL)
				curr_uV += LM51772_ILIM_STEP_UV;
		}

		vout->csel_mask = LM51772_ILIM_THRESHOLD_MASK;
		vout->csel_reg = LM51772_REG_ILIM_THRESHOLD;
		vout->n_current_limits = LM51772_ILIM_NSEL;
		vout->curr_table = priv->vout_curr_table;

		vout->ops = &lm51772_reg_default_ops;
	}

	ret = regmap_update_bits(
		regmap, LM51772_REG_MFR_SPECIFIC_D3, LM51772_EN_IVP | LM51772_SEL_IVR,
		FIELD_PREP(LM51772_EN_IVP, ivp) | FIELD_PREP(LM51772_SEL_IVR, ivr));
	if (ret)
		return ret;

	ret = regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D0, LM51772_IMON_LIMITER_EN,
				 FIELD_PREP(LM51772_IMON_LIMITER_EN, 1));
	if (ret)
		return ret;

	ret = regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D6, LM51772_CONFIG_SYNC_PIN_MASK,
				 FIELD_PREP(LM51772_CONFIG_SYNC_PIN_MASK, sync_pin));
	if (ret)
		return ret;

	ret = regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D8, LM51772_EN_CDC,
				 FIELD_PREP(LM51772_EN_CDC, cable_drop_compensation));
	if (ret)
		return ret;

	ret = regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D9, LM51772_SEL_ISET_PIN,
				 FIELD_PREP(LM51772_SEL_ISET_PIN, iset_pin));
	if (ret)
		return ret;

	ret = regmap_write(regmap, LM51772_REG_IVP_VOLTAGE, ivp_thres);
	if (ret)
		return ret;

	return 0;
}

static int lm51772_setup_irq(struct device *dev, struct regmap *regmap, int irq,
			     struct regulator_dev *rdev[LM51772_N_REGS], bool nint)
{
	int common_errs = REGULATOR_ERROR_OVER_TEMP | REGULATOR_ERROR_OVER_TEMP_WARN |
			  REGULATOR_ERROR_FAIL;
	int per_rdev_errs[] = {
		REGULATOR_ERROR_OVER_CURRENT | REGULATOR_ERROR_OVER_VOLTAGE_WARN,
		0,
	};
	struct regulator_irq_desc irq_desc = {
		.name = "lm51772-irq",
		.data = regmap,
		.map_event = lm51772_irq_map_event,
		.irq_off_ms = 1000,
	};
	void *retp;
	int ret;

	if (!nint) {
		irq_desc.renable = lm51772_irq_renable;
		irq_desc.reread_ms = 200;
	}

	ret = regmap_update_bits(regmap, LM51772_REG_MFR_SPECIFIC_D1, LM51772_EN_NINT,
				 FIELD_PREP(LM51772_EN_NINT, nint));
	if (ret)
		return ret;

	retp = devm_regulator_irq_helper(dev, &irq_desc, irq, 0, common_errs, per_rdev_errs, rdev,
					 LM51772_N_REGS);

	return IS_ERR(retp) ? PTR_ERR(retp) : 0;
}

static const struct regmap_range lm51772_readable_ranges[] = {
	regmap_reg_range(LM51772_REG_CLEAR_FAULTS, LM51772_REG_CLEAR_FAULTS),
	regmap_reg_range(LM51772_REG_ILIM_THRESHOLD, LM51772_REG_ILIM_THRESHOLD),
	regmap_reg_range(LM51772_REG_VOUT_TARGET1_LSB, LM51772_REG_VOUT_TARGET1_MSB),
	regmap_reg_range(LM51772_REG_USB_PD_STATUS_0, LM51772_REG_USB_PD_STATUS_0),
	regmap_reg_range(LM51772_REG_STATUS_BYTE, LM51772_REG_STATUS_BYTE),
	regmap_reg_range(LM51772_REG_USB_PD_CONTROL_0, LM51772_REG_USB_PD_CONTROL_0),
	regmap_reg_range(LM51772_REG_MFR_SPECIFIC_D0, LM51772_REG_IVP_VOLTAGE)
};

static const struct regmap_access_table lm51772_readable_table = {
	.yes_ranges = lm51772_readable_ranges,
	.n_yes_ranges = ARRAY_SIZE(lm51772_readable_ranges)
};

static const struct regmap_range lm51772_writeable_ranges[] = {
	regmap_reg_range(LM51772_REG_CLEAR_FAULTS, LM51772_REG_CLEAR_FAULTS),
	regmap_reg_range(LM51772_REG_STATUS_BYTE, LM51772_REG_STATUS_BYTE),
	regmap_reg_range(LM51772_REG_ILIM_THRESHOLD, LM51772_REG_ILIM_THRESHOLD),
	regmap_reg_range(LM51772_REG_VOUT_TARGET1_LSB, LM51772_REG_VOUT_TARGET1_MSB),
	regmap_reg_range(LM51772_REG_USB_PD_CONTROL_0, LM51772_REG_USB_PD_CONTROL_0),
	regmap_reg_range(LM51772_REG_MFR_SPECIFIC_D0, LM51772_REG_IVP_VOLTAGE)
};

static const struct regmap_access_table lm51772_writeable_table = {
	.yes_ranges = lm51772_writeable_ranges,
	.n_yes_ranges = ARRAY_SIZE(lm51772_writeable_ranges)
};

static const struct regmap_range lm51772_volatile_ranges[] = {
	regmap_reg_range(LM51772_REG_USB_PD_STATUS_0, LM51772_REG_USB_PD_STATUS_0),
	regmap_reg_range(LM51772_REG_STATUS_BYTE, LM51772_REG_STATUS_BYTE),
	regmap_reg_range(LM51772_REG_CLEAR_FAULTS, LM51772_REG_CLEAR_FAULTS)
};

static const struct regmap_access_table lm51772_volatile_table = {
	.yes_ranges = lm51772_volatile_ranges,
	.n_yes_ranges = ARRAY_SIZE(lm51772_volatile_ranges)
};

static const struct regmap_range lm51772_precious_ranges[] = {
	regmap_reg_range(LM51772_REG_CLEAR_FAULTS, LM51772_REG_CLEAR_FAULTS)
};

static const struct regmap_access_table lm51772_precious_table = {
	.yes_ranges = lm51772_precious_ranges,
	.n_yes_ranges = ARRAY_SIZE(lm51772_precious_ranges)
};

static const struct regmap_config lm51772_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.rd_table = &lm51772_readable_table,
	.wr_table = &lm51772_writeable_table,
	.volatile_table = &lm51772_volatile_table,
	.precious_table = &lm51772_precious_table,
	.max_register = LM51772_REG_IVP_VOLTAGE,
	.cache_type = REGCACHE_MAPLE
};

static const struct regulator_ops lm51772_fixed_ops = {
	.enable = regulator_enable_regmap,
	.disable = regulator_disable_regmap,
	.is_enabled = regulator_is_enabled_regmap
};

/*
 * For < 24V, voltages are set in 10mV monotonous steps.
 * For >= 24V, voltages are set in 20mV monotonous steps.
 */
static const struct linear_range lm51772_voltage_ranges[] = {
	REGULATOR_LINEAR_RANGE(LM51772_DIV10_MIN_UV, 0, 99, 0),
	REGULATOR_LINEAR_RANGE(LM51772_DIV10_MIN_UV, 100, 2400, LM51772_DIV10_STEP_UV),

	REGULATOR_LINEAR_RANGE(LM51772_DIV20_MIN_UV, 0, 164, 0),
	REGULATOR_LINEAR_RANGE(LM51772_DIV20_MIN_UV, 165, 2400, LM51772_DIV20_STEP_UV)
};

static const unsigned int lm51772_voltage_ranges_sel[] = { 0,  0, 1, 1 };

static const unsigned int lm51772_ramp_delays[] = { 40000, 20000, 1000, 500 };

static const struct regulator_desc lm51772_regulator_template[] = {
	{ .name = "vout",
	  .of_match = of_match_ptr("vout"),
	  .of_parse_cb = lm51772_vout_of_parse,
	  .regulators_node = of_match_ptr("regulators"),
	  .id = 0,
	  .type = REGULATOR_VOLTAGE,
	  .owner = THIS_MODULE,
	  .linear_ranges = lm51772_voltage_ranges,
	  .linear_range_selectors_bitfield = lm51772_voltage_ranges_sel,
	  .n_linear_ranges = ARRAY_SIZE(lm51772_voltage_ranges),
	  .n_voltages = 100 + 2301 + 165 + 2236,
	  .vsel_reg = LM51772_REG_VOUT_TARGET1_LSB,
	  .vsel_mask = LM51772_VOUT_TARGET1_MASK,
	  .vsel_reg_oversize = true,
	  .vsel_range_reg = LM51772_REG_MFR_SPECIFIC_D8,
	  .vsel_range_mask = LM51772_SEL_FB_DIV20,
	  .active_discharge_reg = LM51772_REG_MFR_SPECIFIC_D2,
	  .active_discharge_mask = LM51772_DISCHARGE_CONFIG1 | LM51772_DISCHARGE_CONFIG0,
	  .active_discharge_on =
		  FIELD_PREP_CONST(LM51772_DISCHARGE_CONFIG1, 1) |
		  FIELD_PREP_CONST(LM51772_DISCHARGE_CONFIG0, 1),
	  .active_discharge_off =
		  FIELD_PREP_CONST(LM51772_DISCHARGE_CONFIG1, 0) |
		  FIELD_PREP_CONST(LM51772_DISCHARGE_CONFIG0, 0),
	  .ramp_reg = LM51772_REG_MFR_SPECIFIC_D2,
	  .ramp_mask = LM51772_DVS_SLEW_RAMP_MASK,
	  .ramp_delay_table = lm51772_ramp_delays,
	  .n_ramp_values = ARRAY_SIZE(lm51772_ramp_delays)
	},
	{
		.name = "vcc1",
		.of_match = of_match_ptr("vcc1"),
		.regulators_node = of_match_ptr("regulators"),
		.id = 1,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.ops = &lm51772_fixed_ops,
		.fixed_uV = LM51772_VCC1_LDO_UV,
		.n_voltages = LM51772_VCC1_LDO_NV,
		.enable_reg = LM51772_REG_MFR_SPECIFIC_D0,
		.enable_mask = LM51772_EN_VCC1,
	},
};

static int lm51772_probe(struct i2c_client *client)
{
	struct regulator_dev *rdev[LM51772_N_REGS];
	struct regulator_config config = {};
	struct device *dev = &client->dev;
	struct lm51772_priv *priv;
	struct regmap *regmap;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	memcpy(priv->desc, lm51772_regulator_template, sizeof(lm51772_regulator_template));

	ret = devm_regulator_get_enable_optional(dev, "vin");
	if (ret < 0 && ret != -ENODEV)
		return dev_err_probe(dev, ret, "unable to get vin regulator\n");

	regmap = devm_regmap_init_i2c(client, &lm51772_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap), "unable to init regmap\n");

	config.dev = dev;
	config.driver_data = priv;
	config.regmap = regmap;

	ret = lm51772_of_parse(priv, dev, regmap);
	if (ret)
		return dev_err_probe(dev, ret, "unable to parse dt node\n");

	for (size_t i = 0; i < LM51772_N_REGS; i++) {
		rdev[i] = devm_regulator_register(dev, &priv->desc[i], &config);
		if (IS_ERR(rdev[i]))
			return dev_err_probe(dev, PTR_ERR(rdev[i]),
					     "unable to register regulator %s\n",
					     priv->desc[i].name);
	}

	ret = lm51772_setup_irq(dev, regmap, client->irq, rdev, priv->nint);
	if (ret)
		return dev_err_probe(dev, ret, "unable to request irq\n");

	return 0;
}

static const struct of_device_id lm51772_of_match[] = {
	{ .compatible = "ti,lm51772" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, lm51772_of_match);

static const struct i2c_device_id lm51772_id[] = {
	{ .name = "lm51772" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(i2c, lm51772_id);

static struct i2c_driver lm51772_driver = {
	.driver = {
		.name = "lm51772",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.of_match_table = lm51772_of_match,
	},
	.probe = lm51772_probe,
	.id_table = lm51772_id,
};

module_i2c_driver(lm51772_driver);

MODULE_AUTHOR("Paul Louvel <paul.louvel@bootlin.com>");
MODULE_DESCRIPTION("TI LM51772 I2C regulator driver");
MODULE_LICENSE("GPL");
