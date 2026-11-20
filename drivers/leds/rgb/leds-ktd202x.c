// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kinetic KTD2026/7 RGB/White LED driver with I2C interface
 *
 * Copyright 2023 André Apitzsch <git@apitzsch.eu>
 *
 * Datasheet: https://www.kinet-ic.com/uploads/KTD2026-7-04h.pdf
 */

#include <linux/i2c.h>
#include <linux/led-class-multicolor.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/overflow.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>

#define KTD2026_NUM_LEDS 3
#define KTD2027_NUM_LEDS 4
#define KTD202X_MAX_LEDS 4

/* Register bank */
#define KTD202X_REG_RESET_CONTROL	0x00
#define KTD202X_REG_FLASH_PERIOD	0x01
#define KTD202X_REG_PWM1_TIMER		0x02
#define KTD202X_REG_PWM2_TIMER		0x03
#define KTD202X_REG_CHANNEL_CTRL	0x04
#define KTD202X_REG_TRISE_FALL		0x05
#define KTD202X_REG_LED_IOUT(x)		(0x06 + (x))

/* Register 0 */
#define KTD202X_TIMER_SLOT_CONTROL_TSLOT1	0x00
#define KTD202X_TIMER_SLOT_CONTROL_TSLOT2	0x01
#define KTD202X_TIMER_SLOT_CONTROL_TSLOT3	0x02
#define KTD202X_TIMER_SLOT_CONTROL_TSLOT4	0x03
#define KTD202X_RSTR_RESET			0x07

#define KTD202X_ENABLE_CTRL_WAKE	0x00 /* SCL High & SDA High */
#define KTD202X_ENABLE_CTRL_SLEEP	0x08 /* SCL High & SDA Toggling */

#define KTD202X_TRISE_FALL_SCALE_NORMAL		0x00
#define KTD202X_TRISE_FALL_SCALE_SLOW_X2	0x20
#define KTD202X_TRISE_FALL_SCALE_SLOW_X4	0x40
#define KTD202X_TRISE_FALL_SCALE_FAST_X8	0x60

/* Register 1 */
#define KTD202X_FLASH_PERIOD_256_MS_LOG_RAMP	0x00

/* Register 2-3 */
#define KTD202X_FLASH_ON_TIME_0_4_PERCENT	0x01

/* Register 4 */
#define KTD202X_CHANNEL_CTRL_MASK(x) (BIT(2 * (x)) | BIT(2 * (x) + 1))
#define KTD202X_CHANNEL_CTRL_OFF 0x00
#define KTD202X_CHANNEL_CTRL_ON(x) BIT(2 * (x))
#define KTD202X_CHANNEL_CTRL_PWM1(x) BIT(2 * (x) + 1)
#define KTD202X_CHANNEL_CTRL_PWM2(x) (BIT(2 * (x)) | BIT(2 * (x) + 1))

/* Register 5 */
#define KTD202X_RAMP_TIMES_2_MS			0x00
#define KTD202X_RAMP_TRISE(x)			(x)
#define KTD202X_RAMP_TFALL_SHIFT		4
#define KTD202X_RAMP_TFALL(x)			((x) << KTD202X_RAMP_TFALL_SHIFT)

/* Register 6-9 */
#define KTD202X_LED_CURRENT_10_mA		0x4f

#define KTD202X_FLASH_PERIOD_MIN_MS 256
#define KTD202X_FLASH_PERIOD_STEP_MS 128
#define KTD202X_FLASH_PERIOD_MAX_STEPS 126
#define ET6326_FLASH_PERIOD_MIN_MS 128
#define ET6326_FLASH_PERIOD_MAX_STEPS 127
#define KTD202X_FLASH_ON_MIN 1
#define KTD202X_FLASH_ON_MAX 256
#define KTD202X_RAMP_STEP_MS 128
#define KTD202X_RAMP_MAX_STEPS 15

/* Rise, high, fall and low */
#define KTD202X_PATTERN_LEN 4
#define KTD202X_PATTERN_MAX_MS 16384

#define KTD202X_MAX_BRIGHTNESS 192
#define KTD202X_LED_CURRENT_STEP_uA 125

static const struct reg_default ktd202x_reg_defaults[] = {
	{ KTD202X_REG_RESET_CONTROL, KTD202X_TIMER_SLOT_CONTROL_TSLOT1 |
		KTD202X_ENABLE_CTRL_WAKE | KTD202X_TRISE_FALL_SCALE_NORMAL },
	{ KTD202X_REG_FLASH_PERIOD, KTD202X_FLASH_PERIOD_256_MS_LOG_RAMP },
	{ KTD202X_REG_PWM1_TIMER, KTD202X_FLASH_ON_TIME_0_4_PERCENT },
	{ KTD202X_REG_PWM2_TIMER, KTD202X_FLASH_ON_TIME_0_4_PERCENT },
	{ KTD202X_REG_CHANNEL_CTRL, KTD202X_CHANNEL_CTRL_OFF },
	{ KTD202X_REG_TRISE_FALL, KTD202X_RAMP_TIMES_2_MS },
	{ KTD202X_REG_LED_IOUT(0), KTD202X_LED_CURRENT_10_mA },
	{ KTD202X_REG_LED_IOUT(1), KTD202X_LED_CURRENT_10_mA },
	{ KTD202X_REG_LED_IOUT(2), KTD202X_LED_CURRENT_10_mA },
	{ KTD202X_REG_LED_IOUT(3), KTD202X_LED_CURRENT_10_mA },
};

struct ktd202x_caps {
	unsigned long num_leds;
	unsigned int flash_period_min_ms;
	unsigned int flash_period_max_steps;
};

static const struct ktd202x_caps ktd2026_caps = {
	.num_leds = KTD2026_NUM_LEDS,
	.flash_period_min_ms = KTD202X_FLASH_PERIOD_MIN_MS,
	.flash_period_max_steps = KTD202X_FLASH_PERIOD_MAX_STEPS,
};

static const struct ktd202x_caps ktd2027_caps = {
	.num_leds = KTD2027_NUM_LEDS,
	.flash_period_min_ms = KTD202X_FLASH_PERIOD_MIN_MS,
	.flash_period_max_steps = KTD202X_FLASH_PERIOD_MAX_STEPS,
};

static const struct ktd202x_caps et6326_caps = {
	.num_leds = KTD2026_NUM_LEDS,
	.flash_period_min_ms = ET6326_FLASH_PERIOD_MIN_MS,
	.flash_period_max_steps = ET6326_FLASH_PERIOD_MAX_STEPS,
};

struct ktd202x_led {
	struct ktd202x *chip;
	union {
		struct led_classdev cdev;
		struct led_classdev_mc mcdev;
	};
	u32 index;
};

struct ktd202x {
	struct mutex mutex;
	struct regulator_bulk_data regulators[2];
	struct device *dev;
	struct regmap *regmap;
	const struct ktd202x_caps *caps;
	bool enabled;
	unsigned long num_leds;
	struct ktd202x_led leds[] __counted_by(num_leds);
};

static int ktd202x_chip_disable(struct ktd202x *chip)
{
	int ret;

	if (!chip->enabled)
		return 0;

	regmap_write(chip->regmap, KTD202X_REG_RESET_CONTROL, KTD202X_ENABLE_CTRL_SLEEP);

	ret = regulator_bulk_disable(ARRAY_SIZE(chip->regulators), chip->regulators);
	if (ret) {
		dev_err(chip->dev, "Failed to disable regulators: %d\n", ret);
		return ret;
	}

	chip->enabled = false;
	return 0;
}

static int ktd202x_chip_enable(struct ktd202x *chip)
{
	int ret;

	if (chip->enabled)
		return 0;

	ret = regulator_bulk_enable(ARRAY_SIZE(chip->regulators), chip->regulators);
	if (ret) {
		dev_err(chip->dev, "Failed to enable regulators: %d\n", ret);
		return ret;
	}
	chip->enabled = true;

	ret = regmap_write(chip->regmap, KTD202X_REG_RESET_CONTROL, KTD202X_ENABLE_CTRL_WAKE);

	if (ret) {
		dev_err(chip->dev, "Failed to enable the chip: %d\n", ret);
		ktd202x_chip_disable(chip);
	}

	return ret;
}

static bool ktd202x_chip_in_use(struct ktd202x *chip)
{
	int i;

	for (i = 0; i < chip->num_leds; i++) {
		if (chip->leds[i].cdev.brightness)
			return true;
	}

	return false;
}

static int ktd202x_brightness_set(struct ktd202x_led *led,
				  struct mc_subled *subleds,
				  unsigned int num_channels)
{
	bool mode_blink = false;
	int channel;
	int state;
	int ret;
	int i;

	if (ktd202x_chip_in_use(led->chip)) {
		ret = ktd202x_chip_enable(led->chip);
		if (ret)
			return ret;
	}

	ret = regmap_read(led->chip->regmap, KTD202X_REG_CHANNEL_CTRL, &state);
	if (ret)
		return ret;

	/*
	 * In multicolor case, assume blink mode if PWM is set for at least one
	 * channel because another channel cannot be in state ON at the same time
	 */
	for (i = 0; i < num_channels; i++) {
		int channel_state;

		channel = subleds[i].channel;
		channel_state = (state >> 2 * channel) & KTD202X_CHANNEL_CTRL_MASK(0);
		if (channel_state == KTD202X_CHANNEL_CTRL_OFF)
			continue;
		mode_blink = channel_state == KTD202X_CHANNEL_CTRL_PWM1(0);
		break;
	}

	for (i = 0; i < num_channels; i++) {
		enum led_brightness brightness;
		int mode;

		brightness = subleds[i].brightness;
		channel = subleds[i].channel;

		if (brightness) {
			/* Register expects brightness between 0 and MAX_BRIGHTNESS - 1 */
			ret = regmap_write(led->chip->regmap, KTD202X_REG_LED_IOUT(channel),
					   brightness - 1);
			if (ret)
				return ret;

			if (mode_blink)
				mode = KTD202X_CHANNEL_CTRL_PWM1(channel);
			else
				mode = KTD202X_CHANNEL_CTRL_ON(channel);
		} else {
			mode = KTD202X_CHANNEL_CTRL_OFF;
		}
		ret = regmap_update_bits(led->chip->regmap, KTD202X_REG_CHANNEL_CTRL,
					 KTD202X_CHANNEL_CTRL_MASK(channel), mode);
		if (ret)
			return ret;
	}

	if (!ktd202x_chip_in_use(led->chip))
		return ktd202x_chip_disable(led->chip);

	return 0;
}

static int ktd202x_brightness_single_set(struct led_classdev *cdev,
					 enum led_brightness value)
{
	struct ktd202x_led *led = container_of(cdev, struct ktd202x_led, cdev);
	struct mc_subled info;
	int ret;

	cdev->brightness = value;

	mutex_lock(&led->chip->mutex);

	info.brightness = value;
	info.channel = led->index;
	ret = ktd202x_brightness_set(led, &info, 1);

	mutex_unlock(&led->chip->mutex);

	return ret;
}

static int ktd202x_brightness_mc_set(struct led_classdev *cdev,
				     enum led_brightness value)
{
	struct led_classdev_mc *mc = lcdev_to_mccdev(cdev);
	struct ktd202x_led *led = container_of(mc, struct ktd202x_led, mcdev);
	int ret;

	cdev->brightness = value;

	mutex_lock(&led->chip->mutex);

	led_mc_calc_color_components(mc, value);
	ret = ktd202x_brightness_set(led, mc->subled_info, mc->num_colors);

	mutex_unlock(&led->chip->mutex);

	return ret;
}

static unsigned int ktd202x_flash_period_steps(const struct ktd202x_caps *caps,
					       unsigned long period_ms)
{
	if (period_ms < caps->flash_period_min_ms)
		return 0;

	return min_t(unsigned long, caps->flash_period_max_steps,
		     (period_ms - caps->flash_period_min_ms) /
		     KTD202X_FLASH_PERIOD_STEP_MS);
}

static unsigned long ktd202x_flash_period_ms(const struct ktd202x_caps *caps,
					     unsigned int num_steps)
{
	return num_steps * KTD202X_FLASH_PERIOD_STEP_MS + caps->flash_period_min_ms;
}

static int ktd202x_blink_set(struct ktd202x_led *led, unsigned long *delay_on,
			     unsigned long *delay_off, struct mc_subled *subleds,
			     unsigned int num_channels)
{
	const struct ktd202x_caps *caps = led->chip->caps;
	unsigned long delay_total_ms;
	int ret, num_steps, on;
	u8 ctrl_mask = 0;
	u8 ctrl_pwm1 = 0;
	u8 ctrl_on = 0;
	int i;

	mutex_lock(&led->chip->mutex);

	for (i = 0; i < num_channels; i++) {
		int channel = subleds[i].channel;

		ctrl_mask |= KTD202X_CHANNEL_CTRL_MASK(channel);

		/* A color with no brightness stays off */
		if (!subleds[i].brightness)
			continue;

		ctrl_on |= KTD202X_CHANNEL_CTRL_ON(channel);
		ctrl_pwm1 |= KTD202X_CHANNEL_CTRL_PWM1(channel);
	}

	/* Never off - brightness is already set, disable blinking */
	if (!*delay_off) {
		ret = regmap_update_bits(led->chip->regmap, KTD202X_REG_CHANNEL_CTRL,
					 ctrl_mask, ctrl_on);
		goto out;
	}

	/* Convert into values the HW will understand. */

	/* Integer representation of time of flash period */
	if (check_add_overflow(*delay_on, *delay_off, &delay_total_ms))
		delay_total_ms = ULONG_MAX;
	num_steps = ktd202x_flash_period_steps(caps, delay_total_ms);

	/*
	 * Integer representation of percentage of LED ON time. A value of 0
	 * keeps the LED dark, so use the shortest on time instead.
	 */
	on = mul_u64_u64_div_u64(*delay_on, KTD202X_FLASH_ON_MAX, delay_total_ms);
	on = clamp(on, KTD202X_FLASH_ON_MIN, KTD202X_FLASH_ON_MAX - 1);

	/* Actually used delay_{on,off} values */
	delay_total_ms = ktd202x_flash_period_ms(caps, num_steps);
	/*
	 * Rounded to the nearest ms, so that the delays give the same on time
	 * when written back. Rounded down, 1/256 of the 128 ms ET6326 period
	 * would be 0 ms, which means never on.
	 */
	*delay_on = clamp(DIV_ROUND_CLOSEST(delay_total_ms * on, KTD202X_FLASH_ON_MAX),
			  1UL, delay_total_ms - 1);
	*delay_off = delay_total_ms - *delay_on;

	/* Set timings */
	ret = regmap_write(led->chip->regmap, KTD202X_REG_FLASH_PERIOD, num_steps);
	if (ret)
		goto out;

	ret = regmap_write(led->chip->regmap, KTD202X_REG_PWM1_TIMER, on);
	if (ret)
		goto out;

	/* Drop the ramps a hardware pattern may have left behind */
	ret = regmap_write(led->chip->regmap, KTD202X_REG_TRISE_FALL,
			   KTD202X_RAMP_TIMES_2_MS);
	if (ret)
		goto out;

	ret = regmap_update_bits(led->chip->regmap, KTD202X_REG_CHANNEL_CTRL,
				 ctrl_mask, ctrl_pwm1);
out:
	mutex_unlock(&led->chip->mutex);
	return ret;
}

static int ktd202x_blink_single_set(struct led_classdev *cdev,
				    unsigned long *delay_on,
				    unsigned long *delay_off)
{
	struct ktd202x_led *led = container_of(cdev, struct ktd202x_led, cdev);
	struct mc_subled info;
	int ret;

	if (!cdev->brightness) {
		ret = ktd202x_brightness_single_set(cdev, cdev->max_brightness);
		if (ret)
			return ret;
	}

	/* If no blink specified, default to 1 Hz. */
	if (!*delay_off && !*delay_on) {
		*delay_off = 500;
		*delay_on = 500;
	}

	/* Never on - just set to off */
	if (!*delay_on)
		return ktd202x_brightness_single_set(cdev, LED_OFF);

	info.brightness = cdev->brightness;
	info.channel = led->index;

	return ktd202x_blink_set(led, delay_on, delay_off, &info, 1);
}

static int ktd202x_blink_mc_set(struct led_classdev *cdev,
				unsigned long *delay_on,
				unsigned long *delay_off)
{
	struct led_classdev_mc *mc = lcdev_to_mccdev(cdev);
	struct ktd202x_led *led = container_of(mc, struct ktd202x_led, mcdev);
	int ret;

	if (!cdev->brightness) {
		ret = ktd202x_brightness_mc_set(cdev, KTD202X_MAX_BRIGHTNESS);
		if (ret)
			return ret;
	}

	/* If no blink specified, default to 1 Hz. */
	if (!*delay_off && !*delay_on) {
		*delay_off = 500;
		*delay_on = 500;
	}

	/* Never on - just set to off */
	if (!*delay_on)
		return ktd202x_brightness_mc_set(cdev, LED_OFF);

	return ktd202x_blink_set(led, delay_on, delay_off, mc->subled_info,
				 mc->num_colors);
}

/*
 * The hardware pattern is a single breathing cycle that repeats forever:
 *
 *   "0 rise brightness high brightness fall 0 low"
 *
 * The LED ramps up for the rise time, stays at the brightness for the high
 * time, ramps down for the fall time and stays off for the low time.
 */
static int ktd202x_pattern_check(struct led_classdev *cdev,
				 struct led_pattern *pattern, u32 len,
				 int repeat)
{
	/*
	 * Only forever: the pattern trigger passes -1, or 0 when repeat
	 * has not been written since the trigger was set.
	 */
	if (len != KTD202X_PATTERN_LEN || repeat > 0)
		return -EINVAL;

	if (pattern[0].brightness || pattern[3].brightness ||
	    pattern[1].brightness != pattern[2].brightness ||
	    pattern[1].brightness <= 0 ||
	    pattern[1].brightness > cdev->max_brightness)
		return -EINVAL;

	return 0;
}

static int ktd202x_pattern_program(struct ktd202x_led *led,
				   struct led_pattern *pattern,
				   struct mc_subled *subleds,
				   unsigned int num_channels)
{
	const struct ktd202x_caps *caps = led->chip->caps;
	unsigned int rise_ms, high_ms, fall_ms, low_ms;
	unsigned int rise_steps, fall_steps, num_steps, on;
	unsigned long period_ms, ton_ms;
	u8 ctrl_mask = 0;
	u8 ctrl_pwm1 = 0;
	int ret;

	rise_ms = min_t(u32, pattern[0].delta_t, KTD202X_PATTERN_MAX_MS);
	high_ms = min_t(u32, pattern[1].delta_t, KTD202X_PATTERN_MAX_MS);
	fall_ms = min_t(u32, pattern[2].delta_t, KTD202X_PATTERN_MAX_MS);
	low_ms = min_t(u32, pattern[3].delta_t, KTD202X_PATTERN_MAX_MS);

	rise_steps = min_t(unsigned int, KTD202X_RAMP_MAX_STEPS,
			   DIV_ROUND_CLOSEST(rise_ms, KTD202X_RAMP_STEP_MS));
	fall_steps = min_t(unsigned int, KTD202X_RAMP_MAX_STEPS,
			   DIV_ROUND_CLOSEST(fall_ms, KTD202X_RAMP_STEP_MS));

	/* Round the period up so that the fall ramp is not cut short */
	period_ms = rise_ms + high_ms + fall_ms + low_ms;
	num_steps = ktd202x_flash_period_steps(caps, period_ms + KTD202X_FLASH_PERIOD_STEP_MS - 1);
	period_ms = ktd202x_flash_period_ms(caps, num_steps);

	/* The on time includes the rise time */
	ton_ms = rise_ms + high_ms;
	on = clamp_t(unsigned long, DIV_ROUND_CLOSEST(ton_ms * KTD202X_FLASH_ON_MAX, period_ms),
		     KTD202X_FLASH_ON_MIN, KTD202X_FLASH_ON_MAX - 1);

	guard(mutex)(&led->chip->mutex);

	for (unsigned int i = 0; i < num_channels; i++) {
		int channel = subleds[i].channel;

		ctrl_mask |= KTD202X_CHANNEL_CTRL_MASK(channel);

		/* A color with no brightness stays off */
		if (!subleds[i].brightness)
			continue;

		ctrl_pwm1 |= KTD202X_CHANNEL_CTRL_PWM1(channel);
	}

	ret = regmap_write(led->chip->regmap, KTD202X_REG_FLASH_PERIOD, num_steps);
	if (ret)
		return ret;

	ret = regmap_write(led->chip->regmap, KTD202X_REG_PWM1_TIMER, on);
	if (ret)
		return ret;

	ret = regmap_write(led->chip->regmap, KTD202X_REG_TRISE_FALL,
			   KTD202X_RAMP_TFALL(fall_steps) | KTD202X_RAMP_TRISE(rise_steps));
	if (ret)
		return ret;

	return regmap_update_bits(led->chip->regmap, KTD202X_REG_CHANNEL_CTRL,
				  ctrl_mask, ctrl_pwm1);
}

static int ktd202x_pattern_single_set(struct led_classdev *cdev,
				      struct led_pattern *pattern, u32 len,
				      int repeat)
{
	struct ktd202x_led *led = container_of(cdev, struct ktd202x_led, cdev);
	struct mc_subled info;
	int ret;

	ret = ktd202x_pattern_check(cdev, pattern, len, repeat);
	if (ret)
		return ret;

	ret = ktd202x_brightness_single_set(cdev, pattern[1].brightness);
	if (ret)
		return ret;

	info.brightness = cdev->brightness;
	info.channel = led->index;

	return ktd202x_pattern_program(led, pattern, &info, 1);
}

static int ktd202x_pattern_single_clear(struct led_classdev *cdev)
{
	return ktd202x_brightness_single_set(cdev, LED_OFF);
}

static int ktd202x_pattern_mc_set(struct led_classdev *cdev,
				  struct led_pattern *pattern, u32 len,
				  int repeat)
{
	struct led_classdev_mc *mc = lcdev_to_mccdev(cdev);
	struct ktd202x_led *led = container_of(mc, struct ktd202x_led, mcdev);
	int ret;

	ret = ktd202x_pattern_check(cdev, pattern, len, repeat);
	if (ret)
		return ret;

	ret = ktd202x_brightness_mc_set(cdev, pattern[1].brightness);
	if (ret)
		return ret;

	return ktd202x_pattern_program(led, pattern, mc->subled_info,
				       mc->num_colors);
}

static int ktd202x_pattern_mc_clear(struct led_classdev *cdev)
{
	return ktd202x_brightness_mc_set(cdev, LED_OFF);
}

/* The current limit of a LED in brightness steps, each of which adds 0.125 mA */
static unsigned int ktd202x_max_brightness(struct fwnode_handle *fwnode)
{
	u32 max_microamp;

	if (fwnode_property_read_u32(fwnode, "led-max-microamp", &max_microamp))
		return KTD202X_MAX_BRIGHTNESS;

	return clamp_t(u32, max_microamp / KTD202X_LED_CURRENT_STEP_uA, 1,
		       KTD202X_MAX_BRIGHTNESS);
}

static int ktd202x_setup_led_rgb(struct ktd202x *chip, struct fwnode_handle *fwnode,
				 struct ktd202x_led *led, struct led_init_data *init_data)
{
	struct fwnode_handle *child;
	struct led_classdev *cdev;
	struct mc_subled *info;
	int num_channels;
	int i = 0;

	num_channels = 0;
	fwnode_for_each_child_node(fwnode, child)
		num_channels++;

	if (!num_channels || num_channels > chip->num_leds)
		return -EINVAL;

	info = devm_kcalloc(chip->dev, num_channels, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	fwnode_for_each_child_node(fwnode, child) {
		u32 mono_color;
		u32 reg;
		int ret;

		ret = fwnode_property_read_u32(child, "reg", &reg);
		if (ret != 0 || reg >= chip->num_leds) {
			dev_err(chip->dev, "invalid 'reg' of %pfw\n", child);
			fwnode_handle_put(child);
			return ret;
		}

		ret = fwnode_property_read_u32(child, "color", &mono_color);
		if (ret < 0 && ret != -EINVAL) {
			dev_err(chip->dev, "failed to parse 'color' of %pfw\n", child);
			fwnode_handle_put(child);
			return ret;
		}

		info[i].color_index = mono_color;
		info[i].channel = reg;
		info[i].intensity = KTD202X_MAX_BRIGHTNESS;
		i++;
	}

	led->mcdev.subled_info = info;
	led->mcdev.num_colors = num_channels;

	cdev = &led->mcdev.led_cdev;
	cdev->max_brightness = KTD202X_MAX_BRIGHTNESS;
	cdev->brightness_set_blocking = ktd202x_brightness_mc_set;
	cdev->blink_set = ktd202x_blink_mc_set;
	cdev->pattern_set = ktd202x_pattern_mc_set;
	cdev->pattern_clear = ktd202x_pattern_mc_clear;

	return devm_led_classdev_multicolor_register_ext(chip->dev, &led->mcdev, init_data);
}

static int ktd202x_setup_led_single(struct ktd202x *chip, struct fwnode_handle *fwnode,
				    struct ktd202x_led *led, struct led_init_data *init_data)
{
	struct led_classdev *cdev;
	u32 reg;
	int ret;

	ret = fwnode_property_read_u32(fwnode, "reg", &reg);
	if (ret != 0 || reg >= chip->num_leds) {
		dev_err(chip->dev, "invalid 'reg' of %pfw\n", fwnode);
		return -EINVAL;
	}
	led->index = reg;

	cdev = &led->cdev;
	cdev->max_brightness = ktd202x_max_brightness(fwnode);

	cdev->brightness_set_blocking = ktd202x_brightness_single_set;
	cdev->blink_set = ktd202x_blink_single_set;
	cdev->pattern_set = ktd202x_pattern_single_set;
	cdev->pattern_clear = ktd202x_pattern_single_clear;

	return devm_led_classdev_register_ext(chip->dev, &led->cdev, init_data);
}

static int ktd202x_add_led(struct ktd202x *chip, struct fwnode_handle *fwnode, unsigned int index)
{
	struct ktd202x_led *led = &chip->leds[index];
	struct led_init_data init_data = {};
	struct led_classdev *cdev;
	u32 color;
	int ret;

	/* Color property is optional in single color case */
	ret = fwnode_property_read_u32(fwnode, "color", &color);
	if (ret < 0 && ret != -EINVAL) {
		dev_err(chip->dev, "failed to parse 'color' of %pfw\n", fwnode);
		return ret;
	}

	led->chip = chip;
	init_data.fwnode = fwnode;

	if (color == LED_COLOR_ID_RGB) {
		cdev = &led->mcdev.led_cdev;
		ret = ktd202x_setup_led_rgb(chip, fwnode, led, &init_data);
	} else {
		cdev = &led->cdev;
		ret = ktd202x_setup_led_single(chip, fwnode, led, &init_data);
	}

	if (ret) {
		dev_err(chip->dev, "unable to register %s\n", cdev->name);
		return ret;
	}

	return 0;
}

static int ktd202x_probe_fw(struct ktd202x *chip)
{
	struct device *dev = chip->dev;
	int count;
	int i = 0;

	count = device_get_child_node_count(dev);
	if (!count || count > chip->num_leds)
		return -EINVAL;

	regmap_write(chip->regmap, KTD202X_REG_RESET_CONTROL, KTD202X_RSTR_RESET);

	/* Allow the device to execute the complete reset */
	usleep_range(200, 300);

	device_for_each_child_node_scoped(dev, child) {
		int ret = ktd202x_add_led(chip, child, i);

		if (ret)
			return ret;

		i++;
	}

	return 0;
}

static const struct regmap_config ktd202x_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 0x09,
	.cache_type = REGCACHE_FLAT,
	.reg_defaults = ktd202x_reg_defaults,
	.num_reg_defaults = ARRAY_SIZE(ktd202x_reg_defaults),
};

static int ktd202x_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	const struct ktd202x_caps *caps;
	struct ktd202x *chip;
	int count;
	int ret;

	count = device_get_child_node_count(dev);
	if (!count || count > KTD202X_MAX_LEDS)
		return dev_err_probe(dev, -EINVAL, "Incorrect number of leds (%d)", count);

	caps = i2c_get_match_data(client);
	if (!caps)
		return -ENODEV;

	/* Loops over the LEDs go up to the number of channels, not of child nodes */
	chip = devm_kzalloc(dev, struct_size(chip, leds, caps->num_leds), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->caps = caps;
	chip->num_leds = caps->num_leds;
	chip->dev = dev;
	i2c_set_clientdata(client, chip);

	chip->regmap = devm_regmap_init_i2c(client, &ktd202x_regmap_config);
	if (IS_ERR(chip->regmap)) {
		ret = dev_err_probe(dev, PTR_ERR(chip->regmap),
				    "Failed to allocate register map.\n");
		return ret;
	}

	ret = devm_mutex_init(dev, &chip->mutex);
	if (ret)
		return ret;

	chip->regulators[0].supply = "vin";
	chip->regulators[1].supply = "vio";
	ret = devm_regulator_bulk_get(dev, ARRAY_SIZE(chip->regulators), chip->regulators);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Failed to request regulators.\n");
		return ret;
	}

	ret = regulator_bulk_enable(ARRAY_SIZE(chip->regulators), chip->regulators);
	if (ret) {
		dev_err_probe(dev, ret, "Failed to enable regulators.\n");
		return ret;
	}

	ret = ktd202x_probe_fw(chip);
	if (ret < 0) {
		regulator_bulk_disable(ARRAY_SIZE(chip->regulators), chip->regulators);
		return ret;
	}

	ret = regulator_bulk_disable(ARRAY_SIZE(chip->regulators), chip->regulators);
	if (ret) {
		dev_err_probe(dev, ret, "Failed to disable regulators.\n");
		return ret;
	}

	return 0;
}

static void ktd202x_remove(struct i2c_client *client)
{
	struct ktd202x *chip = i2c_get_clientdata(client);

	ktd202x_chip_disable(chip);
}

static void ktd202x_shutdown(struct i2c_client *client)
{
	struct ktd202x *chip = i2c_get_clientdata(client);

	/* Reset registers to make sure all LEDs are off before shutdown */
	regmap_write(chip->regmap, KTD202X_REG_RESET_CONTROL, KTD202X_RSTR_RESET);
}

static const struct i2c_device_id ktd202x_id[] = {
	{ .name = "et6326", .driver_data = (kernel_ulong_t)&et6326_caps },
	{ .name = "ktd2026", .driver_data = (kernel_ulong_t)&ktd2026_caps },
	{ .name = "ktd2027", .driver_data = (kernel_ulong_t)&ktd2027_caps },
	{ }
};
MODULE_DEVICE_TABLE(i2c, ktd202x_id);

static const struct of_device_id ktd202x_match_table[] = {
	{ .compatible = "etekmicro,et6326", .data = &et6326_caps },
	{ .compatible = "kinetic,ktd2026", .data = &ktd2026_caps },
	{ .compatible = "kinetic,ktd2027", .data = &ktd2027_caps },
	{}
};
MODULE_DEVICE_TABLE(of, ktd202x_match_table);

static struct i2c_driver ktd202x_driver = {
	.driver = {
		.name = "leds-ktd202x",
		.of_match_table = ktd202x_match_table,
	},
	.probe = ktd202x_probe,
	.remove = ktd202x_remove,
	.shutdown = ktd202x_shutdown,
	.id_table = ktd202x_id,
};
module_i2c_driver(ktd202x_driver);

MODULE_AUTHOR("André Apitzsch <git@apitzsch.eu>");
MODULE_DESCRIPTION("Kinetic KTD2026/7 and Etek ET6326 LED driver");
MODULE_LICENSE("GPL");
