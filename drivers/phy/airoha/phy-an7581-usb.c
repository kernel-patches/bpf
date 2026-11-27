// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Christian Marangi <ansuelsmth@gmail.com>
 */

#include <dt-bindings/phy/phy.h>
#include <dt-bindings/soc/airoha,scu-ssr.h>
#include <linux/bitfield.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/mfd/syscon.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

/* U2PHY */
#define AIROHA_USB_PHY_FMCR0			0x100
#define   AIROHA_USB_PHY_MONCLK_SEL		GENMASK(27, 26)
#define   AIROHA_USB_PHY_MONCLK_SEL0		FIELD_PREP_CONST(AIROHA_USB_PHY_MONCLK_SEL, 0x0)
#define   AIROHA_USB_PHY_MONCLK_SEL1		FIELD_PREP_CONST(AIROHA_USB_PHY_MONCLK_SEL, 0x1)
#define   AIROHA_USB_PHY_MONCLK_SEL2		FIELD_PREP_CONST(AIROHA_USB_PHY_MONCLK_SEL, 0x2)
#define   AIROHA_USB_PHY_MONCLK_SEL3		FIELD_PREP_CONST(AIROHA_USB_PHY_MONCLK_SEL, 0x3)
#define   AIROHA_USB_PHY_FREQDET_EN		BIT(24)
#define   AIROHA_USB_PHY_CYCLECNT		GENMASK(23, 0)
#define AIROHA_USB_PHY_FMMONR0			0x10c
#define   AIROHA_USB_PHY_USB_FM_OUT		GENMASK(31, 0)
#define AIROHA_USB_PHY_FMMONR1			0x110
#define   AIROHA_USB_PHY_FRCK_EN		BIT(8)

#define AIROHA_USB_PHY_USBPHYACR4		0x310
#define   AIROHA_USB_PHY_USB20_FS_CR		GENMASK(10, 8)
#define   AIROHA_USB_PHY_USB20_FS_CR_MAX	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_CR, 0x0)
#define   AIROHA_USB_PHY_USB20_FS_CR_NORMAL	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_CR, 0x2)
#define   AIROHA_USB_PHY_USB20_FS_CR_SMALLER	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_CR, 0x4)
#define   AIROHA_USB_PHY_USB20_FS_CR_MIN	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_CR, 0x6)
#define   AIROHA_USB_PHY_USB20_FS_SR		GENMASK(2, 0)
#define   AIROHA_USB_PHY_USB20_FS_SR_MAX	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_SR, 0x0)
#define   AIROHA_USB_PHY_USB20_FS_SR_NORMAL	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_SR, 0x2)
#define   AIROHA_USB_PHY_USB20_FS_SR_SMALLER	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_SR, 0x4)
#define   AIROHA_USB_PHY_USB20_FS_SR_MIN	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_FS_SR, 0x6)
#define AIROHA_USB_PHY_USBPHYACR5		0x314
#define   AIROHA_USB_PHY_USB20_HSTX_SRCAL_EN	BIT(15)
#define   AIROHA_USB_PHY_USB20_HSTX_SRCTRL	GENMASK(14, 12)
#define AIROHA_USB_PHY_USBPHYACR6		0x318
#define   AIROHA_USB_PHY_USB20_BC11_SW_EN	BIT(23)
#define   AIROHA_USB_PHY_USB20_DISCTH		GENMASK(7, 4)
#define   AIROHA_USB_PHY_USB20_DISCTH_400	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x0)
#define   AIROHA_USB_PHY_USB20_DISCTH_420	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x1)
#define   AIROHA_USB_PHY_USB20_DISCTH_440	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x2)
#define   AIROHA_USB_PHY_USB20_DISCTH_460	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x3)
#define   AIROHA_USB_PHY_USB20_DISCTH_480	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x4)
#define   AIROHA_USB_PHY_USB20_DISCTH_500	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x5)
#define   AIROHA_USB_PHY_USB20_DISCTH_520	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x6)
#define   AIROHA_USB_PHY_USB20_DISCTH_540	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x7)
#define   AIROHA_USB_PHY_USB20_DISCTH_560	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x8)
#define   AIROHA_USB_PHY_USB20_DISCTH_580	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0x9)
#define   AIROHA_USB_PHY_USB20_DISCTH_600	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xa)
#define   AIROHA_USB_PHY_USB20_DISCTH_620	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xb)
#define   AIROHA_USB_PHY_USB20_DISCTH_640	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xc)
#define   AIROHA_USB_PHY_USB20_DISCTH_660	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xd)
#define   AIROHA_USB_PHY_USB20_DISCTH_680	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xe)
#define   AIROHA_USB_PHY_USB20_DISCTH_700	FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_DISCTH, 0xf)
#define   AIROHA_USB_PHY_USB20_SQTH		GENMASK(3, 0)
#define   AIROHA_USB_PHY_USB20_SQTH_85		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x0)
#define   AIROHA_USB_PHY_USB20_SQTH_90		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x1)
#define   AIROHA_USB_PHY_USB20_SQTH_95		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x2)
#define   AIROHA_USB_PHY_USB20_SQTH_100		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x3)
#define   AIROHA_USB_PHY_USB20_SQTH_105		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x4)
#define   AIROHA_USB_PHY_USB20_SQTH_110		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x5)
#define   AIROHA_USB_PHY_USB20_SQTH_115		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x6)
#define   AIROHA_USB_PHY_USB20_SQTH_120		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x7)
#define   AIROHA_USB_PHY_USB20_SQTH_125		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x8)
#define   AIROHA_USB_PHY_USB20_SQTH_130		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0x9)
#define   AIROHA_USB_PHY_USB20_SQTH_135		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xa)
#define   AIROHA_USB_PHY_USB20_SQTH_140		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xb)
#define   AIROHA_USB_PHY_USB20_SQTH_145		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xc)
#define   AIROHA_USB_PHY_USB20_SQTH_150		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xd)
#define   AIROHA_USB_PHY_USB20_SQTH_155		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xe)
#define   AIROHA_USB_PHY_USB20_SQTH_160		FIELD_PREP_CONST(AIROHA_USB_PHY_USB20_SQTH, 0xf)

#define AIROHA_USB_PHY_U2PHYDTM1		0x36c
#define   AIROHA_USB_PHY_FORCE_IDDIG		BIT(9)
#define   AIROHA_USB_PHY_IDDIG			BIT(1)

#define AIROHA_USB_PHY_GPIO_CTLD		0x80c
#define   AIROHA_USB_PHY_C60802_GPIO_CTLD	GENMASK(31, 0)
#define     AIROHA_USB_PHY_SSUSB_IP_SW_RST	BIT(31)
#define     AIROHA_USB_PHY_MCU_BUS_CK_GATE_EN	BIT(30)
#define     AIROHA_USB_PHY_FORCE_SSUSB_IP_SW_RST BIT(29)
#define     AIROHA_USB_PHY_SSUSB_SW_RST		BIT(28)

#define AIROHA_USB_PHY_U3_PHYA_REG0		0xb00
#define   AIROHA_USB_PHY_SSUSB_BG_DIV		GENMASK(29, 28)
#define   AIROHA_USB_PHY_SSUSB_BG_DIV_2		FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_BG_DIV, 0x0)
#define   AIROHA_USB_PHY_SSUSB_BG_DIV_4		FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_BG_DIV, 0x1)
#define   AIROHA_USB_PHY_SSUSB_BG_DIV_8		FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_BG_DIV, 0x2)
#define   AIROHA_USB_PHY_SSUSB_BG_DIV_16	FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_BG_DIV, 0x3)
#define AIROHA_USB_PHY_U3_PHYA_REG1		0xb04
#define   AIROHA_USB_PHY_SSUSB_XTAL_TOP_RESERVE	GENMASK(25, 10)
#define AIROHA_USB_PHY_U3_PHYA_REG6		0xb18
#define   AIROHA_USB_PHY_SSUSB_CDR_RESERVE	GENMASK(31, 24)
#define AIROHA_USB_PHY_U3_PHYA_REG8		0xb20
#define   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY	GENMASK(7, 6)
#define   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY_32	FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_CDR_RST_DLY, 0x0)
#define   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY_64	FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_CDR_RST_DLY, 0x1)
#define   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY_128	FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_CDR_RST_DLY, 0x2)
#define   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY_216	FIELD_PREP_CONST(AIROHA_USB_PHY_SSUSB_CDR_RST_DLY, 0x3)

#define AIROHA_USB_PHY_U3_PHYA_DA_REG19		0xc38
#define   AIROHA_USB_PHY_SSUSB_PLL_SSC_DELTA1_U3 GENMASK(15, 0)

#define AIROHA_USB_PHY_U2_FM_DET_CYCLE_CNT	1024
#define AIROHA_USB_PHY_REF_CK			20
#define AIROHA_USB_PHY_U2_SR_COEF		28
#define AIROHA_USB_PHY_U2_SR_COEF_DIVISOR	1000

#define AIROHA_USB_PHY_DEFAULT_SR_CALIBRATION	0x5
#define AIROHA_USB_PHY_FREQDET_SLEEP		1000 /* 1ms */
#define AIROHA_USB_PHY_FREQDET_TIMEOUT		(AIROHA_USB_PHY_FREQDET_SLEEP * 10)

struct an7581_usb_phy_instance {
	struct phy *phy;
	u32 type;
};

enum an7581_usb_phy_instance_type {
	AIROHA_PHY_USB2,
	AIROHA_PHY_USB3,

	AIROHA_PHY_USB_MAX,
};

struct an7581_usb_phy_priv {
	struct device *dev;
	struct regmap *regmap;

	unsigned int monclk_sel;

	struct phy *serdes_phy;
	struct an7581_usb_phy_instance *phys[AIROHA_PHY_USB_MAX];
};

static void an7581_usb_phy_u2_slew_rate_calibration(struct an7581_usb_phy_priv *priv)
{
	u32 fm_out = 0;
	u32 srctrl;

	/* Enable HS TX SR calibration */
	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR5,
			AIROHA_USB_PHY_USB20_HSTX_SRCAL_EN);

	usleep_range(1000, 1500);

	/* Enable Free run clock */
	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_FMMONR1,
			AIROHA_USB_PHY_FRCK_EN);

	/* Select Monitor Clock */
	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_FMCR0,
			   AIROHA_USB_PHY_MONCLK_SEL,
			   FIELD_PREP(AIROHA_USB_PHY_MONCLK_SEL,
				      priv->monclk_sel));

	/* Set cyclecnt */
	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_FMCR0,
			   AIROHA_USB_PHY_CYCLECNT,
			   FIELD_PREP(AIROHA_USB_PHY_CYCLECNT,
				      AIROHA_USB_PHY_U2_FM_DET_CYCLE_CNT));

	/* Enable Frequency meter */
	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_FMCR0,
			AIROHA_USB_PHY_FREQDET_EN);

	/* Timeout can happen and we will apply workaround at the end */
	regmap_read_poll_timeout(priv->regmap, AIROHA_USB_PHY_FMMONR0, fm_out,
				 fm_out, AIROHA_USB_PHY_FREQDET_SLEEP,
				 AIROHA_USB_PHY_FREQDET_TIMEOUT);

	/* Disable Frequency meter */
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_FMCR0,
			  AIROHA_USB_PHY_FREQDET_EN);

	/* Disable Free run clock */
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_FMMONR1,
			  AIROHA_USB_PHY_FRCK_EN);

	/* Disable HS TX SR calibration */
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR5,
			  AIROHA_USB_PHY_USB20_HSTX_SRCAL_EN);

	usleep_range(1000, 1500);

	/* Frequency was not detected, use default SR calibration value */
	if (!fm_out) {
		srctrl = AIROHA_USB_PHY_DEFAULT_SR_CALIBRATION;
		dev_err(priv->dev, "Frequency not detected, using default SR calibration.\n");
	} else {
		/* (1024 / FM_OUT) * REF_CK * U2_SR_COEF (round to the nearest digits) */
		srctrl = AIROHA_USB_PHY_REF_CK * AIROHA_USB_PHY_U2_SR_COEF;
		srctrl = (srctrl * AIROHA_USB_PHY_U2_FM_DET_CYCLE_CNT) / fm_out;
		srctrl = DIV_ROUND_CLOSEST(srctrl, AIROHA_USB_PHY_U2_SR_COEF_DIVISOR);
		dev_dbg(priv->dev, "SR calibration applied: %x\n", srctrl);
	}

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR5,
			   AIROHA_USB_PHY_USB20_HSTX_SRCTRL,
			   FIELD_PREP(AIROHA_USB_PHY_USB20_HSTX_SRCTRL, srctrl));
}

static void an7581_usb_phy_u2_init(struct an7581_usb_phy_priv *priv)
{
	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR4,
			   AIROHA_USB_PHY_USB20_FS_CR,
			   AIROHA_USB_PHY_USB20_FS_CR_MIN);

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR4,
			   AIROHA_USB_PHY_USB20_FS_SR,
			   AIROHA_USB_PHY_USB20_FS_SR_NORMAL);

	/* FIXME: evaluate if needed */
	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			   AIROHA_USB_PHY_USB20_SQTH,
			   AIROHA_USB_PHY_USB20_SQTH_130);

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			   AIROHA_USB_PHY_USB20_DISCTH,
			   AIROHA_USB_PHY_USB20_DISCTH_600);

	/* Enable the USB port and then disable after calibration */
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			  AIROHA_USB_PHY_USB20_BC11_SW_EN);

	an7581_usb_phy_u2_slew_rate_calibration(priv);

	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			AIROHA_USB_PHY_USB20_BC11_SW_EN);

	usleep_range(1000, 1500);
}

/*
 * USB 3.0 mode can only work if USB serdes is correctly set.
 * This is validated in xLate function.
 */
static void an7581_usb_phy_u3_init(struct an7581_usb_phy_priv *priv)
{
	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_U3_PHYA_REG8,
			   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY,
			   AIROHA_USB_PHY_SSUSB_CDR_RST_DLY_32);

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_U3_PHYA_REG6,
			   AIROHA_USB_PHY_SSUSB_CDR_RESERVE,
			   FIELD_PREP(AIROHA_USB_PHY_SSUSB_CDR_RESERVE, 0xe));

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_U3_PHYA_REG0,
			   AIROHA_USB_PHY_SSUSB_BG_DIV,
			   AIROHA_USB_PHY_SSUSB_BG_DIV_4);

	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_U3_PHYA_REG1,
			FIELD_PREP(AIROHA_USB_PHY_SSUSB_XTAL_TOP_RESERVE, 0x600));

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_U3_PHYA_DA_REG19,
			   AIROHA_USB_PHY_SSUSB_PLL_SSC_DELTA1_U3,
			   FIELD_PREP(AIROHA_USB_PHY_SSUSB_PLL_SSC_DELTA1_U3, 0x43));
}

static int an7581_usb_phy_init(struct phy *phy)
{
	struct an7581_usb_phy_instance *instance = phy_get_drvdata(phy);
	struct an7581_usb_phy_priv *priv = dev_get_drvdata(phy->dev.parent);
	int ret;

	switch (instance->type) {
	case PHY_TYPE_USB2:
		an7581_usb_phy_u2_init(priv);
		break;
	case PHY_TYPE_USB3:
		ret = phy_set_mode(priv->serdes_phy, PHY_MODE_USB_DEVICE_SS);
		if (ret)
			return ret;

		an7581_usb_phy_u3_init(priv);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int an7581_usb_phy_u2_power_on(struct an7581_usb_phy_priv *priv)
{
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			  AIROHA_USB_PHY_USB20_BC11_SW_EN);

	usleep_range(1000, 1500);

	return 0;
}

static int an7581_usb_phy_u3_power_on(struct an7581_usb_phy_priv *priv)
{
	regmap_clear_bits(priv->regmap, AIROHA_USB_PHY_GPIO_CTLD,
			  AIROHA_USB_PHY_SSUSB_IP_SW_RST |
			  AIROHA_USB_PHY_MCU_BUS_CK_GATE_EN |
			  AIROHA_USB_PHY_FORCE_SSUSB_IP_SW_RST |
			  AIROHA_USB_PHY_SSUSB_SW_RST);

	usleep_range(1000, 1500);

	return 0;
}

static int an7581_usb_phy_power_on(struct phy *phy)
{
	struct an7581_usb_phy_instance *instance = phy_get_drvdata(phy);
	struct an7581_usb_phy_priv *priv = dev_get_drvdata(phy->dev.parent);

	switch (instance->type) {
	case PHY_TYPE_USB2:
		an7581_usb_phy_u2_power_on(priv);
		break;
	case PHY_TYPE_USB3:
		an7581_usb_phy_u3_power_on(priv);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int an7581_usb_phy_u2_power_off(struct an7581_usb_phy_priv *priv)
{
	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_USBPHYACR6,
			AIROHA_USB_PHY_USB20_BC11_SW_EN);

	usleep_range(1000, 1500);

	return 0;
}

static int an7581_usb_phy_u3_power_off(struct an7581_usb_phy_priv *priv)
{
	regmap_set_bits(priv->regmap, AIROHA_USB_PHY_GPIO_CTLD,
			AIROHA_USB_PHY_SSUSB_IP_SW_RST |
			AIROHA_USB_PHY_FORCE_SSUSB_IP_SW_RST);

	usleep_range(1000, 1500);

	return 0;
}

static int an7581_usb_phy_power_off(struct phy *phy)
{
	struct an7581_usb_phy_instance *instance = phy_get_drvdata(phy);
	struct an7581_usb_phy_priv *priv = dev_get_drvdata(phy->dev.parent);

	switch (instance->type) {
	case PHY_TYPE_USB2:
		an7581_usb_phy_u2_power_off(priv);
		break;
	case PHY_TYPE_USB3:
		an7581_usb_phy_u3_power_off(priv);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int an7581_usb_phy_u2_set_mode(struct an7581_usb_phy_priv *priv,
				      enum phy_mode mode)
{
	u32 val;

	/*
	 * For Device and Host mode, enable force IDDIG.
	 * For Device set IDDIG, for Host clear IDDIG.
	 * For OTG disable force and clear IDDIG bit while at it.
	 */
	switch (mode) {
	case PHY_MODE_USB_DEVICE:
		val = AIROHA_USB_PHY_FORCE_IDDIG |
		      AIROHA_USB_PHY_IDDIG;
		break;
	case PHY_MODE_USB_HOST:
		val = AIROHA_USB_PHY_FORCE_IDDIG;
		break;
	case PHY_MODE_USB_OTG:
		val = 0;
		break;
	default:
		return 0;
	}

	regmap_update_bits(priv->regmap, AIROHA_USB_PHY_U2PHYDTM1,
			   AIROHA_USB_PHY_FORCE_IDDIG |
			   AIROHA_USB_PHY_IDDIG, val);

	return 0;
}

static int an7581_usb_phy_set_mode(struct phy *phy, enum phy_mode mode, int submode)
{
	struct an7581_usb_phy_instance *instance = phy_get_drvdata(phy);
	struct an7581_usb_phy_priv *priv = dev_get_drvdata(phy->dev.parent);

	switch (instance->type) {
	case PHY_TYPE_USB2:
		return an7581_usb_phy_u2_set_mode(priv, mode);
	default:
		return 0;
	}
}

static struct phy *an7581_usb_phy_xlate(struct device *dev,
					const struct of_phandle_args *args)
{
	struct an7581_usb_phy_priv *priv = dev_get_drvdata(dev);
	struct an7581_usb_phy_instance *instance = NULL;
	unsigned int index, phy_type;

	if (args->args_count != 1) {
		dev_err(dev, "invalid number of cells in 'phy' property\n");
		return ERR_PTR(-EINVAL);
	}

	phy_type = args->args[0];
	if (!(phy_type == PHY_TYPE_USB2 || phy_type == PHY_TYPE_USB3)) {
		dev_err(dev, "unsupported device type: %d\n", phy_type);
		return ERR_PTR(-EINVAL);
	}

	for (index = 0; index < AIROHA_PHY_USB_MAX; index++)
		if (priv->phys[index] &&
		    phy_type == priv->phys[index]->type) {
			instance = priv->phys[index];
			break;
		}

	if (!instance) {
		dev_err(dev, "failed to find appropriate phy\n");
		return ERR_PTR(-EINVAL);
	}

	if (instance->type == PHY_TYPE_USB3 && !priv->serdes_phy) {
		dev_err(dev, "missing serdes phy for USB 3.0\n");
		return ERR_PTR(-EINVAL);
	}

	return instance->phy;
}

static const struct phy_ops airoha_phy = {
	.init		= an7581_usb_phy_init,
	.power_on	= an7581_usb_phy_power_on,
	.power_off	= an7581_usb_phy_power_off,
	.set_mode	= an7581_usb_phy_set_mode,
	.owner		= THIS_MODULE,
};

static const struct regmap_config an7581_usb_phy_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static int an7581_usb_phy_probe(struct platform_device *pdev)
{
	struct phy_provider *phy_provider;
	struct an7581_usb_phy_priv *priv;
	struct device *dev = &pdev->dev;
	unsigned int index;
	void __iomem *base;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;

	ret = of_property_read_u32(dev->of_node, "airoha,usb2-monitor-clk-sel",
				   &priv->monclk_sel);
	if (ret)
		return dev_err_probe(dev, ret, "Monitor clock selection is mandatory for USB PHY calibration\n");

	if (priv->monclk_sel > 3)
		return dev_err_probe(dev, -EINVAL, "only 4 Monitor clock are selectable on the SoC\n");

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	priv->regmap = devm_regmap_init_mmio(dev, base, &an7581_usb_phy_regmap_config);
	if (IS_ERR(priv->regmap))
		return PTR_ERR(priv->regmap);

	platform_set_drvdata(pdev, priv);

	for (index = 0; index < AIROHA_PHY_USB_MAX; index++) {
		struct an7581_usb_phy_instance *instance;
		u32 phy_type;

		switch (index) {
		case AIROHA_PHY_USB2:
			phy_type = PHY_TYPE_USB2;
			break;
		case AIROHA_PHY_USB3:
			phy_type = PHY_TYPE_USB3;
			break;
		}

		if (phy_type == PHY_TYPE_USB3) {
			priv->serdes_phy = devm_phy_optional_get(dev, NULL);
			if (IS_ERR(priv->serdes_phy))
				return dev_err_probe(dev, PTR_ERR(priv->serdes_phy), "error on serdes phy for USB 3.0\n");
		}

		instance = devm_kzalloc(dev, sizeof(*instance), GFP_KERNEL);
		if (!instance)
			return -ENOMEM;

		instance->type = phy_type;
		priv->phys[index] = instance;

		instance->phy = devm_phy_create(dev, NULL, &airoha_phy);
		if (IS_ERR(instance->phy))
			return dev_err_probe(dev, PTR_ERR(instance->phy), "failed to create phy\n");

		phy_set_drvdata(instance->phy, instance);
	}

	phy_provider = devm_of_phy_provider_register(&pdev->dev, an7581_usb_phy_xlate);

	return PTR_ERR_OR_ZERO(phy_provider);
}

static const struct of_device_id airoha_phy_id_table[] = {
	{ .compatible = "airoha,an7581-usb-phy" },
	{ },
};
MODULE_DEVICE_TABLE(of, airoha_phy_id_table);

static struct platform_driver an7581_usb_driver = {
	.probe		= an7581_usb_phy_probe,
	.driver		= {
		.name	= "airoha-an7581-usb-phy",
		.of_match_table = airoha_phy_id_table,
	},
};

module_platform_driver(an7581_usb_driver);

MODULE_DESCRIPTION("Airoha AN7581 USB PHY driver");
MODULE_AUTHOR("Christian Marangi <ansuelsmth@gmail.com>");
MODULE_LICENSE("GPL");
