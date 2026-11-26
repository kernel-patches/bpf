// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/errno.h>
#if IS_ENABLED(CONFIG_INDIRECT_IOMEM)
#include <linux/logic_iomem.h>
#endif
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

#define QSPI_SPI_CMD_REG	0x48
#define QSPI_INVAL		(4 << 16)

struct ti_qspi_test_ctx {
	struct platform_device *pdev;
	struct spi_device *spi;
	struct spi_message msg;
	struct spi_transfer xfer;
	u8 tx[4];
};

static bool g_inval;

static bool ti_qspi_can_run(void)
{
	return IS_ENABLED(CONFIG_INDIRECT_IOMEM) && !IS_ENABLED(CONFIG_HAVE_CLK);
}

#if IS_ENABLED(CONFIG_INDIRECT_IOMEM)
static bool g_region_registered;
static struct resource g_iomem_res = DEFINE_RES_MEM(0x30000000, 0x1000);

static unsigned long ti_qspi_io_r(void *p, unsigned int off, int sz)
{
	return 0;
}

static void ti_qspi_io_w(void *p, unsigned int off, int sz, unsigned long val)
{
	if (off == QSPI_SPI_CMD_REG && (val & QSPI_INVAL))
		g_inval = true;
}

static const struct logic_iomem_ops g_iops = {
	.read = ti_qspi_io_r,
	.write = ti_qspi_io_w,
};

static long ti_qspi_map(unsigned long o, size_t s,
			const struct logic_iomem_ops **ops, void **p)
{
	*ops = &g_iops;
	return 0;
}

static const struct logic_iomem_region_ops g_rops = {
	.map = ti_qspi_map,
};

static int ti_qspi_suite_init(struct kunit_suite *s)
{
	int ret;

	if (!ti_qspi_can_run() || g_region_registered)
		return 0;

	ret = logic_iomem_add_region(&g_iomem_res, &g_rops);
	if (!ret)
		g_region_registered = true;
	return ret;
}
#else
static int ti_qspi_suite_init(struct kunit_suite *s)
{
	return 0;
}
#endif

static int ti_qspi_find_ctlr(struct device *d, void *data)
{
	*(struct spi_controller **)data = container_of(d, struct spi_controller, dev);
	return 1;
}

static int ti_qspi_init(struct kunit *t)
{
	const struct resource res[] = {
		DEFINE_RES_MEM(0x30000000, 0x1000),
		DEFINE_RES_IRQ(1),
	};
	struct ti_qspi_test_ctx *ctx;
	struct spi_board_info info = { .modalias = "ti-qspi-test" };
	struct spi_controller *ctlr = NULL;
	struct platform_device *pdev;

	if (!ti_qspi_can_run())
		return 0;

	g_inval = false;
	ctx = kunit_kzalloc(t, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, ctx);
	t->priv = ctx;

	pdev = platform_device_register_simple("ti-qspi", -1, res, ARRAY_SIZE(res));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(t, pdev);
	ctx->pdev = pdev;

	device_for_each_child(&pdev->dev, &ctlr, ti_qspi_find_ctlr);
	if (!ctlr) {
		platform_device_unregister(pdev);
		ctx->pdev = NULL;
		KUNIT_FAIL_AND_ABORT(t, "TI QSPI controller device not found");
	}

	ctlr->max_speed_hz = 50000000;
	ctx->spi = spi_new_device(ctlr, &info);
	if (!ctx->spi) {
		platform_device_unregister(pdev);
		ctx->pdev = NULL;
		KUNIT_FAIL_AND_ABORT(t, "Failed to create spi child device");
	}

	memcpy(ctx->tx, "ABCD", sizeof(ctx->tx));
	ctx->xfer.tx_buf = ctx->tx;
	ctx->xfer.len = sizeof(ctx->tx);
	spi_message_init_with_transfers(&ctx->msg, &ctx->xfer, 1);
	return 0;
}

static void ti_qspi_exit(struct kunit *t)
{
	struct ti_qspi_test_ctx *ctx = t->priv;

	if (!ctx)
		return;
	if (ctx->spi)
		spi_unregister_device(ctx->spi);
	if (ctx->pdev)
		platform_device_unregister(ctx->pdev);
}

static void ti_qspi_test(struct kunit *t)
{
	struct ti_qspi_test_ctx *ctx = t->priv;

	if (!ti_qspi_can_run())
		kunit_skip(t,
			   "needs UML MMIO (CONFIG_INDIRECT_IOMEM) and no clock framework");

	KUNIT_EXPECT_EQ(t, spi_sync(ctx->spi, &ctx->msg), -ETIMEDOUT);
	/* Message must be finalized and unoptimized even when a transfer fails. */
	KUNIT_EXPECT_FALSE(t, ctx->msg.optimized);
	/* QSPI_INVAL must be written to terminate the frame on error. */
	KUNIT_EXPECT_TRUE(t, g_inval);
}

static struct kunit_case ti_qspi_test_cases[] = {
	KUNIT_CASE(ti_qspi_test),
	{}
};

static struct kunit_suite ti_qspi_test_suite = {
	.name = "spi_ti_qspi",
	.suite_init = ti_qspi_suite_init,
	.init = ti_qspi_init,
	.exit = ti_qspi_exit,
	.test_cases = ti_qspi_test_cases,
};

kunit_test_suite(ti_qspi_test_suite);

MODULE_DESCRIPTION("KUnit test for TI QSPI controller driver");
MODULE_LICENSE("GPL");
