// SPDX-License-Identifier: GPL-2.0
// KUnit tests for the SPI core message optimize state.
#include <kunit/device.h>
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/spi/spi.h>

struct spi_core_test_ctx {
	struct spi_controller *ctlr;
	struct spi_device *spi;
	int (*queued_transfer)(struct spi_device *spi, struct spi_message *msg);
	int optimize_count, unoptimize_count;
	int transfer_err;
	bool bad_opt_state;
	struct spi_transfer xfer;
	struct spi_message msg;
	struct completion done;
	u8 tx[4];
};

static int spi_core_test_optimize(struct spi_message *msg)
{
	struct spi_core_test_ctx *ctx = spi_controller_get_devdata(msg->spi->controller);

	ctx->optimize_count++;
	msg->opt_state = ctx;
	return 0;
}

static int spi_core_test_unoptimize(struct spi_message *msg)
{
	struct spi_core_test_ctx *ctx = spi_controller_get_devdata(msg->spi->controller);

	ctx->unoptimize_count++;
	if (msg->opt_state != ctx)
		ctx->bad_opt_state = true;
	return 0;
}

static int spi_core_test_xfer_one(struct spi_controller *ctlr, struct spi_message *msg)
{
	struct spi_transfer *xfer;

	list_for_each_entry(xfer, &msg->transfers, transfer_list)
		msg->actual_length += xfer->len;
	msg->status = 0;
	spi_finalize_current_message(ctlr);
	return 0;
}

static int spi_core_test_transfer(struct spi_device *spi,
				  struct spi_message *msg)
{
	struct spi_core_test_ctx *ctx =
		spi_controller_get_devdata(spi->controller);

	if (ctx->transfer_err)
		return ctx->transfer_err;

	return ctx->queued_transfer(spi, msg);
}

static size_t spi_core_test_max_transfer_size(struct spi_device *spi)
{
	return 2;
}

static void kunit_done(void *p)
{
	complete(p);
}

static struct spi_core_test_ctx *spi_core_test_ctx_new(struct kunit *test)
{
	struct spi_board_info info = { .modalias = "spi-core-kunit", .max_speed_hz = 1000000 };
	struct device *dev = kunit_device_register(test, "spi-core-kunit");
	struct spi_controller *ctlr;
	struct spi_core_test_ctx *ctx;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dev);
	ctlr = devm_spi_alloc_host(dev, sizeof(struct spi_core_test_ctx));
	KUNIT_ASSERT_NOT_NULL(test, ctlr);
	ctx = spi_controller_get_devdata(ctlr);

	ctx->ctlr = ctlr;
	ctlr->bus_num = -1;
	ctlr->num_chipselect = 1;
	ctlr->max_transfer_size = spi_core_test_max_transfer_size;
	ctlr->optimize_message = spi_core_test_optimize;
	ctlr->unoptimize_message = spi_core_test_unoptimize;
	ctlr->transfer_one_message = spi_core_test_xfer_one;
	KUNIT_ASSERT_EQ(test, 0, devm_spi_register_controller(dev, ctlr));
	ctx->queued_transfer = ctlr->transfer;
	ctlr->transfer = spi_core_test_transfer;
	ctx->spi = spi_new_device(ctlr, &info);
	KUNIT_ASSERT_NOT_NULL(test, ctx->spi);
	init_completion(&ctx->done);
	/* 4-byte TX buffer with max_transfer_size = 2 splits into two 2-byte transfers. */
	ctx->xfer.tx_buf = ctx->tx;
	ctx->xfer.len = sizeof(ctx->tx);
	spi_message_init_with_transfers(&ctx->msg, &ctx->xfer, 1);
	ctx->msg.complete = kunit_done;
	ctx->msg.context = &ctx->done;
	return ctx;
}

enum spi_core_err_mode {
	ERR_NONE,
	ERR_BUS_LOCKED,
	ERR_TRANSFER,
	ERR_SUSPEND,
};

struct spi_core_err_param {
	const char *name;
	enum spi_core_err_mode mode;
	int exp;
	bool use_sync;
	bool pre_opt;
	bool must_async;
};

static const struct spi_core_err_param spi_core_err_cases[] = {
	{
		.name = "bus_locked_async",
		.mode = ERR_BUS_LOCKED,
		.exp = -EBUSY,
	},
	{
		.name = "suspend_async",
		.mode = ERR_SUSPEND,
		.exp = -ESHUTDOWN,
	},
	{
		.name = "xfer_err_sync",
		.mode = ERR_TRANSFER,
		.exp = -EIO,
		.use_sync = true,
		.must_async = true,
	},
	{
		.name = "pre_opt_locked",
		.mode = ERR_BUS_LOCKED,
		.exp = -EBUSY,
		.pre_opt = true,
	},
	{
		.name = "pre_opt_xfer_err_sync",
		.mode = ERR_TRANSFER,
		.exp = -EIO,
		.use_sync = true,
		.pre_opt = true,
		.must_async = true,
	},
	{
		.name = "sync_success",
		.mode = ERR_NONE,
		.exp = 0,
		.use_sync = true,
	},
	{
		.name = "sync_success_queued",
		.mode = ERR_NONE,
		.exp = 0,
		.use_sync = true,
		.must_async = true,
	},
};

static void spi_core_err_desc(const struct spi_core_err_param *t, char *desc)
{
	strscpy(desc, t->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(spi_core_err, spi_core_err_cases, spi_core_err_desc);

static void check_state(struct kunit *test, struct spi_core_test_ctx *ctx,
			int opt, int unopt, bool state)
{
	KUNIT_EXPECT_EQ(test, ctx->optimize_count, opt);
	KUNIT_EXPECT_EQ(test, ctx->unoptimize_count, unopt);
	KUNIT_EXPECT_FALSE(test, ctx->bad_opt_state);
	KUNIT_EXPECT_EQ(test, ctx->msg.optimized, state);
	KUNIT_EXPECT_EQ(test, !ctx->msg.opt_state, !state);
	KUNIT_EXPECT_EQ(test, list_empty(&ctx->msg.resources), !state);
	KUNIT_EXPECT_EQ(test, list_is_singular(&ctx->msg.transfers), !state);
}

static int spi_core_test_send_locked(struct spi_device *spi, struct spi_message *msg)
{
	int ret;

	spi_bus_lock(spi->controller);
	ret = spi_async(spi, msg);
	spi_bus_unlock(spi->controller);

	return ret;
}

static void spi_core_queue_error_test(struct kunit *test)
{
	const struct spi_core_err_param *p = test->param_value;
	struct spi_core_test_ctx *ctx = spi_core_test_ctx_new(test);
	int exp = p->exp, ret;

	ctx->ctlr->must_async = p->must_async;
	if (p->pre_opt)
		KUNIT_ASSERT_EQ(test, spi_optimize_message(ctx->spi, &ctx->msg), 0);
	if (p->mode == ERR_SUSPEND)
		KUNIT_ASSERT_EQ(test, 0, spi_controller_suspend(ctx->ctlr));
	if (p->mode == ERR_TRANSFER)
		ctx->transfer_err = -EIO;

	if (p->mode == ERR_BUS_LOCKED)
		ret = spi_core_test_send_locked(ctx->spi, &ctx->msg);
	else if (p->use_sync)
		ret = spi_sync(ctx->spi, &ctx->msg);
	else
		ret = spi_async(ctx->spi, &ctx->msg);

	ctx->transfer_err = 0;
	if (p->mode == ERR_SUSPEND)
		KUNIT_ASSERT_EQ(test, 0, spi_controller_resume(ctx->ctlr));

	KUNIT_EXPECT_EQ(test, ret, exp);
	if (!exp) {
		KUNIT_EXPECT_EQ(test, ctx->msg.actual_length, sizeof(ctx->tx));
		check_state(test, ctx, 1, 1, false);
		return;
	}

	/* Core-optimized messages are unoptimized on queue error; pre-optimized stay optimized. */
	check_state(test, ctx, 1, p->pre_opt ? 0 : 1, p->pre_opt);
	if (p->pre_opt)
		spi_unoptimize_message(&ctx->msg);

	reinit_completion(&ctx->done);
	ctx->msg.complete = kunit_done;
	ctx->msg.context = &ctx->done;
	KUNIT_ASSERT_EQ(test, spi_async(ctx->spi, &ctx->msg), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&ctx->done, msecs_to_jiffies(1000)), 0);
	KUNIT_EXPECT_EQ(test, ctx->msg.status, 0);
	/* Resubmitting the message after the transient error clears succeeds cleanly. */
	check_state(test, ctx, 2, 2, false);
}

static struct kunit_case spi_core_optimize_cases[] = {
	KUNIT_CASE_PARAM(spi_core_queue_error_test, spi_core_err_gen_params),
	{}
};

static struct kunit_suite spi_core_optimize_suite = {
	.name = "spi_core_optimize",
	.test_cases = spi_core_optimize_cases,
};

kunit_test_suite(spi_core_optimize_suite);

MODULE_DESCRIPTION("KUnit tests for SPI core message optimize state");
MODULE_LICENSE("GPL");
