// SPDX-License-Identifier: GPL-2.0-only
/*
 * K3 DTHE V2 crypto accelerator driver
 *
 * Copyright (C) Texas Instruments 2025 - https://www.ti.com
 * Author: T Pratham <t-pratham@ti.com>
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/engine.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>

#include "dthev2-common.h"

#include <linux/delay.h>
#include <linux/dmaengine.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>

#define DRIVER_NAME	"dthev2"

static struct dthe_list dthe_dev_list = {
	.dev_list = LIST_HEAD_INIT(dthe_dev_list.dev_list),
	.lock = __SPIN_LOCK_UNLOCKED(dthe_dev_list.lock),
};

struct device *dthe_get_dev(void)
{
	struct dthe_data *dev_data;
	struct device *dev = NULL;

	spin_lock_bh(&dthe_dev_list.lock);
	dev_data = list_first_entry_or_null(&dthe_dev_list.dev_list, struct dthe_data, list);
	if (dev_data) {
		list_move_tail(&dev_data->list, &dthe_dev_list.dev_list);
		dev = get_device(dev_data->dev);
	}
	spin_unlock_bh(&dthe_dev_list.lock);

	return dev;
}

void dthe_put_dev(struct device *dev)
{
	put_device(dev);
}

struct dthe_data *dthe_get_drvdata(struct device *dev)
{
	struct dthe_data *dev_data;

	spin_lock_bh(&dthe_dev_list.lock);
	dev_data = dev_get_drvdata(dev);
	if (dev_data)
		kref_get(&dev_data->refcnt);
	spin_unlock_bh(&dthe_dev_list.lock);

	return dev_data;
}

static void dthe_release_drvdata(struct kref *kref)
{
	struct dthe_data *dev_data = container_of(kref, struct dthe_data, refcnt);

	complete(&dev_data->drain_compl);
}

void dthe_put_drvdata(struct dthe_data *dev_data)
{
	spin_lock_bh(&dthe_dev_list.lock);
	kref_put(&dev_data->refcnt, dthe_release_drvdata);
	spin_unlock_bh(&dthe_dev_list.lock);
}

struct scatterlist *dthe_copy_sg(struct scatterlist *dst,
				 struct scatterlist *src,
				 unsigned int buflen)
{
	struct scatterlist *from_sg, *to_sg;
	int sglen;

	for (to_sg = dst, from_sg = src; buflen && from_sg; buflen -= sglen) {
		sglen = from_sg->length;
		if (sglen > buflen)
			sglen = buflen;
		sg_set_page(to_sg, sg_page(from_sg), sglen, from_sg->offset);
		from_sg = sg_next(from_sg);
		to_sg = sg_next(to_sg);
	}

	return to_sg;
}

static int dthe_dma_init(struct dthe_data *dev_data)
{
	int ret;
	struct dma_slave_config cfg;

	dev_data->dma_aes_rx = NULL;
	dev_data->dma_aes_tx = NULL;
	dev_data->dma_sha_tx = NULL;

	dev_data->dma_aes_rx = dma_request_chan(dev_data->dev, "rx");
	if (IS_ERR(dev_data->dma_aes_rx)) {
		return dev_err_probe(dev_data->dev, PTR_ERR(dev_data->dma_aes_rx),
				     "Unable to request rx DMA channel\n");
	}

	dev_data->dma_aes_tx = dma_request_chan(dev_data->dev, "tx1");
	if (IS_ERR(dev_data->dma_aes_tx)) {
		ret = dev_err_probe(dev_data->dev, PTR_ERR(dev_data->dma_aes_tx),
				    "Unable to request tx1 DMA channel\n");
		goto err_dma_aes_tx;
	}

	dev_data->dma_sha_tx = dma_request_chan(dev_data->dev, "tx2");
	if (IS_ERR(dev_data->dma_sha_tx)) {
		ret = dev_err_probe(dev_data->dev, PTR_ERR(dev_data->dma_sha_tx),
				    "Unable to request tx2 DMA channel\n");
		goto err_dma_sha_tx;
	}

	memzero_explicit(&cfg, sizeof(cfg));

	cfg.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	cfg.src_maxburst = 4;

	ret = dmaengine_slave_config(dev_data->dma_aes_rx, &cfg);
	if (ret) {
		dev_err(dev_data->dev, "Can't configure IN dmaengine slave: %d\n", ret);
		goto err_dma_config;
	}

	cfg.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	cfg.dst_maxburst = 4;

	ret = dmaengine_slave_config(dev_data->dma_aes_tx, &cfg);
	if (ret) {
		dev_err(dev_data->dev, "Can't configure OUT dmaengine slave: %d\n", ret);
		goto err_dma_config;
	}

	return 0;

err_dma_config:
	dma_release_channel(dev_data->dma_sha_tx);
err_dma_sha_tx:
	dma_release_channel(dev_data->dma_aes_tx);
err_dma_aes_tx:
	dma_release_channel(dev_data->dma_aes_rx);

	return ret;
}

static int dthe_register_algs(void)
{
	return dthe_register_aes_algs();
}

static void dthe_unregister_algs(void)
{
	dthe_unregister_aes_algs();
}

static int dthe_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct dthe_data *dev_data;
	int ret;

	dev_data = devm_kzalloc_obj(dev, *dev_data);
	if (!dev_data)
		return -ENOMEM;

	dev_data->dev = dev;
	dev_data->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(dev_data->regs))
		return PTR_ERR(dev_data->regs);

	ret = dthe_dma_init(dev_data);
	if (ret)
		return ret;

	dev_data->engine = crypto_engine_alloc_init(dev, 1);
	if (!dev_data->engine) {
		ret = -ENOMEM;
		goto probe_engine_err;
	}

	ret = crypto_engine_start(dev_data->engine);
	if (ret) {
		dev_err(dev, "Failed to start crypto engine\n");
		goto probe_engine_start_err;
	}

	kref_init(&dev_data->refcnt);
	init_completion(&dev_data->drain_compl);

	spin_lock_bh(&dthe_dev_list.lock);
	platform_set_drvdata(pdev, dev_data);
	list_add(&dev_data->list, &dthe_dev_list.dev_list);
	spin_unlock_bh(&dthe_dev_list.lock);

	ret = dthe_register_algs();
	if (ret) {
		dev_err(dev, "Failed to register algs\n");
		goto probe_register_algs_err;
	}

	return 0;

probe_register_algs_err:
	spin_lock_bh(&dthe_dev_list.lock);
	list_del(&dev_data->list);
	platform_set_drvdata(pdev, NULL);
	spin_unlock_bh(&dthe_dev_list.lock);

	dthe_put_drvdata(dev_data);
	wait_for_completion(&dev_data->drain_compl);
probe_engine_start_err:
	crypto_engine_exit(dev_data->engine);
probe_engine_err:
	dma_release_channel(dev_data->dma_aes_rx);
	dma_release_channel(dev_data->dma_aes_tx);
	dma_release_channel(dev_data->dma_sha_tx);

	return ret;
}

static void dthe_remove(struct platform_device *pdev)
{
	struct dthe_data *dev_data = platform_get_drvdata(pdev);

	spin_lock_bh(&dthe_dev_list.lock);
	list_del(&dev_data->list);
	platform_set_drvdata(pdev, NULL);
	spin_unlock_bh(&dthe_dev_list.lock);

	dthe_unregister_algs();

	dthe_put_drvdata(dev_data);
	wait_for_completion(&dev_data->drain_compl);

	crypto_engine_exit(dev_data->engine);

	dma_release_channel(dev_data->dma_aes_rx);
	dma_release_channel(dev_data->dma_aes_tx);
	dma_release_channel(dev_data->dma_sha_tx);
}

static const struct of_device_id dthe_of_match[] = {
	{ .compatible = "ti,am62l-dthev2", },
	{},
};
MODULE_DEVICE_TABLE(of, dthe_of_match);

static struct platform_driver dthe_driver = {
	.probe	= dthe_probe,
	.remove	= dthe_remove,
	.driver = {
		.name		= DRIVER_NAME,
		.of_match_table	= dthe_of_match,
	},
};

module_platform_driver(dthe_driver);

MODULE_AUTHOR("T Pratham <t-pratham@ti.com>");
MODULE_DESCRIPTION("Texas Instruments DTHE V2 driver");
MODULE_LICENSE("GPL");
