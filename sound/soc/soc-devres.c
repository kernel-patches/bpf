// SPDX-License-Identifier: GPL-2.0+
//
// soc-devres.c  --  ALSA SoC Audio Layer devres functions
//
// Copyright (C) 2013 Linaro Ltd

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>

static void devm_component_release(struct device *dev, void *res)
{
	struct snd_soc_component **component = res;

	snd_soc_component_unregister(*component);
}

/**
 * devm_snd_soc_register_component - resource managed component registration
 * @dev: Device used to manage component
 * @cmpnt_drv: Component driver
 * @dai_drv: DAI driver
 * @num_dai: Number of DAIs to register
 *
 * Register a component with automatic unregistration when the device is
 * unregistered.
 */
int devm_snd_soc_register_component(struct device *dev,
			 const struct snd_soc_component_driver *cmpnt_drv,
			 struct snd_soc_dai_driver *dai_drv, int num_dai)
{
	const struct snd_soc_component **ptr;
	struct snd_soc_component *component;
	int ret = -ENOMEM;

	component = snd_soc_component_new(dev, NULL, cmpnt_drv);
	if (IS_ERR(component))
		goto err;

	ptr = devres_alloc(devm_component_release, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		goto free_component;

	ret = snd_soc_component_register(component, dai_drv, num_dai);
	if (ret < 0)
		goto free_devres;

	*ptr = component;
	devres_add(dev, ptr);

	return ret;

free_devres:
	devres_free(ptr);
free_component:
	devm_kfree(dev, component);
err:
	return ret;
}
EXPORT_SYMBOL_GPL(devm_snd_soc_register_component);

/**
 * devm_snd_soc_register_card - resource managed card registration
 * @dev: Device used to manage card
 * @card: Card to register
 *
 * Register a card with automatic unregistration when the device is
 * unregistered.
 */
int devm_snd_soc_register_card(struct device *dev, struct snd_soc_card *card)
{
	card->devres_dev = dev;
	return snd_soc_register_card(card);
}
EXPORT_SYMBOL_GPL(devm_snd_soc_register_card);
