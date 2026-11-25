// SPDX-License-Identifier: GPL-2.0+
//
// soc-devres.c  --  ALSA SoC Audio Layer devres functions
//
// Copyright (C) 2013 Linaro Ltd

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>

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
