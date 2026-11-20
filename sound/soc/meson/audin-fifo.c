// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 BayLibre, SAS.
// Author: Valerio Setti <vsetti@baylibre.com>

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/hrtimer.h>
#include <linux/math64.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/wordpart.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dai.h>

#include "audin.h"

/* FIFO registers */
#define AUDIN_FIFO_START	0x00
#define AUDIN_FIFO_END		0x04
#define AUDIN_FIFO_PTR		0x08

/* FIFOx_CTRL1 registers and bits */
#define AUDIN_FIFO_CTRL1			0x18
#define  AUDIN_FIFO_CTRL1_DIN_BYTE_NUM_MASK	GENMASK(3, 2)
#define  AUDIN_FIFO_CTRL1_DIN_POS_01_MASK	GENMASK(1, 0)

/* When the FIFO is full the data is bulk transferred to memory. */
#define AUDIN_FIFO_LANE_SIZE		8 /* bytes */
#define AUDIN_FIFO_I2S_BLOCK		(AUDIN_FIFO_LANE_SIZE * 32) /* 256 bytes */

static const struct snd_pcm_hardware audin_fifo_pcm_hw = {
	.info = (SNDRV_PCM_INFO_INTERLEAVED |
		 SNDRV_PCM_INFO_MMAP |
		 SNDRV_PCM_INFO_MMAP_VALID |
		 SNDRV_PCM_INFO_BLOCK_TRANSFER |
		 SNDRV_PCM_INFO_PAUSE),
	.formats = SNDRV_PCM_FMTBIT_S16_LE,
	.rate_min = 5512,
	.rate_max = 192000,
	.channels_min = 2,
	.channels_max = 2,
	/*
	 * The FIFO only moves data to the memory once it is full, so its pointer
	 * progresses one block at a time.
	 */
	.period_bytes_min = 2 * AUDIN_FIFO_I2S_BLOCK,
	.period_bytes_max = UINT_MAX, /* Bounded by buffer_bytes_max */
	.periods_min = 2,
	.periods_max = UINT_MAX,
	/*
	 * It's 1 MB. There is no physical constraint for this; it's only meant to
	 * provide some decently large buffer size where to store incoming data
	 * and fit various period_bytes requests.
	 */
	.buffer_bytes_max = 4096 * AUDIN_FIFO_I2S_BLOCK,
};

struct audin_fifo_dai_data {
	/*
	 * The AUDIN peripheral has an IRQ to signal when data is received, but
	 * it cannot grant a periodic behavior. The reason is that the register
	 * which holds the address which triggers the IRQ must be updated
	 * continuously. This creates a risk of overflow if for any reason the
	 * ISR execution is delayed. Using a periodic timer is therefore simpler
	 * and more reliable.
	 */
	struct hrtimer polling_timer;
	struct snd_soc_dai *dai;
	struct snd_pcm_substream *substream;
	unsigned int period_bytes;
	unsigned int byte_rate;
	unsigned int last_pos; /* Position inside the allocated read buffer. */
	bool running;
};

static unsigned int audin_fifo_pos(struct snd_soc_dai *dai,
				   struct snd_pcm_runtime *runtime)
{
	unsigned int ptr = lower_32_bits(runtime->dma_addr);

	regmap_read(dai->component->regmap, dai->driver->base + AUDIN_FIFO_PTR, &ptr);

	return ptr - lower_32_bits(runtime->dma_addr);
}

static ktime_t audin_fifo_bytes_to_ns(struct audin_fifo_dai_data *data,
				      unsigned int bytes)
{
	return div_u64((u64)bytes * NSEC_PER_SEC, data->byte_rate);
}

static int audin_fifo_dai_trigger(struct snd_pcm_substream *substream, int cmd,
				  struct snd_soc_dai *dai)
{
	struct audin_fifo_dai_data *data = snd_soc_dai_dma_data_get_capture(dai);
	struct snd_soc_component *component = dai->component;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL,
					      AUDIN_FIFO_CTRL_EN,
					      AUDIN_FIFO_CTRL_EN);
		WRITE_ONCE(data->running, true);
		hrtimer_start(&data->polling_timer,
			      audin_fifo_bytes_to_ns(data, data->period_bytes),
			      HRTIMER_MODE_REL_SOFT);
		break;
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_STOP:
		WRITE_ONCE(data->running, false);
		/*
		 * PCM stream lock is held here so we cannot call hrtimer_cancel()
		 * which might block if timer's callback is running. Timer is
		 * properly stopped in sync_stop() and shutdown() callbacks.
		 */
		hrtimer_try_to_cancel(&data->polling_timer);
		snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL,
					      AUDIN_FIFO_CTRL_EN, 0);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int audin_fifo_dai_prepare(struct snd_pcm_substream *substream,
				  struct snd_soc_dai *dai)
{
	struct audin_fifo_dai_data *data = snd_soc_dai_dma_data_get_capture(dai);
	struct snd_soc_component *component = dai->component;
	struct snd_pcm_runtime *runtime = substream->runtime;
	dma_addr_t dma_end = runtime->dma_addr + runtime->dma_bytes - AUDIN_FIFO_LANE_SIZE;
	unsigned int val;

	data->last_pos = 0;

	/*
	 * Setup memory boundaries.
	 * Note: DMA has a 32-bit mask, so it's OK to take lower 32 bits.
	 */
	snd_soc_component_write(component, dai->driver->base + AUDIN_FIFO_START,
				lower_32_bits(runtime->dma_addr));
	snd_soc_component_write(component, dai->driver->base + AUDIN_FIFO_PTR,
				lower_32_bits(runtime->dma_addr));
	snd_soc_component_write(component, dai->driver->base + AUDIN_FIFO_END,
				lower_32_bits(dma_end));

	/* Load new addresses (both LOAD and UG are self-clearing). */
	val = AUDIN_FIFO_CTRL_LOAD | AUDIN_FIFO_CTRL_UG;
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL, val, val);

	/* Reset (RST is self-clearing). */
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL,
				      AUDIN_FIFO_CTRL_RST,
				      AUDIN_FIFO_CTRL_RST);

	return 0;
}

static int audin_fifo_dai_hw_params(struct snd_pcm_substream *substream,
				    struct snd_pcm_hw_params *params,
				    struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct audin_fifo_dai_data *data = snd_soc_dai_dma_data_get_capture(dai);
	unsigned int val;

	/*
	 * The I2S input decoder passes 24 bits of left-justified data
	 * but for the time being we only support 16 bit formatted samples
	 * which means that we drop the LSB.
	 */
	val = FIELD_PREP(AUDIN_FIFO_CTRL1_DIN_POS_01_MASK, 1);
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL1,
				      AUDIN_FIFO_CTRL1_DIN_POS_01_MASK,
				      val);

	/* Set sample size to 2 bytes (16 bit) */
	val = FIELD_PREP(AUDIN_FIFO_CTRL1_DIN_BYTE_NUM_MASK, 1);
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL1,
				      AUDIN_FIFO_CTRL1_DIN_BYTE_NUM_MASK,
				      val);

	/*
	 * This is a bit counterintuitive. Even though the platform has a single
	 * pin for I2S input which would mean that we can only support 2
	 * channels, doing so would cause samples to be stored in a weird way
	 * into the FIFO: all the samples from the 1st channel on the 1st half
	 * of the FIFO, then samples from the 2nd channel in the other half. Of
	 * course extra work would be required to properly interleave them
	 * before returning to the userspace.
	 * Setting a single channel mode instead solves the problem: samples
	 * from 1st and 2nd channel are stored interleaved and sequentially in
	 * the FIFO.
	 */
	val = FIELD_PREP(AUDIN_FIFO_CTRL_CHAN_MASK, 1);
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL,
				      AUDIN_FIFO_CTRL_CHAN_MASK, val);

	/*
	 * FIFO is filled line by line and each of them is 8 bytes. The
	 * problem is that each line is filled starting from the end,
	 * so we need to properly reorder them before moving to the
	 * RAM. This is the value required to properly re-order samples stored
	 * in 16 bit format.
	 */
	val = FIELD_PREP(AUDIN_FIFO_CTRL_ENDIAN_MASK, 6);
	snd_soc_component_update_bits(component, dai->driver->base + AUDIN_FIFO_CTRL,
				      AUDIN_FIFO_CTRL_ENDIAN_MASK, val);

	/* Used by the polling timer to convert a byte count into a delay. */
	data->period_bytes = params_period_bytes(params);
	data->byte_rate = params_rate(params) * params_channels(params) *
			  params_physical_width(params) / BITS_PER_BYTE;

	data->substream = substream;

	return 0;
}

static int audin_fifo_dai_startup(struct snd_pcm_substream *substream,
				  struct snd_soc_dai *dai)
{
	int ret;

	snd_soc_set_runtime_hwparams(substream, &audin_fifo_pcm_hw);

	ret = snd_pcm_hw_constraint_step(substream->runtime, 0,
					 SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
					 AUDIN_FIFO_I2S_BLOCK);
	if (ret < 0) {
		dev_err(dai->dev, "Failed to set constraint on buffer_bytes %d\n", ret);
		return ret;
	}

	ret = snd_pcm_hw_constraint_step(substream->runtime, 0,
					 SNDRV_PCM_HW_PARAM_PERIOD_BYTES,
					 AUDIN_FIFO_I2S_BLOCK);
	if (ret < 0) {
		dev_err(dai->dev, "Failed to set constraint on period_bytes %d\n", ret);
		return ret;
	}

	return 0;
}

static void audin_fifo_dai_shutdown(struct snd_pcm_substream *substream,
				    struct snd_soc_dai *dai)
{
	struct audin_fifo_dai_data *data = snd_soc_dai_dma_data_get_capture(dai);

	hrtimer_cancel(&data->polling_timer);
}

static int audin_fifo_dai_pcm_new(struct snd_soc_pcm_runtime *rtd,
				  struct snd_soc_dai *dai)
{
	int ret;

	ret = dma_coerce_mask_and_coherent(dai->dev, DMA_BIT_MASK(32));
	if (ret) {
		dev_err(dai->dev, "Failed to set DMA mask %d\n", ret);
		return ret;
	}

	ret = snd_pcm_set_managed_buffer_all(rtd->pcm, SNDRV_DMA_TYPE_DEV,
					     dai->dev,
					     audin_fifo_pcm_hw.buffer_bytes_max,
					     audin_fifo_pcm_hw.buffer_bytes_max);
	if (ret) {
		dev_err(dai->dev, "Failed to set PCM managed buffer %d\n", ret);
		return ret;
	}

	return 0;
}

static enum hrtimer_restart audin_fifo_timer_cb(struct hrtimer *timer)
{
	struct audin_fifo_dai_data *data =
		container_of(timer, struct audin_fifo_dai_data, polling_timer);
	struct snd_pcm_substream *substream = data->substream;
	struct snd_pcm_runtime *runtime = substream->runtime;
	unsigned int curr_pos;
	unsigned int delta, elapsed_periods_bytes, extra_bytes, sleep_bytes;

	/*
	 * Take the stream lock to prevent userspace from issuing a quick
	 * PAUSE_PUSH -> PAUSE_RELEASE transition while we're running this
	 * callback. Doing so would cause "hrtimer_forward_now()" to be called
	 * (see below) while the timer is already enqueued.
	 */
	guard(pcm_stream_lock_irqsave)(substream);

	/* Stopped, or a trigger already re-armed the timer while we waited. */
	if (!READ_ONCE(data->running) || hrtimer_is_queued(timer))
		return HRTIMER_NORESTART;

	curr_pos = audin_fifo_pos(data->dai, runtime);
	delta = (curr_pos >= data->last_pos) ?
		curr_pos - data->last_pos :
		(runtime->dma_bytes - data->last_pos) + curr_pos;
	extra_bytes = delta % data->period_bytes;
	elapsed_periods_bytes = delta - extra_bytes;

	/* Report only when the period is completed. */
	if (delta >= data->period_bytes) {
		data->last_pos = data->last_pos + elapsed_periods_bytes;
		if (data->last_pos >= runtime->dma_bytes)
			data->last_pos %= runtime->dma_bytes;
		snd_pcm_period_elapsed_under_stream_lock(substream);
	}

	/* Reporting the period might stop the stream on XRUN. */
	if (!READ_ONCE(data->running))
		return HRTIMER_NORESTART;

	/* Sleep until the period is completed. */
	sleep_bytes = round_up(data->period_bytes - extra_bytes, AUDIN_FIFO_I2S_BLOCK);
	hrtimer_forward_now(timer, audin_fifo_bytes_to_ns(data, sleep_bytes));

	return HRTIMER_RESTART;
}

static int audin_fifo_dai_probe(struct snd_soc_dai *dai)
{
	struct audin_fifo_dai_data *data;

	data = kzalloc_obj(*data);
	if (!data)
		return -ENOMEM;

	data->dai = dai;

	hrtimer_setup(&data->polling_timer, audin_fifo_timer_cb, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_SOFT);

	snd_soc_dai_dma_data_set_capture(dai, data);

	return 0;
}

static int audin_fifo_dai_remove(struct snd_soc_dai *dai)
{
	kfree(snd_soc_dai_dma_data_get_capture(dai));

	return 0;
}

const struct snd_soc_dai_ops audin_fifo_dai_ops = {
	.trigger	= audin_fifo_dai_trigger,
	.prepare	= audin_fifo_dai_prepare,
	.hw_params	= audin_fifo_dai_hw_params,
	.startup	= audin_fifo_dai_startup,
	.shutdown	= audin_fifo_dai_shutdown,
	.pcm_new	= audin_fifo_dai_pcm_new,
	.probe		= audin_fifo_dai_probe,
	.remove		= audin_fifo_dai_remove,
};

snd_pcm_uframes_t audin_fifo_component_pointer(struct snd_soc_component *component,
					       struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *dai = snd_soc_rtd_to_cpu(rtd, 0);

	return bytes_to_frames(runtime, audin_fifo_pos(dai, runtime));
}

/*
 * sync_stop() is called before hw_params(), hw_free(), suspend(), prepare().
 * Cancelling the hrtimer here ensures the timer is really stopped even in
 * case the stream is run->stop->prepare->start.
 */
int audin_fifo_sync_stop(struct snd_soc_component *component, struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct audin_fifo_dai_data *data = snd_soc_dai_dma_data_get_capture(dai);

	hrtimer_cancel(&data->polling_timer);
	WRITE_ONCE(data->running, false);

	return 0;
}
