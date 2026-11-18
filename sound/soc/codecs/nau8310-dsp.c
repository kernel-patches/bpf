// SPDX-License-Identifier: GPL-2.0-only
//
// The NAU83G10/20 Boosted Mono Class-D Amplifier with DSP and I/V-sense driver.
//
// Copyright 2026 Nuvoton Technology Crop.
// Author: John Hsu <KCHSU0@nuvoton.com>
//         David Lin <ctlin0@nuvoton.com>
//         Neo Chang <ylchang2@nuvoton.com>

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/bitfield.h>
#include <sound/soc.h>

#include "nau8310-dsp.h"
#include "nau8310.h"

#define NAU8310_DSP_IDLE_RETRY 10

static int nau8310_dsp_set_kcs_setup(struct snd_soc_component *component);

#define NAU_DSP_CMD(_id, _msg, _setup, _reply) \
	[_id] = { \
		.cmd_id = _id, \
		.msg_param = _msg, \
		.setup_data = _setup, \
		.reply_data = _reply, \
	}

#define NAU_DSP_CMD_ID(_id) \
	[_id] = { \
		.cmd_id = _id, \
	}

/*
 * Preamble Fragment Masks:
 * FIELD           | BITS   | SHIFT | MASK | DETAILS
 * ----------------|--------|-------|------|---------------------------------
 * length high     | [31:24]| 24    | 0xff | Upper 8 bits of total length (LEN[9:2])
 * cmd_id          | [23:18]| 18    | 0x3f | Command identifier (6 bits)
 * length low      | [17:16]| 16    | 0x03 | Lower 2 bits of total length (LEN[1:0])
 * preamble magic  | [15:0] | 0     |0xffff| Preamble signature (0xB2A1)
 */
#define NAU8310_HOST_LEN_HIGH_MASK	GENMASK(31, 24)
#define NAU8310_HOST_CMD_ID_MASK	GENMASK(23, 18)
#define NAU8310_HOST_LEN_LOW_MASK	GENMASK(17, 16)
#define NAU8310_HOST_PREAMBLE_MASK	GENMASK(15, 0)

/*
 * Payload Fragment Masks:
 * FIELD           | BITS   | SHIFT | MASK | DETAILS
 * ----------------|--------|-------|------|---------------------------------
 * param_size      | [31:16]| 16    |0xffff| Size of parameter data (16 bits)
 * param_offset    | [15:0] | 0     |0xffff| Starting offset (16 bits)
 */
#define NAU8310_HOST_PARAM_SIZE_MASK	GENMASK(31, 16)
#define NAU8310_HOST_PARAM_OFFSET_MASK	GENMASK(15, 0)

/*
 * Trailing Fragment Masks:
 * FIELD           | BITS   | SHIFT | MASK | DETAILS
 * ----------------|--------|-------|------|---------------------------------
 * length high     | [15:14]| 14    | 0x03 | Upper 2 bits of total length
 * padding         | [13:12]| 12    | 0x03 | Padding bytes count
 * length low      | [7:0]  | 0     | 0xff | Lower 8 bits of total length
 * Note: Reassembled length = (length_high << 8) | length_low (Total 10 bits)
 */
#define NAU8310_TRAIL_LEN_LOW_MASK	GENMASK(7, 0)
#define NAU8310_TRAIL_PAD_MASK		GENMASK(13, 12)
#define NAU8310_TRAIL_LEN_HIGH_MASK	GENMASK(15, 14)

/*
 * Reply Preamble Masks:
 * FIELD           | BITS   | SHIFT | MASK | DETAILS
 * ----------------|--------|-------|------|---------------------------------
 * length high     | [31:24]| 24    | 0xff | Upper 8 bits of total length
 * reply_id        | [23:18]| 18    | 0x3f | Reply identifier (6 bits)
 * length low      | [17:16]| 16    | 0x03 | Lower 2 bits of total length
 * Note: Reassembled length = (length_high << 2) | length_low (Total 10 bits)
 */
#define NAU8310_REPLY_LEN_HIGH_MASK	GENMASK(31, 24)
#define NAU8310_REPLY_ID_MASK		GENMASK(23, 18)
#define NAU8310_REPLY_LEN_LOW_MASK	GENMASK(17, 16)

static const struct nau8310_cmd_info nau8310_dsp_cmd_table[] = {
	/* { cmd_id, msg_param, setup_data, reply_data} */
	NAU_DSP_CMD(NAU8310_DSP_CMD_GET_COUNTER,      0, 0, 1),
	NAU_DSP_CMD(NAU8310_DSP_CMD_GET_FRAME_STATUS, 0, 0, 1),
	NAU_DSP_CMD(NAU8310_DSP_CMD_GET_REVISION,     0, 0, 1),
	NAU_DSP_CMD(NAU8310_DSP_CMD_GET_KCS_RSLTS,    1, 0, 1),
	NAU_DSP_CMD(NAU8310_DSP_CMD_GET_KCS_SETUP,    1, 0, 1),
	NAU_DSP_CMD(NAU8310_DSP_CMD_SET_KCS_SETUP,    1, 1, 0),
	NAU_DSP_CMD_ID(NAU8310_DSP_CMD_CLK_STOP),
	NAU_DSP_CMD_ID(NAU8310_DSP_CMD_CLK_RESTART),
};

static const char *const dsp_cmd_table[] = {
	[NAU8310_DSP_CMD_GET_COUNTER] = "GET_COUNTER",
	[NAU8310_DSP_CMD_GET_FRAME_STATUS] = "GET_FRAME_STATUS",
	[NAU8310_DSP_CMD_GET_REVISION] = "GET_REVISION",
	[NAU8310_DSP_CMD_GET_KCS_RSLTS] = "GET_KCS_RSLTS",
	[NAU8310_DSP_CMD_GET_KCS_SETUP] = "GET_KCS_SETUP",
	[NAU8310_DSP_CMD_SET_KCS_SETUP] = "SET_KCS_SETUP",
	[NAU8310_DSP_CMD_CLK_STOP] = "CLK_STOP",
	[NAU8310_DSP_CMD_CLK_RESTART] = "CLK_RESTART",
};

static int nau8310_dsp_idle(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct regmap *regmap = nau8310->regmap;
	unsigned int idle_pattern, timeout = NAU8310_DSP_IDLE_RETRY * USEC_PER_MSEC;
	int ret = 0;

	ret = regmap_read_poll_timeout(regmap,
		NAU8310_RF000_DSP_COMM, idle_pattern,
		idle_pattern == NAU8310_DSP_COMM_IDLE_WORD, USEC_PER_MSEC, timeout);
	if (ret) {
		dev_err(nau8310->dev, "Timeout waiting for DSP idle state: %d", ret);
		nau8310_software_reset(regmap);
	}

	return ret;
}

/*
 * nau8310_pack_preamble - Pack DSP preamble fragment
 * @cmd_id: Command ID for the DSP message
 * @frag_len: Total length of the message fragments
 *
 * Return: 32-bit packed payload in Little Endian format.
 */
static inline u32 nau8310_pack_preamble(u8 cmd_id, u16 frag_len)
{
	return FIELD_PREP(NAU8310_HOST_PREAMBLE_MASK, NAU8310_DSP_COMM_PREAMBLE) |
		FIELD_PREP(NAU8310_HOST_CMD_ID_MASK, cmd_id) |
		FIELD_PREP(NAU8310_HOST_LEN_LOW_MASK, frag_len) |
		FIELD_PREP(NAU8310_HOST_LEN_HIGH_MASK, frag_len >> 2);
}

/*
 * nau8310_pack_param - Pack DSP parameter fragment
 * @param_offset: Starting offset of the parameter data
 * @param_size: Size of the parameter data in bytes
 *
 * Return: 32-bit packed payload in Little Endian format.
 */
static inline u32 nau8310_pack_param(u16 param_offset, u16 param_size)
{
	return FIELD_PREP(NAU8310_HOST_PARAM_OFFSET_MASK, param_offset) |
		FIELD_PREP(NAU8310_HOST_PARAM_SIZE_MASK, param_size);
}

/*
 * nau8310_pack_trailing - Pack DSP trailing fragment
 * @frag_cnt: Current fragment count
 * @padding: Number of padding bytes added to the final data fragment
 *
 * Return: 32-bit packed payload in Little Endian format.
 */
static inline u32 nau8310_pack_trailing(u16 frag_cnt, u8 padding)
{
	return FIELD_PREP(NAU8310_TRAIL_LEN_LOW_MASK, frag_cnt) |
		FIELD_PREP(NAU8310_TRAIL_PAD_MASK, padding) |
		FIELD_PREP(NAU8310_TRAIL_LEN_HIGH_MASK, frag_cnt >> 8);
}

static void nau8310_send_data_payload(struct snd_soc_component *cp,
	unsigned short dsp_addr, const void *param_data, int param_size,
	int *frag_cnt, int *padding)
{
	const u8 *data = (const u8 *)param_data;
	u32 payload = 0;
	int i, data_size = 0;

	for (i = 0; i < param_size; i++) {
		payload |= (u32)data[i] << (data_size * 8);
		data_size++;

		if (data_size == NAU8310_DSP_DATA_BYTE) {
			snd_soc_component_write(cp, dsp_addr, payload);

			data_size = 0;
			payload = 0;
			(*frag_cnt)++;
		}
	}

	if (data_size > 0) {
		*padding = NAU8310_DSP_DATA_BYTE - data_size;
		snd_soc_component_write(cp, dsp_addr, payload);
		(*frag_cnt)++;
	}
}

static int nau8310_message_to_dsp(struct snd_soc_component *cp,
	const struct nau8310_cmd_info *cmd_info, int frag_len,
	int param_offset, int param_size, void *param_data)
{
	unsigned int payload;
	int ret, padding = 0, frag_cnt = 0;

	ret = nau8310_dsp_idle(cp);
	if (ret)
		return ret;

	/* sending preamble fragment */
	payload = nau8310_pack_preamble(cmd_info->cmd_id, frag_len);
	snd_soc_component_write(cp, NAU8310_RF000_DSP_COMM, payload);

	if (!cmd_info->msg_param)
		return 0;

	/* sending payload + padding */
	payload = nau8310_pack_param(param_offset, param_size);
	snd_soc_component_write(cp, NAU8310_RF000_DSP_COMM, payload);
	frag_cnt++;

	if (cmd_info->setup_data)
		nau8310_send_data_payload(cp, NAU8310_RF000_DSP_COMM, param_data,
			param_size, &frag_cnt, &padding);

	/* sending trailing fragment */
	frag_cnt++;
	payload = nau8310_pack_trailing(frag_cnt, padding);
	snd_soc_component_write(cp, NAU8310_RF000_DSP_COMM, payload);

	if (frag_cnt != frag_len) {
		dev_err(cp->dev, "message error (CMD_ID 0x%x, LEN 0x%x) !!!",
			cmd_info->cmd_id, frag_cnt);
		return -EPROTO;
	}

	return 0;
}

static int nau8310_dsp_replied(struct nau8310 *nau8310, int *length)
{
	unsigned int reply_preamble;
	int ret, reply_id;

	ret = regmap_read_poll_timeout(nau8310->regmap,
		NAU8310_RF000_DSP_COMM, reply_preamble,
		(reply_preamble & 0xffff) == NAU8310_DSP_COMM_PREAMBLE,
		USEC_PER_MSEC, NAU8310_DSP_IDLE_RETRY * USEC_PER_MSEC);
	if (ret) {
		dev_err(nau8310->dev, "timeout for reply preamble: %d", ret);
		return ret;
	}

	*length = FIELD_GET(NAU8310_REPLY_LEN_LOW_MASK, reply_preamble);
	*length |= FIELD_GET(NAU8310_REPLY_LEN_HIGH_MASK, reply_preamble) << 2;
	reply_id = FIELD_GET(NAU8310_REPLY_ID_MASK, reply_preamble);

	return (reply_id != NAU8310_DSP_REPLY_OK) ? -reply_id : 0;
}

static int nau8310_validate_trailing(struct snd_soc_component *cp,
	int frag_len, int pad_len_exp)
{
	int ret, len_pos, pad_len;
	unsigned int payload;
	struct device *dev = cp->dev;
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);

	/* reading trailing fragment */
	ret = regmap_read(nau8310->regmap, NAU8310_RF000_DSP_COMM, &payload);
	if (ret) {
		dev_err(dev, "failed to read trailing fragment");
		return ret;
	}

	len_pos = FIELD_GET(NAU8310_TRAIL_LEN_LOW_MASK, payload);
	len_pos |= FIELD_GET(NAU8310_TRAIL_LEN_HIGH_MASK, payload) << 8;

	if (len_pos != frag_len) {
		dev_err(dev, "LEN_POST %02X, expect %02X", len_pos, frag_len);
		return -EPROTO;
	}

	pad_len = FIELD_GET(NAU8310_TRAIL_PAD_MASK, payload);
	if (pad_len != pad_len_exp) {
		dev_err(dev, "PAD_LEN %02X, expect %02X", pad_len, pad_len_exp);
		return -EPROTO;
	}

	return 0;
}

static int nau8310_read_data_payload(struct snd_soc_component *cp,
	int frag_len, bool msg_param,
	void *data, int data_size, int *data_count)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct device *dev = cp->dev;
	unsigned int payload;
	u32 *data_buf = data;
	int i, j, ret;

	*data_count = (msg_param) ? data_size : 0;
	for (i = 0; i < frag_len - 1; i++) {
		ret = regmap_read(nau8310->regmap, NAU8310_RF000_DSP_COMM, &payload);
		if (ret) {
			dev_err(dev, "failed to read payload of dsp");
			return ret;
		}

		if (!msg_param) {
			*data_buf++ = payload;
			break;
		}

		if (*data_count >= NAU8310_DSP_DATA_BYTE) {
			*data_buf++ = payload;
			*data_count -= NAU8310_DSP_DATA_BYTE;
		} else if (*data_count > 0) {
			for (j = 0; j < *data_count; j++)
				((u8 *)data_buf)[j] = (payload >> (j * 8)) & 0xff;

			*data_count = 0;
		}

		if (*data_count == 0)
			break;
	}

	return 0;
}

static int nau8310_reply_from_dsp(struct snd_soc_component *cp,
	const struct nau8310_cmd_info *cmd_info, int data_size,
	void *data)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct device *dev = cp->dev;
	int ret, frag_len, pad_len_exp, data_count = 0;

	ret = nau8310_dsp_replied(nau8310, &frag_len);
	if (ret)
		return ret;
	if (!frag_len || !cmd_info->reply_data)
		return 0;
	if (!data || frag_len == 1)
		return -EINVAL;

	ret = nau8310_read_data_payload(cp, frag_len,
		cmd_info->msg_param, data, data_size, &data_count);
	if (ret)
		return ret;

	/* check the reply length same as request */
	if (data_count && (cmd_info->cmd_id == NAU8310_DSP_CMD_GET_KCS_RSLTS ||
		cmd_info->cmd_id == NAU8310_DSP_CMD_GET_KCS_SETUP))
		dev_warn(dev, "payload_len %d, expected %d",
			data_size - data_count, data_size);

	pad_len_exp = cmd_info->msg_param ?
		(frag_len - 1) * NAU8310_DSP_DATA_BYTE - (data_size - data_count) : 0;
	return nau8310_validate_trailing(cp, frag_len, pad_len_exp);
}

/*
 * nau8310_send_dsp_command - Send command to DSP
 *
 * @cp:  component to register
 * @cmd_id:  DSP supported command ID
 * @kcs_setup: KCS setup structure
 *
 * The communication protocol is a Master-Slave type protocol
 * where the host processor is the master and DSP is the slave.
 * The Master initiates the communication and can either write or
 * read back from the slave.
 * Transactions from the Master are called "Messages",
 * and read-back data from the Slave is called a "Reply".
 *
 * The function sends command to DSP according to the command ID.
 * These commands include getting the information of DSP,
 * getting or setting KCS configuration, or making DSP control.
 */
static int nau8310_send_dsp_command(struct snd_soc_component *cp, int cmd_id,
	struct nau8310_kcs_setup *kcs_setup)
{
	const struct nau8310_cmd_info *cmd_info;
	int ret = 0, frag_len = 0;

	cmd_info = &nau8310_dsp_cmd_table[cmd_id];
	if ((cmd_info->msg_param && !kcs_setup->set_len) ||
		(cmd_info->setup_data && !kcs_setup->set_kcs_data) ||
		(cmd_info->reply_data && !kcs_setup->get_data))
		return -EFAULT;

	/*
	 * Read up to 1kB data because the LEN field to request data is 10-bits
	 * long; and not beyond 3kB offset.
	 */
	if (cmd_id == NAU8310_DSP_CMD_GET_KCS_SETUP &&
		(kcs_setup->set_len > NAU8310_DSP_KCS_DAT_LEN_MAX ||
		kcs_setup->set_kcs_offset > NAU8310_DSP_KCS_OFFSET_MAX))
		return -ERANGE;

	/*
	 * one fragment for offset and size parameters
	 * one fragment for a postamble fragment
	 */
	if (cmd_info->msg_param)
		frag_len += 2;

	/* fragments for KCS setup writen */
	if (cmd_info->setup_data)
		frag_len += DIV_ROUND_UP(kcs_setup->set_len, NAU8310_DSP_DATA_BYTE);

	ret = nau8310_message_to_dsp(cp, cmd_info, frag_len,
		kcs_setup->set_kcs_offset, kcs_setup->set_len,
		kcs_setup->set_kcs_data);
	if (ret)
		return ret;

	return nau8310_reply_from_dsp(cp, cmd_info, kcs_setup->get_len,
		kcs_setup->get_data);
}

static inline int nau8310_dsp_exec_command(struct snd_soc_component *cp, int cmd_id,
	int offset, int set_len, void *set_data, int get_len, void *get_data)
{
	struct nau8310_kcs_setup kcs_setup = {
		.set_kcs_offset = offset,
		.set_len = set_len,
		.set_kcs_data = set_data,
		.get_len = get_len,
		.get_data = get_data,
	};

	return nau8310_send_dsp_command(cp, cmd_id, &kcs_setup);
}

/*
 * nau8310_dsp_kcs_setup - Send KCS setup command to DSP
 *
 * @cp:  component to register
 * @offset: address offset relative to KCS start
 * @size: size of data writen to KCS
 * @data: data writen to KCS setup
 *
 * The function sends KCS setup command to DSP for
 * setting KCS configuration. The maximum size that you can transfer into
 * the DSP is 96 bytes. Therefore, the driver has to split the data into
 * 96 bytes chucks, if the setup configuration over the threshold.
 */
static int nau8310_dsp_kcs_setup(struct snd_soc_component *cp, int offset, int size,
	const void *data)
{
	u8 *data_buf = (u8 *)data;
	unsigned int kcs_rst = 0;
	int retries = 0, ret, data_len, data_rem, addr_offset;

	/* Limit full load of KCS_SETUP data and not beyond 3kB offset. */
	if (!data || size > NAU8310_DSP_KCS_DAT_LEN_MAX ||
		offset > NAU8310_DSP_KCS_OFFSET_MAX)
		return -EINVAL;

	/* sending fragments for KCS setup */
	addr_offset = offset;
	data_rem = size;

	while (data_rem) {
		data_len = min(data_rem, NAU8310_DSP_KCS_TX_MAX);

		ret = nau8310_dsp_exec_command(cp, NAU8310_DSP_CMD_SET_KCS_SETUP,
			addr_offset, data_len, (void *)data_buf, 0, &kcs_rst);
		if (ret) {
			if (retries++ < NAU8310_DSP_RETRY_MAX)
				continue;
			return ret;
		}

		data_buf += (u8)data_len;
		addr_offset += data_len;
		data_rem -= data_len;

		/* checking KCS result */
		ret = nau8310_dsp_exec_command(cp, NAU8310_DSP_CMD_GET_KCS_RSLTS,
			0, NAU8310_DSP_DATA_BYTE, NULL, NAU8310_DSP_DATA_BYTE, &kcs_rst);
		if (ret)
			return ret;
		if (kcs_rst != NAU8310_DSP_KCS_RSLTS_SUCCESS)
			return -EINVAL;
	}

	return 0;
}

static int nau8310_dsp_snd_soc_dapm_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_to_dapm(kcontrol);
	struct snd_soc_component *component = snd_soc_dapm_to_component(dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(component);
	struct soc_mixer_control *mc =
		(struct soc_mixer_control *)kcontrol->private_value;
	unsigned int mask = (1 << fls(mc->max)) - 1;
	unsigned int val;

	snd_soc_dapm_mutex_lock(dapm);
	if (snd_soc_dapm_get_bias_level(dapm) > SND_SOC_BIAS_STANDBY) {
		dev_warn_ratelimited(nau8310->dev, "changing path is not allowed during playback");
		snd_soc_dapm_mutex_unlock(dapm);
		return -EBUSY;
	}

	val = (ucontrol->value.integer.value[0] & mask);

	if (val == NAU8310_DAC_SRC_DSP && !nau8310->load_fw_done) {
		dev_warn_ratelimited(nau8310->dev, "Cannot enable DSP: Firmware not ready or disabled");
		snd_soc_dapm_mutex_unlock(dapm);
		return -EBUSY;
	}
	snd_soc_dapm_mutex_unlock(dapm);

	mutex_lock(&nau8310->lock);
	regmap_update_bits(nau8310->regmap, NAU8310_R04_ENA_CTRL,
		NAU8310_DSP_SEL_OSC, val == NAU8310_DAC_SRC_DSP ? NAU8310_DSP_SEL_OSC : 0);
	mutex_unlock(&nau8310->lock);

	return snd_soc_dapm_put_volsw(kcontrol, ucontrol);
}

#define NAU8310_DSP_SOC_DAPM_SINGLE(xname, reg, shift, mask, invert) \
	SOC_SINGLE_EXT(xname, reg, shift, mask, invert, \
		snd_soc_dapm_get_volsw, nau8310_dsp_snd_soc_dapm_put)

static const struct snd_kcontrol_new nau8310_dacdat_select_dsp =
	NAU8310_DSP_SOC_DAPM_SINGLE("Switch", NAU8310_R1A_DSP_CORE_CTRL2,
		NAU8310_DAC_SEL_DSP_SFT, 1, 0);

static int nau8310_dsp_clock_event(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *cp = snd_soc_dapm_to_component(w->dapm);
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	int ret = 0;

	mutex_lock(&nau8310->lock);

	if (SND_SOC_DAPM_EVENT_ON(event)) {
		ret = nau8310_dsp_exec_command(cp, NAU8310_DSP_CMD_CLK_RESTART,
			0, 0, NULL, 0, NULL);
		if (ret)
			dev_err(cp->dev, "Send DSP command %s fail (%d)",
				dsp_cmd_table[NAU8310_DSP_CMD_CLK_RESTART], ret);
	} else {
		ret = nau8310_dsp_exec_command(cp, NAU8310_DSP_CMD_CLK_STOP,
			0, 0, NULL, 0, NULL);
		if (ret)
			dev_err(cp->dev, "Send DSP command %s fail (%d)",
				dsp_cmd_table[NAU8310_DSP_CMD_CLK_STOP], ret);
	}

	mutex_unlock(&nau8310->lock);

	return ret;
}

static const struct snd_soc_dapm_widget nau8310_dsp_dapm_widgets[] = {
	SND_SOC_DAPM_PGA("DSP", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_SWITCH("DAC data from DSP", SND_SOC_NOPM,
		0, 0, &nau8310_dacdat_select_dsp),
	SND_SOC_DAPM_SUPPLY("DSP Clock", SND_SOC_NOPM, 0, 0,
		nau8310_dsp_clock_event, SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
};

static const struct snd_soc_dapm_route nau8310_dsp_dapm_routes[] = {
	{ "DSP", NULL, "Capture Sense" },
	{ "DAC data from DSP", "Switch", "DSP" },
	{ "DAC", NULL, "DAC data from DSP" },
	{ "DSP", NULL, "DSP Clock" },
};

static int nau8310_dsp_set_kcs_setup(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct nau8310_kcs_setup kcs_setup_comp = {0};
	struct nau8310_kcs_setup *kcs_setup = &kcs_setup_comp;
	struct device *dev = cp->dev;
	const struct firmware *fw;
	int ret, status = 0, buf_off, buf_len;

	dev_dbg(dev, "Send DSP command %s",
		dsp_cmd_table[NAU8310_DSP_CMD_GET_FRAME_STATUS]);

	kcs_setup->get_len = kcs_setup->set_len = sizeof(status);
	kcs_setup->get_data = (void *)&status;

	ret = nau8310_send_dsp_command(cp, NAU8310_DSP_CMD_GET_FRAME_STATUS, kcs_setup);
	if (ret) {
		dev_err(dev, "Send DSP command %s fail (%d)",
			dsp_cmd_table[NAU8310_DSP_CMD_GET_FRAME_STATUS], ret);
		goto err;
	}

	if (!(status & NAU8310_DSP_ALGO_OK)) {
		dev_err(dev, "Algorithm of DSP is not ready, status %x", status);
		ret = -EIO;
		goto err;
	}

	dev_dbg(dev, "DSP is ready to load firmware %s, status %x", nau8310->dsp_firmware, status);

	dev_dbg(dev, "Request firmware and wait until finish.");
	ret = request_firmware(&fw, nau8310->dsp_firmware, dev);
	if (ret) {
		dev_err(dev, "Failed to load firmware (%d)", ret);
		goto err;
	}

	buf_off = 0;
	buf_len = nau8310->kcs_setup_size = fw->size;
	dev_dbg(dev, "Send DSP command %s (OFF %d, LEN %d)",
		dsp_cmd_table[NAU8310_DSP_CMD_SET_KCS_SETUP], buf_off, buf_len);
	ret = nau8310_dsp_kcs_setup(cp, buf_off, buf_len, fw->data);
	if (ret) {
		dev_err(dev, "Send DSP command %s fail (%d)",
			dsp_cmd_table[NAU8310_DSP_CMD_SET_KCS_SETUP], ret);
		goto err_loaded;
	}

	release_firmware(fw);
	nau8310->load_fw_done = true;

	return 0;

err_loaded:
	if (fw)
		release_firmware(fw);
err:
	nau8310->load_fw_done = false;
	return ret;
}

int nau8310_dsp_init(struct snd_soc_component *cp)
{
	struct regmap *regmap = cp->regmap;

	nau8310_software_reset(regmap);

	/* wait for the power ready */
	msleep(120);

	regmap_update_bits(regmap, NAU8310_R1A_DSP_CORE_CTRL2,
		NAU8310_DSP_RUNSTALL, 0);

	return nau8310_dsp_set_kcs_setup(cp);
}

int nau8310_dsp_setup_controls(struct snd_soc_component *cp)
{
	struct nau8310 *nau8310 = snd_soc_component_get_drvdata(cp);
	struct snd_soc_dapm_context *dapm = nau8310->dapm;
	int ret;

	ret = snd_soc_dapm_new_controls(dapm, nau8310_dsp_dapm_widgets,
		ARRAY_SIZE(nau8310_dsp_dapm_widgets));
	if (ret) {
		dev_err(cp->dev, "Add DSP widget fail (%d)", ret);
		return ret;
	}

	ret = snd_soc_dapm_add_routes(dapm, nau8310_dsp_dapm_routes,
		ARRAY_SIZE(nau8310_dsp_dapm_routes));
	if (ret) {
		dev_err(cp->dev, "Add DSP route fail (%d)", ret);
		return ret;
	}

	return 0;
}
