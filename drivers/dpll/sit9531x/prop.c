// SPDX-License-Identifier: GPL-2.0
/*
 * SiTime SiT9531x firmware node property parsing
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 *
 * Retrieves pin properties from Device Tree firmware nodes (or
 * applies defaults when no firmware node exists).
 */

#include <linux/dev_printk.h>
#include <linux/dpll.h>
#include <linux/err.h>
#include <linux/fwnode.h>
#include <linux/property.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "core.h"
#include "prop.h"

static void sit9531x_input_pin_label(struct sit9531x_dev *sitdev,
				     struct sit9531x_pin_props *props, u8 id)
{
	u8 pair = sit9531x_input_pair(id);

	if (sitdev->ref[id].sig_mode == SIT9531X_MODE_DE)
		snprintf(props->package_label,
			 sizeof(props->package_label), "IN%u", pair);
	else
		snprintf(props->package_label,
			 sizeof(props->package_label), "IN%u%c", pair,
			 sit9531x_input_is_n(id) ? 'N' : 'P');
}

/* A differential input pair is labeled IN<n>; its N lane is not registered. */
static void
sit9531x_prop_pin_package_label_set(struct sit9531x_dev *sitdev,
				    struct sit9531x_pin_props *props,
				    enum dpll_pin_direction dir, u8 id)
{
	if (dir == DPLL_PIN_DIRECTION_INPUT &&
	    id == SIT9531X_INTSYNC_PIN_ID) {
		strscpy(props->package_label, "INTSYNC",
			sizeof(props->package_label));
		props->dpll_props.package_label = props->package_label;
		return;
	}

	if (dir == DPLL_PIN_DIRECTION_INPUT && id == SIT9531X_MAX_INPUTS) {
		strscpy(props->package_label, "XO",
			sizeof(props->package_label));
		props->dpll_props.package_label = props->package_label;
		return;
	}

	if (dir == DPLL_PIN_DIRECTION_OUTPUT &&
	    id == SIT9531X_INTSYNC_OUT_PIN_ID) {
		strscpy(props->package_label, "SYNCOUT",
			sizeof(props->package_label));
		props->dpll_props.package_label = props->package_label;
		return;
	}

	if (dir == DPLL_PIN_DIRECTION_INPUT)
		sit9531x_input_pin_label(sitdev, props, id);
	else
		/*
		 * Package numbering; on the SiT95317 it differs from the chip
		 * slot that the registers and the binding's reg use.
		 */
		snprintf(props->package_label, sizeof(props->package_label),
			 "OUT%u", id);

	props->dpll_props.package_label = props->package_label;
}

/* An output's reg is the chip slot it drives, not the driver's index. */
static int
sit9531x_prop_pin_fwnode_get(struct sit9531x_dev *sitdev,
			     struct sit9531x_pin_props *props,
			     enum dpll_pin_direction dir, u8 id)
{
	struct fwnode_handle *pins_node, *pin_node;
	const char *node_name;

	if (dir == DPLL_PIN_DIRECTION_INPUT) {
		node_name = "input-pins";
	} else {
		node_name = "output-pins";
		if (id < sitdev->info->num_outputs)
			id = sitdev->info->clkout_map[id];
	}

	pins_node = device_get_named_child_node(sitdev->dev, node_name);
	if (!pins_node) {
		dev_dbg(sitdev->dev, "'%s' sub-node is missing\n", node_name);
		return -ENOENT;
	}

	fwnode_for_each_child_node(pins_node, pin_node) {
		u32 reg;

		if (fwnode_property_read_u32(pin_node, "reg", &reg))
			continue;

		if (id == reg)
			break;
	}

	fwnode_handle_put(pins_node);

	props->fwnode = pin_node;

	dev_dbg(sitdev->dev, "Firmware node for %s %sfound\n",
		props->package_label, pin_node ? "" : "NOT ");

	return pin_node ? 0 : -ENOENT;
}

/* Free the result with sit9531x_pin_props_put(). */
struct sit9531x_pin_props *
sit9531x_pin_props_get(struct sit9531x_dev *sitdev,
		       enum dpll_pin_direction dir, u8 index)
{
	bool sync_in = dir == DPLL_PIN_DIRECTION_INPUT &&
		       index == SIT9531X_INTSYNC_PIN_ID;
	bool sync_out = dir == DPLL_PIN_DIRECTION_OUTPUT &&
			index == SIT9531X_INTSYNC_OUT_PIN_ID;
	bool xo = dir == DPLL_PIN_DIRECTION_INPUT &&
		  index == SIT9531X_MAX_INPUTS;
	struct dpll_pin_frequency *ranges;
	struct sit9531x_pin_props *props;
	int i, j, num_freqs = 0, rc;
	u32 *freqs = NULL;
	const char *type;
	u64 curr_freq;

	props = kzalloc_obj(*props, GFP_KERNEL);
	if (!props)
		return ERR_PTR(-ENOMEM);

	if (sync_in) {
		/* INTSYNC destination: a reference the PLL can lock to. */
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = 0;
	} else if (sync_out) {
		/* INTSYNC source: driving it is not a reference selection */
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = 0;
	} else if (xo) {
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities = 0;
		curr_freq = sitdev->xtal_freq;
	} else if (dir == DPLL_PIN_DIRECTION_INPUT) {
		props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = sitdev->ref[index].freq;
	} else {
		props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = 0;
	}

	sit9531x_prop_pin_package_label_set(sitdev, props, dir, index);

	/* Internal pins take no properties from the firmware node. */
	if (sync_in || sync_out || xo)
		goto skip_fwnode_props;

	rc = sit9531x_prop_pin_fwnode_get(sitdev, props, dir, index);
	if (rc)
		goto skip_fwnode_props;

	fwnode_property_read_string(props->fwnode, "label",
				    &props->dpll_props.board_label);

	if (!fwnode_property_read_string(props->fwnode, "connection-type",
					 &type)) {
		if (!strcmp(type, "ext"))
			props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		else if (!strcmp(type, "gnss"))
			props->dpll_props.type = DPLL_PIN_TYPE_GNSS;
		else if (!strcmp(type, "int"))
			props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		else if (!strcmp(type, "synce"))
			props->dpll_props.type = DPLL_PIN_TYPE_SYNCE_ETH_PORT;
		else if (!strcmp(type, "mux"))
			props->dpll_props.type = DPLL_PIN_TYPE_MUX;
		else
			dev_warn(sitdev->dev,
				 "Unknown pin type '%s'\n", type);
	}

	if (!fwnode_property_present(props->fwnode,
				     "supported-frequencies-hz"))
		goto skip_fwnode_props;

	/* A -hz property is 32-bit; no rate of this part needs more. */
	num_freqs = fwnode_property_count_u32(props->fwnode,
					      "supported-frequencies-hz");
	if (num_freqs <= 0) {
		rc = num_freqs ? num_freqs : -EINVAL;
		dev_err(sitdev->dev,
			"malformed supported-frequencies-hz for %s: %d\n",
			props->package_label, rc);
		goto err_alloc_freqs;
	}

	freqs = kcalloc(num_freqs, sizeof(*freqs), GFP_KERNEL);
	if (!freqs) {
		rc = -ENOMEM;
		goto err_alloc_freqs;
	}

	rc = fwnode_property_read_u32_array(props->fwnode,
					    "supported-frequencies-hz",
					    freqs, num_freqs);
	if (rc) {
		dev_warn(sitdev->dev,
			 "failed to parse supported-frequencies-hz for %s: %d\n",
			 props->package_label, rc);
		goto err_alloc_ranges;
	}

	/* The first listed rate seeds the input's rate */
	if (num_freqs > 0 && dir == DPLL_PIN_DIRECTION_INPUT && !xo)
		curr_freq = freqs[0];

skip_fwnode_props:
	if (sync_in || sync_out)
		return props;

	/*
	 * An output with no listed rates gets one wide range, as the setter
	 * checks Fvco/N; the XO gets its one rate.
	 */
	ranges = kcalloc(num_freqs + 1, sizeof(*ranges), GFP_KERNEL);
	if (!ranges) {
		rc = -ENOMEM;
		goto err_alloc_ranges;
	}

	/* Set after the last allocation that can fail */
	if (curr_freq && dir == DPLL_PIN_DIRECTION_INPUT)
		sitdev->ref[index].freq = curr_freq;

	j = 0;

	for (i = 0; i < num_freqs; i++) {
		struct dpll_pin_frequency freq = DPLL_PIN_FREQUENCY(freqs[i]);

		ranges[j++] = freq;
	}

	if (!num_freqs && dir == DPLL_PIN_DIRECTION_OUTPUT) {
		ranges[j].min = 1;
		ranges[j].max = 1000000000ULL; /* 1 GHz */
		j++;
	} else if (!num_freqs && curr_freq) {
		struct dpll_pin_frequency f = DPLL_PIN_FREQUENCY(curr_freq);

		ranges[j++] = f;
	}

	if (j > 0) {
		props->dpll_props.freq_supported = ranges;
		props->dpll_props.freq_supported_num = j;
	} else {
		kfree(ranges);
		props->dpll_props.freq_supported = NULL;
		props->dpll_props.freq_supported_num = 0;
	}

	kfree(freqs);

	return props;

err_alloc_ranges:
	kfree(freqs);
err_alloc_freqs:
	fwnode_handle_put(props->fwnode);
	kfree(props);

	return ERR_PTR(rc);
}

void sit9531x_pin_props_put(struct sit9531x_pin_props *props)
{
	kfree(props->dpll_props.freq_supported);

	if (props->fwnode)
		fwnode_handle_put(props->fwnode);

	kfree(props);
}

enum dpll_type
sit9531x_prop_dpll_type_get(struct sit9531x_dev *sitdev, u8 index)
{
	const char *types[SIT9531X_NUM_PLLS];
	int count;

	count = device_property_read_string_array(sitdev->dev, "dpll-types",
						  types, ARRAY_SIZE(types));

	if (index >= count || !types[index])
		return DPLL_TYPE_PPS;

	if (!strcmp(types[index], "pps"))
		return DPLL_TYPE_PPS;
	else if (!strcmp(types[index], "eec"))
		return DPLL_TYPE_EEC;

	dev_warn(sitdev->dev, "Unknown DPLL type '%s', using default\n",
		 types[index]);

	return DPLL_TYPE_PPS;
}
