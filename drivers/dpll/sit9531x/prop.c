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

/*
 * sit9531x_input_pin_label - fill the package label for an input pin
 *
 * Split out so input-naming changes stay local to this helper.
 */
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

/*
 * sit9531x_prop_pin_package_label_set - generate package label
 * @dir:	pin direction
 * @id:		pin index
 *
 * Generates a package label string.  Output pins are named "OUT0",
 * "OUT1", ...  Input pins are named after the physical pair and lane:
 * "IN0P", "IN0N", "IN1P", ... for single-ended lanes, or "IN0",
 * "IN1", ... when the pair is configured differential (the N lane is
 * not registered in that case).
 */
static void
sit9531x_prop_pin_package_label_set(struct sit9531x_dev *sitdev,
				    struct sit9531x_pin_props *props,
				    enum dpll_pin_direction dir, u8 id)
{
	/* The internal INTSYNC pin has a fixed label */
	if (dir == DPLL_PIN_DIRECTION_INPUT &&
	    id == SIT9531X_INTSYNC_PIN_ID) {
		strscpy(props->package_label, "INTSYNC",
			sizeof(props->package_label));
		props->dpll_props.package_label = props->package_label;
		return;
	}

	/* The internal XO reference has a fixed label */
	if (dir == DPLL_PIN_DIRECTION_INPUT && id == SIT9531X_MAX_INPUTS) {
		strscpy(props->package_label, "XO",
			sizeof(props->package_label));
		props->dpll_props.package_label = props->package_label;
		return;
	}

	/* The internal INTSYNC source (output) pin has a fixed label */
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
		snprintf(props->package_label, sizeof(props->package_label),
			 "OUT%u", id);

	props->dpll_props.package_label = props->package_label;
}

/*
 * sit9531x_prop_pin_fwnode_get - find firmware node for a pin
 * @dir:	pin direction
 * @id:		pin index
 *
 * Searches for input-pins/output-pins child nodes in DT, looking
 * for a child whose "reg" property matches @id.
 *
 * Return: 0 on success, -ENOENT if no firmware node exists
 */
static int
sit9531x_prop_pin_fwnode_get(struct sit9531x_dev *sitdev,
			     struct sit9531x_pin_props *props,
			     enum dpll_pin_direction dir, u8 id)
{
	struct fwnode_handle *pins_node, *pin_node;
	const char *node_name;

	if (dir == DPLL_PIN_DIRECTION_INPUT)
		node_name = "input-pins";
	else
		node_name = "output-pins";

	pins_node = device_get_named_child_node(sitdev->dev, node_name);
	if (!pins_node) {
		dev_dbg(sitdev->dev, "'%s' sub-node is missing\n", node_name);
		return -ENOENT;
	}

	/* Enumerate child pin nodes and find the requested one */
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

/*
 * sit9531x_pin_props_get - get pin properties for a given pin
 * @dir:	pin direction (INPUT or OUTPUT)
 * @index:	pin index
 *
 * Allocates a pin properties structure, generates a package label,
 * looks up the firmware node if available, and reads optional
 * properties (label, connection-type, supported-frequencies-hz,
 * esync-control).
 *
 * Call sit9531x_pin_props_put() to free the returned structure.
 *
 * Return: pointer to pin properties on success, error pointer on error
 */
struct sit9531x_pin_props *
sit9531x_pin_props_get(struct sit9531x_dev *sitdev,
		       enum dpll_pin_direction dir, u8 index)
{
	struct dpll_pin_frequency *ranges;
	struct sit9531x_pin_props *props;
	int i, j, num_freqs = 0, rc;
	u64 *freqs = NULL;
	const char *type;
	u32 curr_freq;

	props = kzalloc_obj(*props, GFP_KERNEL);
	if (!props)
		return ERR_PTR(-ENOMEM);

	if (dir == DPLL_PIN_DIRECTION_INPUT &&
	    index == SIT9531X_INTSYNC_PIN_ID) {
		/*
		 * INTSYNC destination pin: a PLL locks to the INTSYNC net as a
		 * reference, so it can be connected and re-prioritised.
		 */
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = 0;
	} else if (dir == DPLL_PIN_DIRECTION_OUTPUT &&
		   index == SIT9531X_INTSYNC_OUT_PIN_ID) {
		/*
		 * INTSYNC source pin: a PLL drives the INTSYNC net.  It can be
		 * connected/disconnected but carries no priority (driving the
		 * net is not a reference selection) and no frequency.
		 */
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = 0;
	} else if (dir == DPLL_PIN_DIRECTION_INPUT &&
		   index == SIT9531X_MAX_INPUTS) {
		/* The XO reference is fixed: no state or priority control. */
		props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		props->dpll_props.capabilities = 0;
		sitdev->ref[index].freq = sitdev->xtal_freq;
		curr_freq = sitdev->xtal_freq;
	} else if (dir == DPLL_PIN_DIRECTION_INPUT) {
		props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = sitdev->ref[index].freq;
	} else {
		/*
		 * A synthesized clock output is an external connection with
		 * no more specific meaning; a board that knows better says
		 * so through the pin's connection-type property below.
		 */
		props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		props->dpll_props.capabilities =
			DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
		curr_freq = sitdev->out[index].freq;

		/*
		 * Allow phase-adjust over a +/-1 ms window.  The subsystem
		 * rejects pin_set(phase-adjust, X) when X falls outside
		 * [min, max], so leaving these at 0 silently blocks every
		 * netlink call.  1 ms is well beyond the DCO dynamic range
		 * but costs nothing.  Only outputs get a range: input pins
		 * have no .phase_adjust_set, and advertising one there would
		 * promise userspace something every set would refuse.
		 */
		props->dpll_props.phase_range.min = -1000000000; /* -1 ms in ps */
		props->dpll_props.phase_range.max =  1000000000; /* +1 ms in ps */
	}

	/* Generate package label */
	sit9531x_prop_pin_package_label_set(sitdev, props, dir, index);

	/*
	 * Both INTSYNC pins are internal to the chip and have no board-level
	 * wiring, so they take no properties from the firmware node.
	 */
	if (dir == DPLL_PIN_DIRECTION_INPUT &&
	    index == SIT9531X_INTSYNC_PIN_ID)
		goto skip_fwnode_props;
	if (dir == DPLL_PIN_DIRECTION_OUTPUT &&
	    index == SIT9531X_INTSYNC_OUT_PIN_ID)
		goto skip_fwnode_props;

	rc = sit9531x_prop_pin_fwnode_get(sitdev, props, dir, index);
	if (rc)
		goto skip_fwnode_props;

	/* Look for "label" property -> board label */
	fwnode_property_read_string(props->fwnode, "label",
				    &props->dpll_props.board_label);

	/* Look for "connection-type" property -> pin type enum */
	if (!fwnode_property_read_string(props->fwnode, "connection-type",
					 &type)) {
		if (!strcmp(type, "ext"))
			props->dpll_props.type = DPLL_PIN_TYPE_EXT;
		else if (!strcmp(type, "gnss"))
			props->dpll_props.type = DPLL_PIN_TYPE_GNSS;
		else if (!strcmp(type, "int") ||
			 !strcmp(type, "int-oscillator"))
			props->dpll_props.type = DPLL_PIN_TYPE_INT_OSCILLATOR;
		else if (!strcmp(type, "synce") ||
			 !strcmp(type, "synce-eth-port"))
			props->dpll_props.type = DPLL_PIN_TYPE_SYNCE_ETH_PORT;
		else if (!strcmp(type, "mux"))
			props->dpll_props.type = DPLL_PIN_TYPE_MUX;
		else
			dev_warn(sitdev->dev,
				 "Unknown pin type '%s'\n", type);
	}

	props->esync_control =
		fwnode_property_read_bool(props->fwnode, "esync-control");

	num_freqs = fwnode_property_count_u64(props->fwnode,
					      "supported-frequencies-hz");
	if (num_freqs <= 0) {
		num_freqs = 0;
		goto skip_fwnode_props;
	}

	freqs = kcalloc(num_freqs, sizeof(*freqs), GFP_KERNEL);
	if (!freqs) {
		rc = -ENOMEM;
		goto err_alloc_freqs;
	}

	fwnode_property_read_u64_array(props->fwnode,
				       "supported-frequencies-hz",
				       freqs, num_freqs);

	/*
	 * Seed the runtime ref->freq / out->freq with the first DT-listed
	 * supported frequency so the netlink frequency_get callback reports
	 * a sane initial value before any pin_set occurs.  DT lists the
	 * physically-wired reference frequency for each input pin and the
	 * default output frequency for each output pin.
	 */
	if (num_freqs > 0) {
		if (dir == DPLL_PIN_DIRECTION_INPUT)
			sitdev->ref[index].freq = (u32)freqs[0];
		else
			sitdev->out[index].freq = (u32)freqs[0];
		curr_freq = (u32)freqs[0];
	}

skip_fwnode_props:
	/* Neither INTSYNC pin carries a frequency attribute */
	if (dir == DPLL_PIN_DIRECTION_INPUT &&
	    index == SIT9531X_INTSYNC_PIN_ID)
		return props;
	if (dir == DPLL_PIN_DIRECTION_OUTPUT &&
	    index == SIT9531X_INTSYNC_OUT_PIN_ID)
		return props;

	/* Allocate frequency ranges list -- DT discrete entries + current
	 * freq + one catch-all wide range so the subsystem never pre-
	 * rejects a frequency_set call.  The chip's real admissible set
	 * is bounded by VCO / divider math in sit9531x_output_freq_set().
	 */
	ranges = kcalloc(num_freqs + 2, sizeof(*ranges), GFP_KERNEL);
	if (!ranges) {
		rc = -ENOMEM;
		goto err_alloc_ranges;
	}

	/* Current freq as first entry */
	ranges[0] = (struct dpll_pin_frequency)DPLL_PIN_FREQUENCY(curr_freq);
	j = 1;

	for (i = 0; i < num_freqs; i++) {
		struct dpll_pin_frequency freq = DPLL_PIN_FREQUENCY(freqs[i]);

		if (freqs[i] == curr_freq)
			continue;
		ranges[j++] = freq;
	}

	/* Always append a wide catch-all range */
	ranges[j].min = 1;
	ranges[j].max = 1000000000ULL; /* 1 GHz */
	j++;

	props->dpll_props.freq_supported = ranges;
	props->dpll_props.freq_supported_num = j;

	kfree(freqs);

	return props;

err_alloc_ranges:
	kfree(freqs);
err_alloc_freqs:
	fwnode_handle_put(props->fwnode);
	kfree(props);

	return ERR_PTR(rc);
}

/*
 * sit9531x_pin_props_put - release pin properties
 * @props:	pin properties to free
 */
void sit9531x_pin_props_put(struct sit9531x_pin_props *props)
{
	kfree(props->dpll_props.freq_supported);

	if (props->fwnode)
		fwnode_handle_put(props->fwnode);

	kfree(props);
}

/*
 * sit9531x_prop_dpll_type_get - get DPLL channel type from firmware
 * @index:	DPLL channel index (0-3)
 *
 * Reads the "dpll-types" string array property from the firmware node
 * and returns the corresponding DPLL type enum.
 *
 * Return: DPLL type for the given channel (default: DPLL_TYPE_PPS)
 */
enum dpll_type
sit9531x_prop_dpll_type_get(struct sit9531x_dev *sitdev, u8 index)
{
	const char *types[SIT9531X_NUM_PLLS];
	int count;

	count = device_property_read_string_array(sitdev->dev, "dpll-types",
						  types, ARRAY_SIZE(types));

	if (index >= count)
		return DPLL_TYPE_PPS;

	if (!strcmp(types[index], "pps"))
		return DPLL_TYPE_PPS;
	else if (!strcmp(types[index], "eec"))
		return DPLL_TYPE_EEC;

	dev_warn(sitdev->dev, "Unknown DPLL type '%s', using default\n",
		 types[index]);

	return DPLL_TYPE_PPS;
}
