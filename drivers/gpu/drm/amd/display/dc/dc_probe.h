// SPDX-License-Identifier: MIT
//
// Copyright 2025 Advanced Micro Devices, Inc.

#ifndef _DC_PROBE_H_
#define _DC_PROBE_H_

#include "os_types.h"

/**
 * enum dc_probe_type - What DM wants to probe.
 *
 * Each value names a measurable quantity as an abstraction. DC resolves it to
 * whatever HW measurement block fulfills it. DM never selects the HW block.
 *
 * DC_PROBE_URGENT_ASSERTION_COUNT and DC_PROBE_URGENT_REQUEST_COUNT are
 * measured continuously with DC_PROBE_MEASURING, or as a one shot with
 * DC_PROBE_MEASURED, which can be scoped to one frame or to a window of one
 * stream with DC_PROBE_SCOPE_STREAM. With a window, the urgent assertion count
 * result also carries the HUBP outstanding requests, sampled once after the
 * counter was read so the sample does not disturb the window.
 */
enum dc_probe_type {
	DC_PROBE_PEAK_MEM_BW = 0,
	DC_PROBE_AVG_MEM_BW,
	DC_PROBE_MEM_LATENCY,
	DC_PROBE_URGENT_RAMP_LATENCY,
	DC_PROBE_URGENT_ASSERTION_COUNT,
	DC_PROBE_PREFETCH_DATA_SIZE,
	DC_PROBE_PEAK_MEM_BW_STRESSED, /* peak BW under synthetic memory contention */
	DC_PROBE_URGENT_REQUEST_COUNT,
};

/**
 * enum dc_probe_target_state - Target lifecycle state DM wants DC to reach.
 *
 * DM sets this to describe the final state DC must reach by the end of the
 * commit. DC performs whatever HW transition sequence is needed.
 *
 * @DC_PROBE_NOT_MEASURING: probe inactive, no valid data available.
 * @DC_PROBE_MEASURING:     probe runs continuously. The latest value can be
 *   read back at any time and may differ on each read.
 * @DC_PROBE_MEASURED:      probe performed one shot. The result is latched and
 *   stays valid until DM transitions back to DC_PROBE_NOT_MEASURING.
 */
enum dc_probe_target_state {
	DC_PROBE_NOT_MEASURING = 0,
	DC_PROBE_MEASURING,
	DC_PROBE_MEASURED,
};

/**
 * enum dc_probe_scope_type - What the probe is scoped to.
 * @DC_PROBE_SCOPE_GLOBAL: whole memory subsystem, no stream/plane selector.
 * @DC_PROBE_SCOPE_STREAM: lines of one stream, selected by u.stream of
 *   struct dc_probe_scope.
 *
 * Per-stream/plane scoping must select targets by stable id, not object
 * pointer — dc_state copy semantics would dangle a raw pointer when the
 * absolute-set commit removes or replaces the target.
 */
enum dc_probe_scope_type {
	DC_PROBE_SCOPE_GLOBAL = 0,
	DC_PROBE_SCOPE_STREAM,
};

/**
 * struct dc_probe_scope - Selects what a probe measures against.
 * @type: scope kind. It selects which member of @u is valid.
 * @u.stream.stream_id:  stream_id of the stream to measure. A probe on a stream
 *   that is not in the committed state has nothing to measure, and its status
 *   is not valid.
 * @u.stream.start_line: first line of the window, as an OTG vertical position
 *   of the stream (0-based, wraps at v_total). Zero starts the window at vblank
 *   start. Otherwise keep it in [1, v_total - 1].
 * @u.stream.end_line:   last line of the window. A window may cross the v_total
 *   wrap. Arming the counter takes a few lines. A window the position has
 *   already left when the counter is armed is missed, and its status is not
 *   valid, so a window needs to be longer than the arm latency.
 *
 * The lines and the target state select what is measured:
 *
 * - start_line and end_line both zero is no window. DC_PROBE_MEASURING measures
 *   continuously, and DC_PROBE_MEASURED measures one whole frame.
 * - A nonzero end_line is a window from start_line to end_line.
 *   DC_PROBE_MEASURED measures the next window once, and then stops.
 *   DC_PROBE_MEASURING is not valid for a window, because a continuous
 *   measurement cannot be limited to one. A counter only stops when it is
 *   reset.
 * - A nonzero start_line with a zero end_line is not valid.
 */
struct dc_probe_scope {
	enum dc_probe_scope_type type;
	union {
		struct {
			uint32_t stream_id;
			uint32_t start_line;
			uint32_t end_line;
		} stream;
	} u;
};

/**
 * dc_probe_scope_is_windowed() - Whether a scope selects lines of a stream.
 * @scope: scope to check
 *
 * Return: true if start_line or end_line of a stream scope is set
 */
static inline bool dc_probe_scope_is_windowed(const struct dc_probe_scope *scope)
{
	return scope->type == DC_PROBE_SCOPE_STREAM
			&& (scope->u.stream.start_line || scope->u.stream.end_line);
}

/**
 * struct dc_probe_state - DM-authored descriptor of a single probe.
 *
 * A plain inline value with copy semantics: no allocation, no refcount. DC
 * resolves each descriptor to a HW measurement instance and diffs the desired
 * set against the committed set to plan the transition.
 *
 * @type:         what to measure.
 * @target_state: desired lifecycle state for this probe.
 * @scope:        what the probe is scoped to.
 */
struct dc_probe_state {
	enum dc_probe_type         type;
	enum dc_probe_target_state target_state;
	struct dc_probe_scope      scope;
};

#define MAX_PROBES 1

/**
 * struct dc_probe_updates - Absolute set of probes DM wants active.
 *
 * Mirrors the plane/stream absolute-set model: the array is the complete
 * desired set. DC compares it against the committed set to add, remove, or
 * transition probes.
 *
 * @probes:      desired probe descriptors.
 * @probe_count: number of valid entries in @probes.
 */
struct dc_probe_updates {
	struct dc_probe_state probes[MAX_PROBES];
	int                   probe_count;
};

#endif /* _DC_PROBE_H_ */
