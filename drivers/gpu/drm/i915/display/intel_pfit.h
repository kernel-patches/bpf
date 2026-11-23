/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2024 Intel Corporation
 */

#ifndef __INTEL_PFIT_H__
#define __INTEL_PFIT_H__

#include <linux/types.h>

enum drm_mode_status;
struct drm_display_mode;
struct drm_connector_state;
struct intel_crtc_state;
struct intel_display;
enum intel_output_format;

int intel_pfit_compute_config(struct intel_crtc_state *crtc_state,
			      const struct drm_connector_state *conn_state);
void ilk_pfit_enable(const struct intel_crtc_state *crtc_state);
void ilk_pfit_disable(const struct intel_crtc_state *old_crtc_state);
void i9xx_pfit_enable(const struct intel_crtc_state *crtc_state);
void i9xx_pfit_disable(const struct intel_crtc_state *old_crtc_state);
void intel_pfit_get_config(struct intel_crtc_state *crtc_state);
enum drm_mode_status
intel_pfit_mode_valid(struct intel_display *display,
		      const struct drm_display_mode *mode,
		      enum intel_output_format output_format,
		      int num_joined_pipes);
bool i9xx_pfit_is_one_line_mode(const struct intel_crtc_state *crtc_state);
u32 i9xx_pfit_vscale_ratio(struct intel_display *display);

#endif /* __INTEL_PFIT_H__ */
