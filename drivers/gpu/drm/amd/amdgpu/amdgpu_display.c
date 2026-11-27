/*
 * Copyright 2007-8 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 */

#include <drm/amdgpu_drm.h>
#include "amdgpu.h"
#include "amdgpu_i2c.h"
#include "atom.h"
#include "amdgpu_display.h"
#include "soc15_common.h"
#include "gc/gc_11_0_0_offset.h"
#include "gc/gc_11_0_0_sh_mask.h"
#include "bif/bif_4_1_d.h"
#include <asm/div64.h>

#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <drm/clients/drm_fbdev_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_edid.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_modeset_helper.h>
#include <drm/drm_vblank.h>

static int amdgpu_display_framebuffer_init(struct drm_device *dev,
					   struct amdgpu_framebuffer *rfb,
					   const struct drm_mode_fb_cmd2 *mode_cmd,
					   struct drm_gem_object *obj);

static int amdgpu_dirtyfb(struct drm_framebuffer *fb, struct drm_file *file,
			  unsigned int flags, unsigned int color,
			  struct drm_clip_rect *clips, unsigned int num_clips)
{

	if (file)
		return -ENOSYS;

	return drm_atomic_helper_dirtyfb(fb, file, flags, color, clips,
					 num_clips);
}

static const struct drm_framebuffer_funcs amdgpu_fb_funcs = {
	.destroy = drm_gem_fb_destroy,
	.create_handle = drm_gem_fb_create_handle,
};

static const struct drm_framebuffer_funcs amdgpu_fb_funcs_atomic = {
	.destroy = drm_gem_fb_destroy,
	.create_handle = drm_gem_fb_create_handle,
	.dirty = amdgpu_dirtyfb
};

uint32_t amdgpu_display_supported_domains(struct amdgpu_device *adev,
					  uint64_t bo_flags)
{
	uint32_t domain = AMDGPU_GEM_DOMAIN_VRAM;

#if defined(CONFIG_DRM_AMD_DC)
	/*
	 * if amdgpu_bo_support_uswc returns false it means that USWC mappings
	 * is not supported for this board. But this mapping is required
	 * to avoid hang caused by placement of scanout BO in GTT on certain
	 * APUs. So force the BO placement to VRAM in case this architecture
	 * will not allow USWC mappings.
	 * Also, don't allow GTT domain if the BO doesn't have USWC flag set.
	 */
	if ((bo_flags & AMDGPU_GEM_CREATE_CPU_GTT_USWC) &&
	    amdgpu_bo_support_uswc(bo_flags) &&
	    adev->dc_enabled &&
	    adev->mode_info.gpu_vm_support)
		domain |= AMDGPU_GEM_DOMAIN_GTT;
#endif

	return domain;
}

static const struct drm_format_info dcc_formats[] = {
	{ .format = DRM_FORMAT_XRGB8888, .depth = 24, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	 { .format = DRM_FORMAT_XBGR8888, .depth = 24, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_ARGB8888, .depth = 32, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	   .has_alpha = true, },
	{ .format = DRM_FORMAT_ABGR8888, .depth = 32, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_BGRA8888, .depth = 32, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_XRGB2101010, .depth = 30, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_XBGR2101010, .depth = 30, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_ARGB2101010, .depth = 30, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_ABGR2101010, .depth = 30, .num_planes = 2,
	  .cpp = { 4, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_RGB565, .depth = 16, .num_planes = 2,
	  .cpp = { 2, 0, }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
};

static const struct drm_format_info dcc_retile_formats[] = {
	{ .format = DRM_FORMAT_XRGB8888, .depth = 24, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	 { .format = DRM_FORMAT_XBGR8888, .depth = 24, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_ARGB8888, .depth = 32, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	   .has_alpha = true, },
	{ .format = DRM_FORMAT_ABGR8888, .depth = 32, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_BGRA8888, .depth = 32, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_XRGB2101010, .depth = 30, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_XBGR2101010, .depth = 30, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
	{ .format = DRM_FORMAT_ARGB2101010, .depth = 30, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_ABGR2101010, .depth = 30, .num_planes = 3,
	  .cpp = { 4, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1,
	  .has_alpha = true, },
	{ .format = DRM_FORMAT_RGB565, .depth = 16, .num_planes = 3,
	  .cpp = { 2, 0, 0 }, .block_w = {1, 1, 1}, .block_h = {1, 1, 1}, .hsub = 1, .vsub = 1, },
};

static const struct drm_format_info *
lookup_format_info(const struct drm_format_info formats[],
		  int num_formats, u32 format)
{
	int i;

	for (i = 0; i < num_formats; i++) {
		if (formats[i].format == format)
			return &formats[i];
	}

	return NULL;
}

const struct drm_format_info *
amdgpu_lookup_format_info(u32 format, uint64_t modifier)
{
	if (!IS_AMD_FMT_MOD(modifier))
		return NULL;

	if (AMD_FMT_MOD_GET(TILE_VERSION, modifier) < AMD_FMT_MOD_TILE_VER_GFX9 ||
	    AMD_FMT_MOD_GET(TILE_VERSION, modifier) >= AMD_FMT_MOD_TILE_VER_GFX12)
		return NULL;

	if (AMD_FMT_MOD_GET(DCC_RETILE, modifier))
		return lookup_format_info(dcc_retile_formats,
					  ARRAY_SIZE(dcc_retile_formats),
					  format);

	if (AMD_FMT_MOD_GET(DCC, modifier))
		return lookup_format_info(dcc_formats, ARRAY_SIZE(dcc_formats),
					  format);

	/* returning NULL will cause the default format structs to be used. */
	return NULL;
}


/*
 * Tries to extract the renderable DCC offset from the opaque metadata attached
 * to the buffer.
 */
static int
extract_render_dcc_offset(struct amdgpu_device *adev,
			  struct drm_gem_object *obj,
			  uint64_t *offset)
{
	struct amdgpu_bo *rbo;
	int r = 0;
	uint32_t metadata[10]; /* Something that fits a descriptor + header. */
	uint32_t size;

	rbo = gem_to_amdgpu_bo(obj);
	r = amdgpu_bo_reserve(rbo, false);

	if (unlikely(r)) {
		/* Don't show error message when returning -ERESTARTSYS */
		if (r != -ERESTARTSYS)
			DRM_ERROR("Unable to reserve buffer: %d\n", r);
		return r;
	}

	r = amdgpu_bo_get_metadata(rbo, metadata, sizeof(metadata), &size, NULL);
	amdgpu_bo_unreserve(rbo);

	if (r)
		return r;

	/*
	 * The first word is the metadata version, and we need space for at least
	 * the version + pci vendor+device id + 8 words for a descriptor.
	 */
	if (size < 40  || metadata[0] != 1)
		return -EINVAL;

	if (adev->family >= AMDGPU_FAMILY_NV) {
		/* resource word 6/7 META_DATA_ADDRESS{_LO} */
		*offset = ((u64)metadata[9] << 16u) |
			  ((metadata[8] & 0xFF000000u) >> 16);
	} else {
		/* resource word 5/7 META_DATA_ADDRESS */
		*offset = ((u64)metadata[9] << 8u) |
			  ((u64)(metadata[7] & 0x1FE0000u) << 23);
	}

	return 0;
}

static int convert_tiling_flags_to_modifier_gfx12(struct amdgpu_framebuffer *afb)
{
	u64 modifier = 0;
	int swizzle_mode = AMDGPU_TILING_GET(afb->tiling_flags, GFX12_SWIZZLE_MODE);

	if (!swizzle_mode) {
		modifier = DRM_FORMAT_MOD_LINEAR;
	} else {
		int max_comp_block =
			AMDGPU_TILING_GET(afb->tiling_flags, GFX12_DCC_MAX_COMPRESSED_BLOCK);

		modifier =
			AMD_FMT_MOD |
			AMD_FMT_MOD_SET(TILE_VERSION, AMD_FMT_MOD_TILE_VER_GFX12) |
			AMD_FMT_MOD_SET(TILE, swizzle_mode) |
			AMD_FMT_MOD_SET(DCC, afb->gfx12_dcc) |
			AMD_FMT_MOD_SET(DCC_MAX_COMPRESSED_BLOCK, max_comp_block);
	}

	afb->base.modifier = modifier;
	afb->base.flags |= DRM_MODE_FB_MODIFIERS;
	return 0;
}

static int convert_tiling_flags_to_modifier_gfx9(struct amdgpu_framebuffer *afb)
{
	struct amdgpu_device *adev = drm_to_adev(afb->base.dev);
	uint64_t modifier = 0;
	int num_pipes = 0;
	int num_pkrs = 0;

	num_pkrs = adev->gfx.config.gb_addr_config_fields.num_pkrs;
	num_pipes = adev->gfx.config.gb_addr_config_fields.num_pipes;

	if (!afb->tiling_flags || !AMDGPU_TILING_GET(afb->tiling_flags, SWIZZLE_MODE)) {
		modifier = DRM_FORMAT_MOD_LINEAR;
	} else {
		int swizzle = AMDGPU_TILING_GET(afb->tiling_flags, SWIZZLE_MODE);
		bool has_xor = swizzle >= 16;
		int block_size_bits;
		int version;
		int pipe_xor_bits = 0;
		int bank_xor_bits = 0;
		int packers = 0;
		int rb = 0;
		int pipes = ilog2(num_pipes);
		uint32_t dcc_offset = AMDGPU_TILING_GET(afb->tiling_flags, DCC_OFFSET_256B);

		switch (swizzle >> 2) {
		case 0: /* 256B */
			block_size_bits = 8;
			break;
		case 1: /* 4KiB */
		case 5: /* 4KiB _X */
			block_size_bits = 12;
			break;
		case 2: /* 64KiB */
		case 4: /* 64 KiB _T */
		case 6: /* 64 KiB _X */
			block_size_bits = 16;
			break;
		case 7: /* 256 KiB */
			block_size_bits = 18;
			break;
		default:
			/* RESERVED or VAR */
			return -EINVAL;
		}

		if (amdgpu_ip_version(adev, GC_HWIP, 0) >= IP_VERSION(11, 0, 0))
			version = AMD_FMT_MOD_TILE_VER_GFX11;
		else if (amdgpu_ip_version(adev, GC_HWIP, 0) >=
			 IP_VERSION(10, 3, 0))
			version = AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS;
		else if (amdgpu_ip_version(adev, GC_HWIP, 0) >=
			 IP_VERSION(10, 0, 0))
			version = AMD_FMT_MOD_TILE_VER_GFX10;
		else
			version = AMD_FMT_MOD_TILE_VER_GFX9;

		switch (swizzle & 3) {
		case 0: /* Z microtiling */
			return -EINVAL;
		case 1: /* S microtiling */
			if (amdgpu_ip_version(adev, GC_HWIP, 0) <
			    IP_VERSION(11, 0, 0)) {
				if (!has_xor)
					version = AMD_FMT_MOD_TILE_VER_GFX9;
			}
			break;
		case 2:
			if (amdgpu_ip_version(adev, GC_HWIP, 0) <
			    IP_VERSION(11, 0, 0)) {
				if (!has_xor && afb->base.format->cpp[0] != 4)
					version = AMD_FMT_MOD_TILE_VER_GFX9;
			}
			break;
		case 3:
			break;
		}

		if (has_xor) {
			if (num_pipes == num_pkrs && num_pkrs == 0) {
				DRM_ERROR("invalid number of pipes and packers\n");
				return -EINVAL;
			}

			switch (version) {
			case AMD_FMT_MOD_TILE_VER_GFX11:
				pipe_xor_bits = min(block_size_bits - 8, pipes);
				packers = ilog2(adev->gfx.config.gb_addr_config_fields.num_pkrs);
				break;
			case AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS:
				pipe_xor_bits = min(block_size_bits - 8, pipes);
				packers = min(block_size_bits - 8 - pipe_xor_bits,
					      ilog2(adev->gfx.config.gb_addr_config_fields.num_pkrs));
				break;
			case AMD_FMT_MOD_TILE_VER_GFX10:
				pipe_xor_bits = min(block_size_bits - 8, pipes);
				break;
			case AMD_FMT_MOD_TILE_VER_GFX9:
				rb = ilog2(adev->gfx.config.gb_addr_config_fields.num_se) +
				     ilog2(adev->gfx.config.gb_addr_config_fields.num_rb_per_se);
				pipe_xor_bits = min(block_size_bits - 8, pipes +
						    ilog2(adev->gfx.config.gb_addr_config_fields.num_se));
				bank_xor_bits = min(block_size_bits - 8 - pipe_xor_bits,
						    ilog2(adev->gfx.config.gb_addr_config_fields.num_banks));
				break;
			}
		}

		modifier = AMD_FMT_MOD |
			   AMD_FMT_MOD_SET(TILE, AMDGPU_TILING_GET(afb->tiling_flags, SWIZZLE_MODE)) |
			   AMD_FMT_MOD_SET(TILE_VERSION, version) |
			   AMD_FMT_MOD_SET(PIPE_XOR_BITS, pipe_xor_bits) |
			   AMD_FMT_MOD_SET(BANK_XOR_BITS, bank_xor_bits) |
			   AMD_FMT_MOD_SET(PACKERS, packers);

		if (dcc_offset != 0) {
			bool dcc_i64b = AMDGPU_TILING_GET(afb->tiling_flags, DCC_INDEPENDENT_64B) != 0;
			bool dcc_i128b = version >= AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS;
			const struct drm_format_info *format_info;
			u64 render_dcc_offset;

			/* Enable constant encode on RAVEN2 and later. */
			bool dcc_constant_encode =
				(adev->asic_type > CHIP_RAVEN ||
				 (adev->asic_type == CHIP_RAVEN &&
				  adev->external_rev_id >= 0x81)) &&
				amdgpu_ip_version(adev, GC_HWIP, 0) <
					IP_VERSION(11, 0, 0);

			int max_cblock_size = dcc_i64b ? AMD_FMT_MOD_DCC_BLOCK_64B :
					      dcc_i128b ? AMD_FMT_MOD_DCC_BLOCK_128B :
					      AMD_FMT_MOD_DCC_BLOCK_256B;

			modifier |= AMD_FMT_MOD_SET(DCC, 1) |
				    AMD_FMT_MOD_SET(DCC_CONSTANT_ENCODE, dcc_constant_encode) |
				    AMD_FMT_MOD_SET(DCC_INDEPENDENT_64B, dcc_i64b) |
				    AMD_FMT_MOD_SET(DCC_INDEPENDENT_128B, dcc_i128b) |
				    AMD_FMT_MOD_SET(DCC_MAX_COMPRESSED_BLOCK, max_cblock_size);

			afb->base.offsets[1] = dcc_offset * 256 + afb->base.offsets[0];
			afb->base.pitches[1] =
				AMDGPU_TILING_GET(afb->tiling_flags, DCC_PITCH_MAX) + 1;

			/*
			 * If the userspace driver uses retiling the tiling flags do not contain
			 * info on the renderable DCC buffer. Luckily the opaque metadata contains
			 * the info so we can try to extract it. The kernel does not use this info
			 * but we should convert it to a modifier plane for getfb2, so the
			 * userspace driver that gets it doesn't have to juggle around another DCC
			 * plane internally.
			 */
			if (extract_render_dcc_offset(adev, afb->base.obj[0],
						      &render_dcc_offset) == 0 &&
			    render_dcc_offset != 0 &&
			    render_dcc_offset != afb->base.offsets[1] &&
			    render_dcc_offset < UINT_MAX) {
				uint32_t dcc_block_bits;  /* of base surface data */

				modifier |= AMD_FMT_MOD_SET(DCC_RETILE, 1);
				afb->base.offsets[2] = render_dcc_offset;

				if (adev->family >= AMDGPU_FAMILY_NV) {
					int extra_pipe = 0;

					if ((amdgpu_ip_version(adev, GC_HWIP,
							       0) >=
					     IP_VERSION(10, 3, 0)) &&
					    pipes == packers && pipes > 1)
						extra_pipe = 1;

					dcc_block_bits = max(20, 16 + pipes + extra_pipe);
				} else {
					modifier |= AMD_FMT_MOD_SET(RB, rb) |
						    AMD_FMT_MOD_SET(PIPE, pipes);
					dcc_block_bits = max(20, 18 + rb);
				}

				dcc_block_bits -= ilog2(afb->base.format->cpp[0]);
				afb->base.pitches[2] = ALIGN(afb->base.width,
							     1u << ((dcc_block_bits + 1) / 2));
			}
			format_info = amdgpu_lookup_format_info(afb->base.format->format,
								modifier);
			if (!format_info)
				return -EINVAL;

			afb->base.format = format_info;
		}
	}

	afb->base.modifier = modifier;
	afb->base.flags |= DRM_MODE_FB_MODIFIERS;
	return 0;
}

static int convert_tiling_flags_to_modifier_gfx6(struct amdgpu_framebuffer *afb)
{
	const uint32_t array_mode = AMDGPU_TILING_GET(afb->tiling_flags, ARRAY_MODE);
	const uint32_t pipe_config = AMDGPU_TILING_GET(afb->tiling_flags, PIPE_CONFIG);
	const uint32_t tile_split = AMDGPU_TILING_GET(afb->tiling_flags, TILE_SPLIT);
	const uint32_t micro_tile_mode = AMDGPU_TILING_GET(afb->tiling_flags, MICRO_TILE_MODE);
	const uint32_t bank_width = AMDGPU_TILING_GET(afb->tiling_flags, BANK_WIDTH);
	const uint32_t bank_height = AMDGPU_TILING_GET(afb->tiling_flags, BANK_HEIGHT);
	const uint32_t macro_tile_aspect = AMDGPU_TILING_GET(afb->tiling_flags, MACRO_TILE_ASPECT);
	const uint32_t num_banks = AMDGPU_TILING_GET(afb->tiling_flags, NUM_BANKS);
	struct amdgpu_device *adev = drm_to_adev(afb->base.dev);
	uint64_t modifier = 0;

	switch (array_mode) {
	case DC_ARRAY_LINEAR_GENERAL:
	case DC_ARRAY_LINEAR_ALLIGNED:
		modifier = DRM_FORMAT_MOD_LINEAR;
		break;

	case DC_ARRAY_2D_TILED_THIN1:
		/* Macro tiled modes only */
		modifier |=
			AMD_FMT_MOD_SET(PIPE_CONFIG, pipe_config) |
			AMD_FMT_MOD_SET(TILE_SPLIT, tile_split) |
			AMD_FMT_MOD_SET(BANK_WIDTH, bank_width) |
			AMD_FMT_MOD_SET(BANK_HEIGHT, bank_height) |
			AMD_FMT_MOD_SET(MACRO_TILE_ASPECT, macro_tile_aspect) |
			AMD_FMT_MOD_SET(NUM_BANKS, num_banks);
		fallthrough;

	case DC_ARRAY_1D_TILED_THIN1:
		/* Micro and macro tiled modes */
		modifier |=
			AMD_FMT_MOD |
			AMD_FMT_MOD_SET(TILE_VERSION, AMD_FMT_MOD_TILE_VER_GFX6) |
			AMD_FMT_MOD_SET(TILE, array_mode) |
			AMD_FMT_MOD_SET(MICROTILE, micro_tile_mode);
		break;

	default:
		drm_dbg_kms(&adev->ddev, "array mode 0x%x not supported\n", array_mode);
		return -EINVAL;
	}

	afb->base.modifier = modifier;
	afb->base.flags |= DRM_MODE_FB_MODIFIERS;
	return 0;
}

static int check_tiling_flags_gfx6(struct amdgpu_framebuffer *afb)
{
	const u64 array_mode = AMDGPU_TILING_GET(afb->tiling_flags, ARRAY_MODE);
	const u64 micro_tile_mode = AMDGPU_TILING_GET(afb->tiling_flags, MICRO_TILE_MODE);

	/* LINEAR_GENERAL, LINEAR_ALIGNED */
	if (array_mode == 0 || array_mode == 1)
		return 0;

	/* 1D_TILED_THIN1, 2D_TILED_THIN1 */
	if (array_mode != 2 && array_mode != 4) {
		drm_dbg_kms(afb->base.dev,
			    "Array mode %llu not supported for scanout\n",
			    array_mode);
		return -EINVAL;
	}

	/*
	 * For now, only allow DISPLAY micro tile mode.
	 * THIN, DEPTH and THICK modes are not displayable.
	 * ROTATED has never been supported by Linux or Mesa.
	 */
	if (micro_tile_mode != 0) {
		drm_dbg_kms(afb->base.dev,
			    "Micro tile mode %llu not supported for scanout\n",
			    micro_tile_mode);
		return -EINVAL;
	}

	return 0;
}

static void get_block_dimensions(unsigned int block_log2, unsigned int cpp,
				 unsigned int *width, unsigned int *height)
{
	unsigned int cpp_log2 = ilog2(cpp);
	unsigned int pixel_log2 = block_log2 - cpp_log2;
	unsigned int width_log2 = (pixel_log2 + 1) / 2;
	unsigned int height_log2 = pixel_log2 - width_log2;

	*width = 1 << width_log2;
	*height = 1 << height_log2;
}

static unsigned int get_dcc_block_size(uint64_t modifier, bool rb_aligned,
				       bool pipe_aligned)
{
	unsigned int ver = AMD_FMT_MOD_GET(TILE_VERSION, modifier);

	switch (ver) {
	case AMD_FMT_MOD_TILE_VER_GFX9: {
		/*
		 * TODO: for pipe aligned we may need to check the alignment of the
		 * total size of the surface, which may need to be bigger than the
		 * natural alignment due to some HW workarounds
		 */
		return max(10 + (rb_aligned ? (int)AMD_FMT_MOD_GET(RB, modifier) : 0), 12);
	}
	case AMD_FMT_MOD_TILE_VER_GFX10:
	case AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS:
	case AMD_FMT_MOD_TILE_VER_GFX11: {
		int pipes_log2 = AMD_FMT_MOD_GET(PIPE_XOR_BITS, modifier);

		if (ver >= AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS && pipes_log2 > 1 &&
		    AMD_FMT_MOD_GET(PACKERS, modifier) == pipes_log2)
			++pipes_log2;

		return max(8 + (pipe_aligned ? pipes_log2 : 0), 12);
	}
	default:
		return 0;
	}
}

static int amdgpu_display_verify_plane(struct amdgpu_framebuffer *rfb, int plane,
				       const struct drm_format_info *format,
				       unsigned int block_width, unsigned int block_height,
				       unsigned int block_size_log2)
{
	unsigned int width = rfb->base.width /
		((plane && plane < format->num_planes) ? format->hsub : 1);
	unsigned int height = rfb->base.height /
		((plane && plane < format->num_planes) ? format->vsub : 1);
	unsigned int cpp = plane < format->num_planes ? format->cpp[plane] : 1;
	unsigned int block_pitch = block_width * cpp;
	unsigned int min_pitch = ALIGN(width * cpp, block_pitch);
	unsigned int block_size = 1 << block_size_log2;
	uint64_t size;

	if (rfb->base.pitches[plane] % block_pitch) {
		drm_dbg_kms(rfb->base.dev,
			    "pitch %d for plane %d is not a multiple of block pitch %d\n",
			    rfb->base.pitches[plane], plane, block_pitch);
		return -EINVAL;
	}
	if (rfb->base.pitches[plane] < min_pitch) {
		drm_dbg_kms(rfb->base.dev,
			    "pitch %d for plane %d is less than minimum pitch %d\n",
			    rfb->base.pitches[plane], plane, min_pitch);
		return -EINVAL;
	}

	/* Force at least natural alignment. */
	if (rfb->base.offsets[plane] % block_size) {
		drm_dbg_kms(rfb->base.dev,
			    "offset 0x%x for plane %d is not a multiple of block pitch 0x%x\n",
			    rfb->base.offsets[plane], plane, block_size);
		return -EINVAL;
	}

	size = rfb->base.offsets[plane] +
		(uint64_t)rfb->base.pitches[plane] / block_pitch *
		block_size * DIV_ROUND_UP(height, block_height);

	if (rfb->base.obj[0]->size < size) {
		drm_dbg_kms(rfb->base.dev,
			    "BO size 0x%zx is less than 0x%llx required for plane %d\n",
			    rfb->base.obj[0]->size, size, plane);
		return -EINVAL;
	}

	return 0;
}

static int amdgpu_display_verify_sizes_gfx6(struct drm_device *dev,
					    const u64 modifier,
					    unsigned int *out_block_width,
					    unsigned int *out_block_height)
{
	const u32 display_micro_tile_pitch = 32; /* required by DCE */
	const u32 micro_tile_width = 8;
	const u32 micro_tile_height = 8;
	const u32 micro_tile_mode = AMD_FMT_MOD_GET(MICROTILE, modifier);
	const u32 array_mode = AMD_FMT_MOD_GET(TILE, modifier);
	u32 num_banks, bank_width, bank_height, pipe_config, macro_tile_aspect;
	u32 num_pipes;

	if (AMD_FMT_MOD_GET(DCC, modifier)) {
		drm_dbg_kms(dev, "DCC is not displayable on GFX6-8\n");
		return -EINVAL;
	}
	if (array_mode != AMD_FMT_MOD_TILE_GFX6_1D_TILED_THIN1 &&
	    array_mode != AMD_FMT_MOD_TILE_GFX6_2D_TILED_THIN1) {
		drm_dbg_kms(dev, "Array mode %u not supported for scanout\n", array_mode);
		return -EINVAL;
	}
	if (micro_tile_mode != AMD_FMT_MOD_MICROTILE_DISPLAY) {
		drm_dbg_kms(dev, "Microtile mode %u not supported for scanout\n", micro_tile_mode);
		return -EINVAL;
	}

	num_banks = 2 << AMD_FMT_MOD_GET(NUM_BANKS, modifier);
	bank_width = 1 << AMD_FMT_MOD_GET(BANK_WIDTH, modifier);
	bank_height = 1 << AMD_FMT_MOD_GET(BANK_HEIGHT, modifier);
	pipe_config = AMD_FMT_MOD_GET(PIPE_CONFIG, modifier);
	macro_tile_aspect = 1 << AMD_FMT_MOD_GET(MACRO_TILE_ASPECT, modifier);

	switch (pipe_config) {
	case AMD_FMT_MOD_PIPE_CONFIG_P16_32x32_8x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P16_32x32_16x16:
		num_pipes = 16;
		break;

	case AMD_FMT_MOD_PIPE_CONFIG_P8_16x16_8x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_16x32_8x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_32x32_8x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_16x32_16x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_32x32_16x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_32x32_16x32:
	case AMD_FMT_MOD_PIPE_CONFIG_P8_32x64_32x32:
		num_pipes = 8;
		break;

	case AMD_FMT_MOD_PIPE_CONFIG_P4_8x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P4_16x16:
	case AMD_FMT_MOD_PIPE_CONFIG_P4_16x32:
	case AMD_FMT_MOD_PIPE_CONFIG_P4_32x32:
		num_pipes = 4;
		break;

	case AMD_FMT_MOD_PIPE_CONFIG_P2:
		num_pipes = 2;
		break;

	default:
		drm_dbg_kms(dev, "Pipe config %u invalid\n", pipe_config);
		return -EINVAL;
	}

	/* For reference, see SiLib::InitEquationTable() in addrlib */
	if (array_mode < AMD_FMT_MOD_TILE_GFX6_2D_TILED_THIN1) {
		*out_block_width = display_micro_tile_pitch;
		*out_block_height = micro_tile_height;
	} else {
		/* Assume non-PRT macro tiling modes */
		*out_block_width = num_pipes * micro_tile_width *
				   bank_width * macro_tile_aspect;
		*out_block_height = micro_tile_height * bank_height *
				    num_banks / macro_tile_aspect;
	}

	return 0;
}

static int amdgpu_display_verify_sizes(struct amdgpu_framebuffer *rfb)
{
	const struct drm_format_info *format_info = drm_format_info(rfb->base.format->format);
	uint64_t modifier = rfb->base.modifier;
	int ret;
	unsigned int i, block_width, block_height, block_size_log2;

	if (rfb->base.dev->mode_config.fb_modifiers_not_supported)
		return 0;

	for (i = 0; i < format_info->num_planes; ++i) {
		if (modifier == DRM_FORMAT_MOD_LINEAR) {
			block_width = 256 / format_info->cpp[i];
			block_height = 1;
			block_size_log2 = 8;
		} else if (AMD_FMT_MOD_GET(TILE_VERSION, modifier) >= AMD_FMT_MOD_TILE_VER_GFX12) {
			int swizzle = AMD_FMT_MOD_GET(TILE, modifier);

			switch (swizzle) {
			case AMD_FMT_MOD_TILE_GFX12_256B_2D:
				block_size_log2 = 8;
				break;
			case AMD_FMT_MOD_TILE_GFX12_4K_2D:
				block_size_log2 = 12;
				break;
			case AMD_FMT_MOD_TILE_GFX12_64K_2D:
				block_size_log2 = 16;
				break;
			case AMD_FMT_MOD_TILE_GFX12_256K_2D:
				block_size_log2 = 18;
				break;
			default:
				drm_dbg_kms(rfb->base.dev,
					    "Gfx12 swizzle mode with unknown block size: %d\n", swizzle);
				return -EINVAL;
			}

			get_block_dimensions(block_size_log2, format_info->cpp[i],
					     &block_width, &block_height);
		} else if (AMD_FMT_MOD_GET(TILE_VERSION, modifier) >= AMD_FMT_MOD_TILE_VER_GFX9) {
			int swizzle = AMD_FMT_MOD_GET(TILE, modifier);

			switch ((swizzle & ~3) + 1) {
			case DC_SW_256B_S:
				block_size_log2 = 8;
				break;
			case DC_SW_4KB_S:
			case DC_SW_4KB_S_X:
				block_size_log2 = 12;
				break;
			case DC_SW_64KB_S:
			case DC_SW_64KB_S_T:
			case DC_SW_64KB_S_X:
				block_size_log2 = 16;
				break;
			case DC_SW_VAR_S_X:
				block_size_log2 = 18;
				break;
			default:
				drm_dbg_kms(rfb->base.dev,
					    "Swizzle mode with unknown block size: %d\n", swizzle);
				return -EINVAL;
			}

			get_block_dimensions(block_size_log2, format_info->cpp[i],
					     &block_width, &block_height);
		} else if (AMD_FMT_MOD_GET(TILE_VERSION, modifier) == AMD_FMT_MOD_TILE_VER_GFX6) {
			ret = amdgpu_display_verify_sizes_gfx6(rfb->base.dev, modifier,
							       &block_width, &block_height);
			if (ret)
				return ret;

			/* amdgpu_display_verify_plane() assumes the block size is a power of 2 */
			WARN_ON(!is_power_of_2(block_width));
			WARN_ON(!is_power_of_2(block_height));
			WARN_ON(!is_power_of_2(format_info->cpp[i]));

			block_size_log2 = ilog2(block_width * block_height * format_info->cpp[i]);
		}

		ret = amdgpu_display_verify_plane(rfb, i, format_info,
						  block_width, block_height, block_size_log2);
		if (ret)
			return ret;
	}

	if (AMD_FMT_MOD_GET(TILE_VERSION, modifier) <= AMD_FMT_MOD_TILE_VER_GFX11 &&
	    AMD_FMT_MOD_GET(DCC, modifier)) {
		if (AMD_FMT_MOD_GET(DCC_RETILE, modifier)) {
			block_size_log2 = get_dcc_block_size(modifier, false, false);
			get_block_dimensions(block_size_log2 + 8, format_info->cpp[0],
					     &block_width, &block_height);
			ret = amdgpu_display_verify_plane(rfb, i, format_info,
							  block_width, block_height,
							  block_size_log2);
			if (ret)
				return ret;

			++i;
			block_size_log2 = get_dcc_block_size(modifier, true, true);
		} else {
			bool pipe_aligned = AMD_FMT_MOD_GET(DCC_PIPE_ALIGN, modifier);

			block_size_log2 = get_dcc_block_size(modifier, true, pipe_aligned);
		}
		get_block_dimensions(block_size_log2 + 8, format_info->cpp[0],
				     &block_width, &block_height);
		ret = amdgpu_display_verify_plane(rfb, i, format_info,
						  block_width, block_height, block_size_log2);
		if (ret)
			return ret;
	}

	return 0;
}

static int amdgpu_display_get_fb_info(const struct amdgpu_framebuffer *amdgpu_fb,
				      uint64_t *tiling_flags, bool *tmz_surface,
				      bool *gfx12_dcc)
{
	struct amdgpu_bo *rbo;
	int r;

	if (!amdgpu_fb) {
		*tiling_flags = 0;
		*tmz_surface = false;
		*gfx12_dcc = false;
		return 0;
	}

	rbo = gem_to_amdgpu_bo(amdgpu_fb->base.obj[0]);
	r = amdgpu_bo_reserve(rbo, false);

	if (unlikely(r)) {
		/* Don't show error message when returning -ERESTARTSYS */
		if (r != -ERESTARTSYS)
			DRM_ERROR("Unable to reserve buffer: %d\n", r);
		return r;
	}

	amdgpu_bo_get_tiling_flags(rbo, tiling_flags);
	*tmz_surface = amdgpu_bo_encrypted(rbo);
	*gfx12_dcc = rbo->flags & AMDGPU_GEM_CREATE_GFX12_DCC;

	amdgpu_bo_unreserve(rbo);

	return r;
}

static int amdgpu_display_gem_fb_verify_and_init(struct drm_device *dev,
						 struct amdgpu_framebuffer *rfb,
						 struct drm_file *file_priv,
						 const struct drm_format_info *info,
						 const struct drm_mode_fb_cmd2 *mode_cmd,
						 struct drm_gem_object *obj)
{
	int ret;

	rfb->base.obj[0] = obj;
	drm_helper_mode_fill_fb_struct(dev, &rfb->base, info, mode_cmd);
	/* Verify that the modifier is supported. */
	if (!drm_any_plane_has_format(dev, mode_cmd->pixel_format,
				      mode_cmd->modifier[0])) {
		drm_dbg_kms(dev,
			    "unsupported pixel format %p4cc / modifier 0x%llx\n",
			    &mode_cmd->pixel_format, mode_cmd->modifier[0]);

		ret = -EINVAL;
		goto err;
	}

	ret = amdgpu_display_framebuffer_init(dev, rfb, mode_cmd, obj);
	if (ret)
		goto err;

	if (drm_drv_uses_atomic_modeset(dev))
		ret = drm_framebuffer_init(dev, &rfb->base,
					   &amdgpu_fb_funcs_atomic);
	else
		ret = drm_framebuffer_init(dev, &rfb->base, &amdgpu_fb_funcs);

	if (ret)
		goto err;

	return 0;
err:
	drm_dbg_kms(dev, "Failed to verify and init gem fb: %d\n", ret);
	rfb->base.obj[0] = NULL;
	return ret;
}

static int amdgpu_display_framebuffer_init(struct drm_device *dev,
					   struct amdgpu_framebuffer *rfb,
					   const struct drm_mode_fb_cmd2 *mode_cmd,
					   struct drm_gem_object *obj)
{
	struct amdgpu_device *adev = drm_to_adev(dev);
	int ret, i;

	/*
	 * This needs to happen before modifier conversion as that might change
	 * the number of planes.
	 */
	for (i = 1; i < rfb->base.format->num_planes; ++i) {
		if (mode_cmd->handles[i] != mode_cmd->handles[0]) {
			drm_dbg_kms(dev, "Plane 0 and %d have different BOs: %u vs. %u\n",
				    i, mode_cmd->handles[0], mode_cmd->handles[i]);
			ret = -EINVAL;
			return ret;
		}
	}

	ret = amdgpu_display_get_fb_info(rfb, &rfb->tiling_flags, &rfb->tmz_surface,
					 &rfb->gfx12_dcc);
	if (ret)
		return ret;

	if (dev->mode_config.fb_modifiers_not_supported && !adev->enable_virtual_display) {
		drm_WARN_ONCE(dev, adev->family >= AMDGPU_FAMILY_AI,
			      "GFX9+ requires FB check based on format modifier\n");
		ret = check_tiling_flags_gfx6(rfb);
		if (ret)
			return ret;
	}

	if (!dev->mode_config.fb_modifiers_not_supported &&
	    !(rfb->base.flags & DRM_MODE_FB_MODIFIERS)) {
		if (amdgpu_ip_version(adev, GC_HWIP, 0) >= IP_VERSION(12, 0, 0))
			ret = convert_tiling_flags_to_modifier_gfx12(rfb);
		else if (amdgpu_ip_version(adev, GC_HWIP, 0) >= IP_VERSION(9, 0, 0))
			ret = convert_tiling_flags_to_modifier_gfx9(rfb);
		else
			ret = convert_tiling_flags_to_modifier_gfx6(rfb);

		if (ret) {
			drm_dbg_kms(dev, "Failed to convert tiling flags 0x%llX to a modifier\n",
				    rfb->tiling_flags);
			return ret;
		}
	}

	ret = amdgpu_display_verify_sizes(rfb);
	if (ret)
		return ret;

	for (i = 0; i < rfb->base.format->num_planes; ++i) {
		drm_gem_object_get(rfb->base.obj[0]);
		rfb->base.obj[i] = rfb->base.obj[0];
	}

	return 0;
}

struct drm_framebuffer *
amdgpu_display_user_framebuffer_create(struct drm_device *dev,
				       struct drm_file *file_priv,
				       const struct drm_format_info *info,
				       const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct amdgpu_framebuffer *amdgpu_fb;
	struct drm_gem_object *obj;
	struct amdgpu_bo *bo;
	uint32_t domains;
	int ret;

	obj = drm_gem_object_lookup(file_priv, mode_cmd->handles[0]);
	if (obj ==  NULL) {
		drm_dbg_kms(dev,
			    "No GEM object associated to handle 0x%08X, can't create framebuffer\n",
			    mode_cmd->handles[0]);

		return ERR_PTR(-ENOENT);
	}

	/* Handle is imported dma-buf, so cannot be migrated to VRAM for scanout */
	bo = gem_to_amdgpu_bo(obj);
	domains = amdgpu_display_supported_domains(drm_to_adev(dev), bo->flags);
	if (drm_gem_is_imported(obj) && !(domains & AMDGPU_GEM_DOMAIN_GTT)) {
		drm_dbg_kms(dev, "Cannot create framebuffer from imported dma_buf\n");
		drm_gem_object_put(obj);
		return ERR_PTR(-EINVAL);
	}

	amdgpu_fb = kzalloc_obj(*amdgpu_fb);
	if (amdgpu_fb == NULL) {
		drm_gem_object_put(obj);
		return ERR_PTR(-ENOMEM);
	}

	ret = amdgpu_display_gem_fb_verify_and_init(dev, amdgpu_fb, file_priv,
						    info, mode_cmd, obj);
	if (ret) {
		kfree(amdgpu_fb);
		drm_gem_object_put(obj);
		return ERR_PTR(ret);
	}

	drm_gem_object_put(obj);
	return &amdgpu_fb->base;
}

const struct drm_mode_config_funcs amdgpu_mode_funcs = {
	.fb_create = amdgpu_display_user_framebuffer_create,
};

static const struct drm_prop_enum_list amdgpu_underscan_enum_list[] = {
	{ UNDERSCAN_OFF, "off" },
	{ UNDERSCAN_ON, "on" },
	{ UNDERSCAN_AUTO, "auto" },
};

static const struct drm_prop_enum_list amdgpu_audio_enum_list[] = {
	{ AMDGPU_AUDIO_DISABLE, "off" },
	{ AMDGPU_AUDIO_ENABLE, "on" },
	{ AMDGPU_AUDIO_AUTO, "auto" },
};

/* XXX support different dither options? spatial, temporal, both, etc. */
static const struct drm_prop_enum_list amdgpu_dither_enum_list[] = {
	{ AMDGPU_FMT_DITHER_DISABLE, "off" },
	{ AMDGPU_FMT_DITHER_ENABLE, "on" },
};

/**
 * DOC: property for adaptive backlight modulation
 *
 * The 'adaptive backlight modulation' property is used for the compositor to
 * directly control the adaptive backlight modulation power savings feature
 * that is part of DCN hardware.
 *
 * The property will be attached specifically to eDP panels that support it.
 *
 * The property is by default set to 'sysfs' to allow the sysfs file 'panel_power_savings'
 * to be able to control it.
 * If set to 'off' the compositor will ensure it stays off.
 * The other values 'min', 'bias min', 'bias max', and 'max' will control the
 * intensity of the power savings.
 *
 * Modifying this value can have implications on color accuracy, so tread
 * carefully.
 */
static int amdgpu_display_setup_abm_prop(struct amdgpu_device *adev)
{
	const struct drm_prop_enum_list props[] = {
		{ ABM_SYSFS_CONTROL, "sysfs" },
		{ ABM_LEVEL_OFF, "off" },
		{ ABM_LEVEL_MIN, "min" },
		{ ABM_LEVEL_BIAS_MIN, "bias min" },
		{ ABM_LEVEL_BIAS_MAX, "bias max" },
		{ ABM_LEVEL_MAX, "max" },
	};
	struct drm_property *prop;
	int i;

	if (!adev->dc_enabled)
		return 0;

	prop = drm_property_create(adev_to_drm(adev), DRM_MODE_PROP_ENUM,
				"adaptive backlight modulation",
				6);
	if (!prop)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(props); i++) {
		int ret;

		ret = drm_property_add_enum(prop, props[i].type,
						props[i].name);

		if (ret) {
			drm_property_destroy(adev_to_drm(adev), prop);

			return ret;
		}
	}

	adev->mode_info.abm_level_property = prop;

	return 0;
}

int amdgpu_display_modeset_create_props(struct amdgpu_device *adev)
{
	int sz;

	adev->mode_info.coherent_mode_property =
		drm_property_create_range(adev_to_drm(adev), 0, "coherent", 0, 1);
	if (!adev->mode_info.coherent_mode_property)
		return -ENOMEM;

	adev->mode_info.load_detect_property =
		drm_property_create_range(adev_to_drm(adev), 0, "load detection", 0, 1);
	if (!adev->mode_info.load_detect_property)
		return -ENOMEM;

	drm_mode_create_scaling_mode_property(adev_to_drm(adev));

	sz = ARRAY_SIZE(amdgpu_underscan_enum_list);
	adev->mode_info.underscan_property =
		drm_property_create_enum(adev_to_drm(adev), 0,
					 "underscan",
					 amdgpu_underscan_enum_list, sz);

	adev->mode_info.underscan_hborder_property =
		drm_property_create_range(adev_to_drm(adev), 0,
					  "underscan hborder", 0, 128);
	if (!adev->mode_info.underscan_hborder_property)
		return -ENOMEM;

	adev->mode_info.underscan_vborder_property =
		drm_property_create_range(adev_to_drm(adev), 0,
					  "underscan vborder", 0, 128);
	if (!adev->mode_info.underscan_vborder_property)
		return -ENOMEM;

	sz = ARRAY_SIZE(amdgpu_audio_enum_list);
	adev->mode_info.audio_property =
		drm_property_create_enum(adev_to_drm(adev), 0,
					 "audio",
					 amdgpu_audio_enum_list, sz);

	sz = ARRAY_SIZE(amdgpu_dither_enum_list);
	adev->mode_info.dither_property =
		drm_property_create_enum(adev_to_drm(adev), 0,
					 "dither",
					 amdgpu_dither_enum_list, sz);

	return amdgpu_display_setup_abm_prop(adev);
}

/*
 * Retrieve current video scanout position of crtc on a given gpu, and
 * an optional accurate timestamp of when query happened.
 *
 * \param dev Device to query.
 * \param pipe Crtc to query.
 * \param flags from caller (DRM_CALLED_FROM_VBLIRQ or 0).
 *              For driver internal use only also supports these flags:
 *
 *              USE_REAL_VBLANKSTART to use the real start of vblank instead
 *              of a fudged earlier start of vblank.
 *
 *              GET_DISTANCE_TO_VBLANKSTART to return distance to the
 *              fudged earlier start of vblank in *vpos and the distance
 *              to true start of vblank in *hpos.
 *
 * \param *vpos Location where vertical scanout position should be stored.
 * \param *hpos Location where horizontal scanout position should go.
 * \param *stime Target location for timestamp taken immediately before
 *               scanout position query. Can be NULL to skip timestamp.
 * \param *etime Target location for timestamp taken immediately after
 *               scanout position query. Can be NULL to skip timestamp.
 *
 * Returns vpos as a positive number while in active scanout area.
 * Returns vpos as a negative number inside vblank, counting the number
 * of scanlines to go until end of vblank, e.g., -1 means "one scanline
 * until start of active scanout / end of vblank."
 *
 * \return Flags, or'ed together as follows:
 *
 * DRM_SCANOUTPOS_VALID = Query successful.
 * DRM_SCANOUTPOS_INVBL = Inside vblank.
 * DRM_SCANOUTPOS_ACCURATE = Returned position is accurate. A lack of
 * this flag means that returned position may be offset by a constant but
 * unknown small number of scanlines wrt. real scanout position.
 *
 */
int amdgpu_display_get_crtc_scanoutpos(struct drm_device *dev,
			unsigned int pipe, unsigned int flags, int *vpos,
			int *hpos, ktime_t *stime, ktime_t *etime,
			const struct drm_display_mode *mode)
{
	u32 vbl = 0, position = 0;
	int vbl_start, vbl_end, vtotal, ret = 0;
	bool in_vbl = true;

	struct amdgpu_device *adev = drm_to_adev(dev);

	/* preempt_disable_rt() should go right here in PREEMPT_RT patchset. */

	/* Get optional system timestamp before query. */
	if (stime)
		*stime = ktime_get();

	if (amdgpu_display_page_flip_get_scanoutpos(adev, pipe, &vbl, &position) == 0)
		ret |= DRM_SCANOUTPOS_VALID;

	/* Get optional system timestamp after query. */
	if (etime)
		*etime = ktime_get();

	/* preempt_enable_rt() should go right here in PREEMPT_RT patchset. */

	/* Decode into vertical and horizontal scanout position. */
	*vpos = position & 0x1fff;
	*hpos = (position >> 16) & 0x1fff;

	/* Valid vblank area boundaries from gpu retrieved? */
	if (vbl > 0) {
		/* Yes: Decode. */
		ret |= DRM_SCANOUTPOS_ACCURATE;
		vbl_start = vbl & 0x1fff;
		vbl_end = (vbl >> 16) & 0x1fff;
	} else {
		/* No: Fake something reasonable which gives at least ok results. */
		vbl_start = mode->crtc_vdisplay;
		vbl_end = 0;
	}

	/* Called from driver internal vblank counter query code? */
	if (flags & GET_DISTANCE_TO_VBLANKSTART) {
		/* Caller wants distance from real vbl_start in *hpos */
		*hpos = *vpos - vbl_start;
	}

	/* Fudge vblank to start a few scanlines earlier to handle the
	 * problem that vblank irqs fire a few scanlines before start
	 * of vblank. Some driver internal callers need the true vblank
	 * start to be used and signal this via the USE_REAL_VBLANKSTART flag.
	 *
	 * The cause of the "early" vblank irq is that the irq is triggered
	 * by the line buffer logic when the line buffer read position enters
	 * the vblank, whereas our crtc scanout position naturally lags the
	 * line buffer read position.
	 */
	if (!(flags & USE_REAL_VBLANKSTART))
		vbl_start -= adev->mode_info.crtcs[pipe]->lb_vblank_lead_lines;

	/* Test scanout position against vblank region. */
	if ((*vpos < vbl_start) && (*vpos >= vbl_end))
		in_vbl = false;

	/* In vblank? */
	if (in_vbl)
		ret |= DRM_SCANOUTPOS_IN_VBLANK;

	/* Called from driver internal vblank counter query code? */
	if (flags & GET_DISTANCE_TO_VBLANKSTART) {
		/* Caller wants distance from fudged earlier vbl_start */
		*vpos -= vbl_start;
		return ret;
	}

	/* Check if inside vblank area and apply corrective offsets:
	 * vpos will then be >=0 in video scanout area, but negative
	 * within vblank area, counting down the number of lines until
	 * start of scanout.
	 */

	/* Inside "upper part" of vblank area? Apply corrective offset if so: */
	if (in_vbl && (*vpos >= vbl_start)) {
		vtotal = mode->crtc_vtotal;

		/* With variable refresh rate displays the vpos can exceed
		 * the vtotal value. Clamp to 0 to return -vbl_end instead
		 * of guessing the remaining number of lines until scanout.
		 */
		*vpos = (*vpos < vtotal) ? (*vpos - vtotal) : 0;
	}

	/* Correct for shifted end of vbl at vbl_end. */
	*vpos = *vpos - vbl_end;

	return ret;
}

int amdgpu_display_crtc_idx_to_irq_type(struct amdgpu_device *adev, int crtc)
{
	if (crtc < 0 || crtc >= adev->mode_info.num_crtc)
		return AMDGPU_CRTC_IRQ_NONE;

	switch (crtc) {
	case 0:
		return AMDGPU_CRTC_IRQ_VBLANK1;
	case 1:
		return AMDGPU_CRTC_IRQ_VBLANK2;
	case 2:
		return AMDGPU_CRTC_IRQ_VBLANK3;
	case 3:
		return AMDGPU_CRTC_IRQ_VBLANK4;
	case 4:
		return AMDGPU_CRTC_IRQ_VBLANK5;
	case 5:
		return AMDGPU_CRTC_IRQ_VBLANK6;
	default:
		return AMDGPU_CRTC_IRQ_NONE;
	}
}

bool amdgpu_crtc_get_scanout_position(struct drm_crtc *crtc,
			bool in_vblank_irq, int *vpos,
			int *hpos, ktime_t *stime, ktime_t *etime,
			const struct drm_display_mode *mode)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = crtc->index;

	return amdgpu_display_get_crtc_scanoutpos(dev, pipe, 0, vpos, hpos,
						  stime, etime, mode);
}

/* panic_bo is set in amdgpu_dm_plane_get_scanout_buffer() and only used in amdgpu_dm_set_pixel()
 * they are called from the panic handler, and protected by the drm_panic spinlock.
 */
static struct amdgpu_bo *panic_abo;

/* Use the indirect MMIO to write each pixel to the GPU VRAM,
 * This is a simplified version of amdgpu_device_mm_access()
 */
static void amdgpu_display_set_pixel(struct drm_scanout_buffer *sb,
				     unsigned int x,
				     unsigned int y,
				     u32 color)
{
	struct amdgpu_res_cursor cursor;
	unsigned long offset;
	struct amdgpu_bo *abo = panic_abo;
	struct amdgpu_device *adev = amdgpu_ttm_adev(abo->tbo.bdev);
	uint32_t tmp;

	offset = x * 4 + y * sb->pitch[0];
	amdgpu_res_first(abo->tbo.resource, offset, 4, &cursor);

	tmp = cursor.start >> 31;
	WREG32_NO_KIQ(mmMM_INDEX, ((uint32_t) cursor.start) | 0x80000000);
	if (tmp != 0xffffffff)
		WREG32_NO_KIQ(mmMM_INDEX_HI, tmp);
	WREG32_NO_KIQ(mmMM_DATA, color);
}

int amdgpu_display_get_scanout_buffer(struct drm_plane *plane,
				      struct drm_scanout_buffer *sb)
{
	struct amdgpu_bo *abo;
	struct drm_framebuffer *fb;

	if (drm_drv_uses_atomic_modeset(plane->dev))
		fb = plane->state->fb;
	else
		fb = plane->fb;

	if (!fb)
		return -EINVAL;

	DRM_DEBUG_KMS("Framebuffer %dx%d %p4cc\n", fb->width, fb->height, &fb->format->format);

	abo = gem_to_amdgpu_bo(fb->obj[0]);
	if (!abo)
		return -EINVAL;

	sb->width = fb->width;
	sb->height = fb->height;
	/* Use the generic linear format, because tiling will be disabled in panic_flush() */
	sb->format = drm_format_info(fb->format->format);
	if (!sb->format)
		return -EINVAL;

	sb->pitch[0] = fb->pitches[0];

	if (abo->flags & AMDGPU_GEM_CREATE_NO_CPU_ACCESS) {
		if (abo->tbo.resource->mem_type != TTM_PL_VRAM) {
			drm_warn(plane->dev, "amdgpu panic, framebuffer not in VRAM\n");
			return -EINVAL;
		}
		/* Only handle 32bits format, to simplify mmio access */
		if (fb->format->cpp[0] != 4) {
			drm_warn(plane->dev, "amdgpu panic, pixel format is not 32bits\n");
			return -EINVAL;
		}
		sb->set_pixel = amdgpu_display_set_pixel;
		panic_abo = abo;
		return 0;
	}
	if (!abo->kmap.virtual &&
	    ttm_bo_kmap(&abo->tbo, 0, PFN_UP(abo->tbo.base.size), &abo->kmap)) {
		drm_warn(plane->dev, "amdgpu bo map failed, panic won't be displayed\n");
		return -ENOMEM;
	}
	if (abo->kmap.bo_kmap_type & TTM_BO_MAP_IOMEM_MASK)
		iosys_map_set_vaddr_iomem(&sb->map[0], abo->kmap.virtual);
	else
		iosys_map_set_vaddr(&sb->map[0], abo->kmap.virtual);

	return 0;
}
