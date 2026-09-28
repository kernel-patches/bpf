// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops for the generic MIPI-DSI panel driver
 *
 * Implements the struct_ops callbacks that let BPF programs provide
 * drm_panel_dsi_bpf_ops.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/string.h>

#include <drm/drm_mipi_dsi.h>

#include "panel-bpf-mipi-dsi.h"
#include "panel-bpf-mipi-dsi-trace.h"

/* Required by bpf_struct_ops_desc_init(), which calls it unconditionally. */
static int panel_bpf_mipi_dsi_bpf_init(struct btf *btf)
{
	return 0;
}

/*
 * Copy non-function fields from the userspace struct_ops map into the
 * kernel instance. The BPF verifier rejects non-zero values in fields
 * that are not explicitly handled here, so every data field must have
 * a case. Return 1 to indicate the field was consumed.
 */
static int panel_bpf_mipi_dsi_bpf_init_member(const struct btf_type *t,
					      const struct btf_member *member,
					      void *kdata, const void *udata)
{
	const struct drm_panel_dsi_bpf_ops *uops =
		(const struct drm_panel_dsi_bpf_ops *)udata;
	struct drm_panel_dsi_bpf_ops *kops =
		(struct drm_panel_dsi_bpf_ops *)kdata;
	u32 moff;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct drm_panel_dsi_bpf_ops, panel_id):
		memcpy(kops->panel_id, uops->panel_id,
		       sizeof(kops->panel_id));
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, compatible):
		memcpy(kops->compatible, uops->compatible,
		       sizeof(kops->compatible));
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, format):
		kops->format = uops->format;
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, lanes):
		kops->lanes = uops->lanes;
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, mode_flags):
		kops->mode_flags = uops->mode_flags;
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, hs_rate):
		kops->hs_rate = uops->hs_rate;
		return 1;
	case offsetof(struct drm_panel_dsi_bpf_ops, lp_rate):
		kops->lp_rate = uops->lp_rate;
		return 1;
	}

	return 0;
}

/*
 * Validate that the DSI link parameters compiled into the BPF program
 * match what the DT describes. Rejects mismatches early so a BPF
 * program built for a different panel variant cannot silently attach.
 */
static int panel_bpf_mipi_dsi_bpf_check_config(struct panel_bpf_mipi_dsi *panel,
					       struct drm_panel_dsi_bpf_ops *ops)
{
	struct mipi_dsi_device *dsi = panel->dsi;
	struct device *dev = &dsi->dev;

	if (!of_device_is_compatible(dev->of_node, ops->compatible)) {
		dev_err(dev,
			"BPF compatible \"%s\" doesn't match panel\n",
			ops->compatible);
		return -EINVAL;
	}

	if (ops->format != dsi->format) {
		dev_err(dev,
			"BPF pixel format %u doesn't match DT format %u\n",
			ops->format, dsi->format);
		return -EINVAL;
	}

	if (ops->lanes != dsi->lanes) {
		dev_err(dev,
			"BPF lanes %u doesn't match DT lanes %u\n",
			ops->lanes, dsi->lanes);
		return -EINVAL;
	}

	if (ops->mode_flags != dsi->mode_flags) {
		dev_err(dev,
			"BPF mode_flags 0x%lx doesn't match DT mode_flags 0x%lx\n",
			ops->mode_flags, dsi->mode_flags);
		return -EINVAL;
	}

	if (ops->hs_rate != dsi->hs_rate) {
		dev_err(dev,
			"BPF hs_rate %lu doesn't match DT hs_rate %lu\n",
			ops->hs_rate, dsi->hs_rate);
		return -EINVAL;
	}

	if (ops->lp_rate != dsi->lp_rate) {
		dev_err(dev,
			"BPF lp_rate %lu doesn't match DT lp_rate %lu\n",
			ops->lp_rate, dsi->lp_rate);
		return -EINVAL;
	}

	return 0;
}

/*
 * Bind a BPF program to its target panel. Called when the struct_ops
 * link is activated. Returns -ENODEV if no panel matches, -EBUSY if
 * a program is already attached.
 */
static int panel_bpf_mipi_dsi_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct drm_panel_dsi_bpf_ops *ops = kdata;
	struct panel_bpf_mipi_dsi *panel;
	int ret;

	trace_panel_bpf_mipi_dsi_reg(ops->panel_id);

	guard(mutex)(&panel_bpf_mipi_dsi_list_lock);

	panel = panel_bpf_mipi_dsi_find_panel_unlocked(ops->panel_id);
	if (!panel)
		return -ENODEV;

	guard(mutex)(&panel->bpf_lock);

	if (panel->bpf_ops)
		return -EBUSY;

	ret = panel_bpf_mipi_dsi_bpf_check_config(panel, ops);
	if (ret)
		return ret;

	ops->bridge = &panel->bridge;
	panel->bpf_ops = ops;

	return 0;
}

/*
 * Detach a BPF program from its panel. The bridge stays registered so
 * the display pipeline is not torn down — callbacks become no-ops
 * until a new program attaches.
 */
static void panel_bpf_mipi_dsi_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct drm_panel_dsi_bpf_ops *ops = kdata;
	struct panel_bpf_mipi_dsi *panel;

	trace_panel_bpf_mipi_dsi_unreg(ops->panel_id);

	if (!ops->bridge)
		return;

	panel = drm_bridge_to_bpf_panel(ops->bridge);

	scoped_guard(mutex, &panel->bpf_lock) {
		panel->bpf_ops = NULL;
		ops->bridge = NULL;
	}
}

static bool panel_bpf_mipi_dsi_verifier_is_valid_access(int off, int size,
							enum bpf_access_type type,
							const struct bpf_prog *prog,
							struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops panel_bpf_mipi_dsi_bpf_verifier_ops = {
	.get_func_proto		= bpf_base_func_proto,
	.is_valid_access	= panel_bpf_mipi_dsi_verifier_is_valid_access,
};

/* CFI stubs — no-op targets for indirect call validation (CONFIG_CFI_CLANG). */
static int panel_bpf_mipi_dsi_cfi_stub_prepare(struct panel_bpf_mipi_dsi_ctx *ctx)
{
	return 0;
}

static int panel_bpf_mipi_dsi_cfi_stub_unprepare(struct panel_bpf_mipi_dsi_ctx *ctx)
{
	return 0;
}

static int panel_bpf_mipi_dsi_cfi_stub_enable(struct panel_bpf_mipi_dsi_ctx *ctx)
{
	return 0;
}

static int panel_bpf_mipi_dsi_cfi_stub_disable(struct panel_bpf_mipi_dsi_ctx *ctx)
{
	return 0;
}

static struct drm_panel_dsi_bpf_ops panel_bpf_mipi_dsi_bpf_struct_ops_cfi_stubs = {
	.panel_prepare		= panel_bpf_mipi_dsi_cfi_stub_prepare,
	.panel_unprepare	= panel_bpf_mipi_dsi_cfi_stub_unprepare,
	.panel_enable		= panel_bpf_mipi_dsi_cfi_stub_enable,
	.panel_disable		= panel_bpf_mipi_dsi_cfi_stub_disable,
};

static struct bpf_struct_ops panel_bpf_mipi_dsi_bpf_struct_ops = {
	.verifier_ops	= &panel_bpf_mipi_dsi_bpf_verifier_ops,
	.init		= panel_bpf_mipi_dsi_bpf_init,
	.init_member	= panel_bpf_mipi_dsi_bpf_init_member,
	.reg		= panel_bpf_mipi_dsi_bpf_reg,
	.unreg		= panel_bpf_mipi_dsi_bpf_unreg,
	.name		= "drm_panel_dsi_bpf_ops",
	.cfi_stubs	= &panel_bpf_mipi_dsi_bpf_struct_ops_cfi_stubs,
	.owner		= THIS_MODULE,
};

int panel_bpf_mipi_dsi_register_struct_ops(void)
{
	return register_bpf_struct_ops(&panel_bpf_mipi_dsi_bpf_struct_ops,
				       drm_panel_dsi_bpf_ops);
}
