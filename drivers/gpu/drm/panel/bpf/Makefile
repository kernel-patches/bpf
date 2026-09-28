# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_DRM_PANEL_BPF_MIPI_DSI) += panel-bpf-mipi-dsi.o

panel-bpf-mipi-dsi-y := panel-bpf-mipi-dsi-core.o \
			 panel-bpf-mipi-dsi-kfuncs.o \
			 panel-bpf-mipi-dsi-ops.o \
			 panel-bpf-mipi-dsi-trace.o

CFLAGS_panel-bpf-mipi-dsi-trace.o := -I$(src)
