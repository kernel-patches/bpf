/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_PANEL_BPF_MIPI_DSI_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _PANEL_BPF_MIPI_DSI_TRACE_H_

#include <linux/tracepoint.h>
#include <linux/types.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM panel_bpf
#define TRACE_INCLUDE_FILE panel-bpf-mipi-dsi-trace

TRACE_EVENT(panel_bpf_mipi_dsi_callback,
	    TP_PROTO(const char *panel, const char *name),
	    TP_ARGS(panel, name),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
	    ),
	    TP_printk("panel=%s callback=%s",
		      __get_str(panel), __get_str(name))
);

TRACE_EVENT(panel_bpf_mipi_dsi_callback_done,
	    TP_PROTO(const char *panel, const char *name, int ret),
	    TP_ARGS(panel, name, ret),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
		__field(int, ret)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
		__entry->ret = ret;
	    ),
	    TP_printk("panel=%s callback=%s ret=%d",
		      __get_str(panel), __get_str(name), __entry->ret)
);

TRACE_EVENT(panel_bpf_mipi_dsi_reg,
	    TP_PROTO(const char *panel),
	    TP_ARGS(panel),
	    TP_STRUCT__entry(
		__string(panel, panel)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
	    ),
	    TP_printk("panel=%s", __get_str(panel))
);

TRACE_EVENT(panel_bpf_mipi_dsi_unreg,
	    TP_PROTO(const char *panel),
	    TP_ARGS(panel),
	    TP_STRUCT__entry(
		__string(panel, panel)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
	    ),
	    TP_printk("panel=%s", __get_str(panel))
);

TRACE_EVENT(panel_bpf_mipi_dsi_dcs_write_and_wait,
	    TP_PROTO(const char *panel, u8 cmd, const u8 *data, u32 len,
		     int ret),
	    TP_ARGS(panel, cmd, data, len, ret),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__field(u8, cmd)
		__field(u32, len)
		__field(int, ret)
		__array(u8, data, 8)
	    ),
	    TP_fast_assign(
		unsigned int n = min_t(u32, len, 8);

		__assign_str(panel);
		__entry->cmd = cmd;
		__entry->len = len;
		__entry->ret = ret;
		memset(__entry->data, 0, 8);
		if (n && data)
			memcpy(__entry->data, data, n);
	    ),
	    TP_printk("panel=%s cmd=0x%02x len=%u data=%s ret=%d",
		      __get_str(panel), __entry->cmd, __entry->len,
		      __print_hex(__entry->data, min_t(u32, __entry->len, 8)),
		      __entry->ret)
);

TRACE_EVENT(panel_bpf_mipi_dsi_generic_write_and_wait,
	    TP_PROTO(const char *panel, const u8 *data, u32 len, int ret),
	    TP_ARGS(panel, data, len, ret),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__field(u32, len)
		__field(int, ret)
		__array(u8, data, 8)
	    ),
	    TP_fast_assign(
		unsigned int n = min_t(u32, len, 8);

		__assign_str(panel);
		__entry->len = len;
		__entry->ret = ret;
		memset(__entry->data, 0, 8);
		if (n && data)
			memcpy(__entry->data, data, n);
	    ),
	    TP_printk("panel=%s len=%u data=%s ret=%d",
		      __get_str(panel), __entry->len,
		      __print_hex(__entry->data, min_t(u32, __entry->len, 8)),
		      __entry->ret)
);

TRACE_EVENT(panel_bpf_mipi_dsi_dcs_read,
	    TP_PROTO(const char *panel, u8 cmd, u32 len),
	    TP_ARGS(panel, cmd, len),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__field(u8, cmd)
		__field(u32, len)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__entry->cmd = cmd;
		__entry->len = len;
	    ),
	    TP_printk("panel=%s cmd=0x%02x len=%u",
		      __get_str(panel), __entry->cmd, __entry->len)
);

TRACE_EVENT(panel_bpf_mipi_dsi_dcs_read_done,
	    TP_PROTO(const char *panel, u8 cmd, u32 len, int ret),
	    TP_ARGS(panel, cmd, len, ret),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__field(u8, cmd)
		__field(u32, len)
		__field(int, ret)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__entry->cmd = cmd;
		__entry->len = len;
		__entry->ret = ret;
	    ),
	    TP_printk("panel=%s cmd=0x%02x len=%u ret=%d",
		      __get_str(panel), __entry->cmd, __entry->len,
		      __entry->ret)
);

TRACE_EVENT(panel_bpf_mipi_dsi_gpio_cycle_and_wait,
	    TP_PROTO(const char *panel, const char *name, u32 assert_ms, u32 wait_ms),
	    TP_ARGS(panel, name, assert_ms, wait_ms),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
		__field(u32, assert_ms)
		__field(u32, wait_ms)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
		__entry->assert_ms = assert_ms;
		__entry->wait_ms = wait_ms;
	    ),
	    TP_printk("panel=%s gpio=%s assert_ms=%u wait_ms=%u",
		      __get_str(panel), __get_str(name),
		      __entry->assert_ms, __entry->wait_ms)
);

TRACE_EVENT(panel_bpf_mipi_dsi_gpio_enable,
	    TP_PROTO(const char *panel, const char *name),
	    TP_ARGS(panel, name),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
	    ),
	    TP_printk("panel=%s gpio=%s",
		      __get_str(panel), __get_str(name))
);

TRACE_EVENT(panel_bpf_mipi_dsi_gpio_disable,
	    TP_PROTO(const char *panel, const char *name),
	    TP_ARGS(panel, name),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
	    ),
	    TP_printk("panel=%s gpio=%s",
		      __get_str(panel), __get_str(name))
);

TRACE_EVENT(panel_bpf_mipi_dsi_regulator_enable_and_wait,
	    TP_PROTO(const char *panel, const char *name, u32 wait_ms),
	    TP_ARGS(panel, name, wait_ms),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
		__field(u32, wait_ms)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
		__entry->wait_ms = wait_ms;
	    ),
	    TP_printk("panel=%s supply=%s wait_ms=%u",
		      __get_str(panel), __get_str(name),
		      __entry->wait_ms)
);

TRACE_EVENT(panel_bpf_mipi_dsi_regulator_disable,
	    TP_PROTO(const char *panel, const char *name),
	    TP_ARGS(panel, name),
	    TP_STRUCT__entry(
		__string(panel, panel)
		__string(name, name)
	    ),
	    TP_fast_assign(
		__assign_str(panel);
		__assign_str(name);
	    ),
	    TP_printk("panel=%s supply=%s",
		      __get_str(panel), __get_str(name))
);

#endif /* _PANEL_BPF_MIPI_DSI_TRACE_H_ */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../drivers/gpu/drm/panel/bpf
#include <trace/define_trace.h>
