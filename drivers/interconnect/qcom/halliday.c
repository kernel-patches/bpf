// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2026, Stanislav Aleksandrov <lightofmysoul@gmail.com>
 */

#include <linux/device.h>
#include <linux/interconnect.h>
#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <dt-bindings/interconnect/qcom,halliday-rpmh.h>

#include "bcm-voter.h"
#include "icc-rpmh.h"

static struct qcom_icc_node srvc_aggre1_noc = {
	.name = "srvc_aggre1_noc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_aggre2_noc = {
	.name = "srvc_aggre2_noc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qup0_core_slave = {
	.name = "qup0_core_slave",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qup1_core_slave = {
	.name = "qup1_core_slave",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_ahb2phy0 = {
	.name = "qhs_ahb2phy0",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_ahb2phy1 = {
	.name = "qhs_ahb2phy1",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_aoss = {
	.name = "qhs_aoss",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_camera_cfg = {
	.name = "qhs_camera_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_clk_ctl = {
	.name = "qhs_clk_ctl",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_cpr_cx = {
	.name = "qhs_cpr_cx",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_cpr_mmcx = {
	.name = "qhs_cpr_mmcx",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_cpr_mxa = {
	.name = "qhs_cpr_mxa",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_cpr_mxc = {
	.name = "qhs_cpr_mxc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_crypto0_cfg = {
	.name = "qhs_crypto0_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_cx_rdpm = {
	.name = "qhs_cx_rdpm",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_display_0_cfg = {
	.name = "qhs_display_0_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_display_1_cfg = {
	.name = "qhs_display_1_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_gpuss_cfg = {
	.name = "qhs_gpuss_cfg",
	.channels = 1,
	.buswidth = 8,
};

static struct qcom_icc_node qhs_imem_cfg = {
	.name = "qhs_imem_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_ipa = {
	.name = "qhs_ipa",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_ipc_router = {
	.name = "qhs_ipc_router",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_mx_rdpm = {
	.name = "qhs_mx_rdpm",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_pdm = {
	.name = "qhs_pdm",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_prng = {
	.name = "qhs_prng",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_qdss_cfg = {
	.name = "qhs_qdss_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_qup0 = {
	.name = "qhs_qup0",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_qup1 = {
	.name = "qhs_qup1",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_sdc2 = {
	.name = "qhs_sdc2",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_spss_cfg = {
	.name = "qhs_spss_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_tcsr = {
	.name = "qhs_tcsr",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_tlmm = {
	.name = "qhs_tlmm",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_tme_cfg = {
	.name = "qhs_tme_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_ufs_mem_cfg = {
	.name = "qhs_ufs_mem_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_usb3_0 = {
	.name = "qhs_usb3_0",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_venus_cfg = {
	.name = "qhs_venus_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_vsense_ctrl_cfg = {
	.name = "qhs_vsense_ctrl_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qns_ddrss_cfg = {
	.name = "qns_ddrss_cfg",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qxs_imem = {
	.name = "qxs_imem",
	.channels = 1,
	.buswidth = 8,
};

static struct qcom_icc_node srvc_cnoc = {
	.name = "srvc_cnoc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node xs_qdss_stm = {
	.name = "xs_qdss_stm",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node xs_sys_tcu_cfg = {
	.name = "xs_sys_tcu_cfg",
	.channels = 1,
	.buswidth = 8,
};

static struct qcom_icc_node qhs_lpass_core = {
	.name = "qhs_lpass_core",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_lpass_lpi = {
	.name = "qhs_lpass_lpi",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_lpass_mpu = {
	.name = "qhs_lpass_mpu",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node qhs_lpass_top = {
	.name = "qhs_lpass_top",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_niu_aml_noc = {
	.name = "srvc_niu_aml_noc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_niu_lpass_agnoc = {
	.name = "srvc_niu_lpass_agnoc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node ebi = {
	.name = "ebi",
	.channels = 4,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_mnoc = {
	.name = "srvc_mnoc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node service_nsp_noc = {
	.name = "service_nsp_noc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_pcie_aggre_noc = {
	.name = "srvc_pcie_aggre_noc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node srvc_snoc = {
	.name = "srvc_snoc",
	.channels = 1,
	.buswidth = 4,
};

static struct qcom_icc_node slv_ddr_rt = {
	.name = "slv_ddr_rt",
	.channels = 4,
	.buswidth = 4,
};

static struct qcom_icc_node qnm_a1noc_cfg = {
	.name = "qnm_a1noc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &srvc_aggre1_noc },
};

static struct qcom_icc_node qnm_a2noc_cfg = {
	.name = "qnm_a2noc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &srvc_aggre2_noc },
};

static struct qcom_icc_node qup0_core_master = {
	.name = "qup0_core_master",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qup0_core_slave },
};

static struct qcom_icc_node qup1_core_master = {
	.name = "qup1_core_master",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qup1_core_slave },
};

static struct qcom_icc_node qhm_config_noc = {
	.name = "qhm_config_noc",
	.channels = 1,
	.buswidth = 4,
	.num_links = 6,
	.link_nodes = { &qhs_lpass_core, &qhs_lpass_lpi, &qhs_lpass_mpu,
			&qhs_lpass_top, &srvc_niu_aml_noc,
			&srvc_niu_lpass_agnoc },
};

static struct qcom_icc_node llcc_mc = {
	.name = "llcc_mc",
	.channels = 4,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &ebi },
};

static struct qcom_icc_node qnm_mnoc_cfg = {
	.name = "qnm_mnoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &srvc_mnoc },
};

static struct qcom_icc_node qhm_nsp_noc_config = {
	.name = "qhm_nsp_noc_config",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &service_nsp_noc },
};

static struct qcom_icc_node qnm_pcie_anoc_cfg = {
	.name = "qnm_pcie_anoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &srvc_pcie_aggre_noc },
};

static struct qcom_icc_node qnm_snoc_cfg = {
	.name = "qnm_snoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &srvc_snoc },
};

static struct qcom_icc_node master_ddr_rt = {
	.name = "master_ddr_rt",
	.channels = 4,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &slv_ddr_rt },
};

static struct qcom_icc_node qhs_compute_cfg = {
	.name = "qhs_compute_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qhm_nsp_noc_config },
};

static struct qcom_icc_node qhs_lpass_cfg = {
	.name = "qhs_lpass_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qhm_config_noc },
};

static struct qcom_icc_node qns_a1_noc_cfg = {
	.name = "qns_a1_noc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qnm_a1noc_cfg },
};

static struct qcom_icc_node qns_a2_noc_cfg = {
	.name = "qns_a2_noc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qnm_a2noc_cfg },
};

static struct qcom_icc_node qns_mnoc_cfg = {
	.name = "qns_mnoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qnm_mnoc_cfg },
};

static struct qcom_icc_node qns_pcie_anoc_cfg = {
	.name = "qns_pcie_anoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qnm_pcie_anoc_cfg },
};

static struct qcom_icc_node qns_snoc_cfg = {
	.name = "qns_snoc_cfg",
	.channels = 1,
	.buswidth = 4,
	.num_links = 1,
	.link_nodes = { &qnm_snoc_cfg },
};

static struct qcom_icc_node qns_llcc = {
	.name = "qns_llcc",
	.channels = 4,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &llcc_mc },
};

static struct qcom_icc_node qnm_gemnoc_cnoc = {
	.name = "qnm_gemnoc_cnoc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 44,
	.link_nodes = { &qhs_ahb2phy0, &qhs_ahb2phy1, &qhs_aoss,
			&qhs_camera_cfg, &qhs_clk_ctl, &qhs_compute_cfg,
			&qhs_cpr_cx, &qhs_cpr_mmcx, &qhs_cpr_mxa, &qhs_cpr_mxc,
			&qhs_crypto0_cfg, &qhs_cx_rdpm, &qhs_display_0_cfg,
			&qhs_display_1_cfg, &qhs_gpuss_cfg, &qhs_imem_cfg,
			&qhs_ipa, &qhs_ipc_router, &qhs_lpass_cfg,
			&qhs_mx_rdpm, &qhs_pdm, &qhs_prng, &qhs_qdss_cfg,
			&qhs_qup0, &qhs_qup1, &qhs_sdc2, &qhs_spss_cfg,
			&qhs_tcsr, &qhs_tlmm, &qhs_tme_cfg, &qhs_ufs_mem_cfg,
			&qhs_usb3_0, &qhs_venus_cfg, &qhs_vsense_ctrl_cfg,
			&qns_a1_noc_cfg, &qns_a2_noc_cfg, &qns_ddrss_cfg,
			&qns_mnoc_cfg, &qns_pcie_anoc_cfg, &qns_snoc_cfg,
			&qxs_imem, &srvc_cnoc, &xs_qdss_stm, &xs_sys_tcu_cfg },
};

static const struct qcom_icc_qosbox qnm_snoc_gc_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa8000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_snoc_gc = {
	.name = "qnm_snoc_gc",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qnm_snoc_gc_qos,
	.num_links = 1,
	.link_nodes = { &qns_llcc },
};

static struct qcom_icc_node qns_gem_noc_cnoc = {
	.name = "qns_gem_noc_cnoc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_gemnoc_cnoc },
};

static struct qcom_icc_node qns_gemnoc_gc = {
	.name = "qns_gemnoc_gc",
	.channels = 1,
	.buswidth = 8,
	.num_links = 1,
	.link_nodes = { &qnm_snoc_gc },
};

static const struct qcom_icc_qosbox alm_gpu_tcu_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa5000 },
	.prio = 6,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node alm_gpu_tcu = {
	.name = "alm_gpu_tcu",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &alm_gpu_tcu_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox alm_sys_tcu_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa6000 },
	.prio = 6,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node alm_sys_tcu = {
	.name = "alm_sys_tcu",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &alm_sys_tcu_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static struct qcom_icc_node chm_apps = {
	.name = "chm_apps",
	.channels = 2,
	.buswidth = 32,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_gpu_qos = {
	.num_ports = 2,
	.port_offsets = { 0x19000, 0x59000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_gpu = {
	.name = "qnm_gpu",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_gpu_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_mnoc_hf_qos = {
	.num_ports = 2,
	.port_offsets = { 0x1a000, 0x5a000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_mnoc_hf = {
	.name = "qnm_mnoc_hf",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_mnoc_hf_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_mnoc_sf_qos = {
	.num_ports = 2,
	.port_offsets = { 0x1b000, 0x5b000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_mnoc_sf = {
	.name = "qnm_mnoc_sf",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_mnoc_sf_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_nsp_gemnoc_qos = {
	.num_ports = 2,
	.port_offsets = { 0x1c000, 0x5c000 },
	.prio = 0,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_nsp_gemnoc = {
	.name = "qnm_nsp_gemnoc",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_nsp_gemnoc_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_pcie_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa7000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_pcie = {
	.name = "qnm_pcie",
	.channels = 1,
	.buswidth = 16,
	.qosbox = &qnm_pcie_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox qnm_snoc_sf_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa9000 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_snoc_sf = {
	.name = "qnm_snoc_sf",
	.channels = 1,
	.buswidth = 16,
	.qosbox = &qnm_snoc_sf_qos,
	.num_links = 2,
	.link_nodes = { &qns_gem_noc_cnoc, &qns_llcc },
};

static const struct qcom_icc_qosbox xm_gic_qos = {
	.num_ports = 1,
	.port_offsets = { 0x13000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_gic = {
	.name = "xm_gic",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_gic_qos,
	.num_links = 1,
	.link_nodes = { &qns_gemnoc_gc },
};

static struct qcom_icc_node qns_mem_noc_hf = {
	.name = "qns_mem_noc_hf",
	.channels = 2,
	.buswidth = 32,
	.num_links = 1,
	.link_nodes = { &qnm_mnoc_hf },
};

static struct qcom_icc_node qns_mem_noc_sf = {
	.name = "qns_mem_noc_sf",
	.channels = 2,
	.buswidth = 32,
	.num_links = 1,
	.link_nodes = { &qnm_mnoc_sf },
};

static struct qcom_icc_node qns_nsp_gemnoc = {
	.name = "qns_nsp_gemnoc",
	.channels = 2,
	.buswidth = 32,
	.num_links = 1,
	.link_nodes = { &qnm_nsp_gemnoc },
};

static struct qcom_icc_node qns_pcie_mem_noc = {
	.name = "qns_pcie_mem_noc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_pcie },
};

static struct qcom_icc_node qns_gemnoc_sf = {
	.name = "qns_gemnoc_sf",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_snoc_sf },
};

static const struct qcom_icc_qosbox qnm_camnoc_hf_qos = {
	.num_ports = 2,
	.port_offsets = { 0x15000, 0x15080 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_camnoc_hf = {
	.name = "qnm_camnoc_hf",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_camnoc_hf_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_hf },
};

static const struct qcom_icc_qosbox qnm_camnoc_icp_qos = {
	.num_ports = 1,
	.port_offsets = { 0x16000 },
	.prio = 4,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_camnoc_icp = {
	.name = "qnm_camnoc_icp",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qnm_camnoc_icp_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_camnoc_sf_qos = {
	.num_ports = 2,
	.port_offsets = { 0x17000, 0x17080 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_camnoc_sf = {
	.name = "qnm_camnoc_sf",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_camnoc_sf_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_mdp0_qos = {
	.num_ports = 2,
	.port_offsets = { 0x1b000, 0x1b080 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_mdp0 = {
	.name = "qnm_mdp0",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_mdp0_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_hf },
};

static const struct qcom_icc_qosbox qnm_mdp1_qos = {
	.num_ports = 2,
	.port_offsets = { 0x1c000, 0x1c080 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_mdp1 = {
	.name = "qnm_mdp1",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_mdp1_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_hf },
};

static struct qcom_icc_node qnm_vapss_hcp = {
	.name = "qnm_vapss_hcp",
	.channels = 1,
	.buswidth = 32,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_video_qos = {
	.num_ports = 2,
	.port_offsets = { 0x19000, 0x19080 },
	.prio = 0,
	.urg_fwd = 1,
};

static struct qcom_icc_node qnm_video = {
	.name = "qnm_video",
	.channels = 2,
	.buswidth = 32,
	.qosbox = &qnm_video_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_video_cv_cpu_qos = {
	.num_ports = 1,
	.port_offsets = { 0x1a080 },
	.prio = 4,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_video_cv_cpu = {
	.name = "qnm_video_cv_cpu",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qnm_video_cv_cpu_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_video_cvp_qos = {
	.num_ports = 1,
	.port_offsets = { 0x1a000 },
	.prio = 4,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_video_cvp = {
	.name = "qnm_video_cvp",
	.channels = 1,
	.buswidth = 32,
	.qosbox = &qnm_video_cvp_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static const struct qcom_icc_qosbox qnm_video_v_cpu_qos = {
	.num_ports = 1,
	.port_offsets = { 0x1a100 },
	.prio = 4,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_video_v_cpu = {
	.name = "qnm_video_v_cpu",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qnm_video_v_cpu_qos,
	.num_links = 1,
	.link_nodes = { &qns_mem_noc_sf },
};

static struct qcom_icc_node qxm_nsp = {
	.name = "qxm_nsp",
	.channels = 2,
	.buswidth = 32,
	.num_links = 1,
	.link_nodes = { &qns_nsp_gemnoc },
};

static const struct qcom_icc_qosbox xm_pcie3_0_qos = {
	.num_ports = 1,
	.port_offsets = { 0xa000 },
	.prio = 3,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_pcie3_0 = {
	.name = "xm_pcie3_0",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_pcie3_0_qos,
	.num_links = 1,
	.link_nodes = { &qns_pcie_mem_noc },
};

static const struct qcom_icc_qosbox xm_pcie3_1_qos = {
	.num_ports = 1,
	.port_offsets = { 0xb000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_pcie3_1 = {
	.name = "xm_pcie3_1",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_pcie3_1_qos,
	.num_links = 1,
	.link_nodes = { &qns_pcie_mem_noc },
};

static const struct qcom_icc_qosbox xm_pcie4_0_qos = {
	.num_ports = 1,
	.port_offsets = { 0xc000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_pcie4_0 = {
	.name = "xm_pcie4_0",
	.channels = 1,
	.buswidth = 16,
	.qosbox = &xm_pcie4_0_qos,
	.num_links = 1,
	.link_nodes = { &qns_pcie_mem_noc },
};

static const struct qcom_icc_qosbox qhm_gic_qos = {
	.num_ports = 1,
	.port_offsets = { 0x11000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qhm_gic = {
	.name = "qhm_gic",
	.channels = 1,
	.buswidth = 4,
	.qosbox = &qhm_gic_qos,
	.num_links = 1,
	.link_nodes = { &qns_gemnoc_sf },
};

static struct qcom_icc_node qnm_aggre1_noc = {
	.name = "qnm_aggre1_noc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qns_gemnoc_sf },
};

static struct qcom_icc_node qnm_aggre2_noc = {
	.name = "qnm_aggre2_noc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qns_gemnoc_sf },
};

static const struct qcom_icc_qosbox qnm_lpass_noc_qos = {
	.num_ports = 1,
	.port_offsets = { 0x12000 },
	.prio = 0,
	.urg_fwd = 0,
};

static struct qcom_icc_node qnm_lpass_noc = {
	.name = "qnm_lpass_noc",
	.channels = 1,
	.buswidth = 16,
	.qosbox = &qnm_lpass_noc_qos,
	.num_links = 1,
	.link_nodes = { &qns_gemnoc_sf },
};

static struct qcom_icc_node qns_a1noc_snoc = {
	.name = "qns_a1noc_snoc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_aggre1_noc },
};

static struct qcom_icc_node qns_a2noc_snoc = {
	.name = "qns_a2noc_snoc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_aggre2_noc },
};

static struct qcom_icc_node qns_sysnoc = {
	.name = "qns_sysnoc",
	.channels = 1,
	.buswidth = 16,
	.num_links = 1,
	.link_nodes = { &qnm_lpass_noc },
};

static const struct qcom_icc_qosbox qhm_qup1_qos = {
	.num_ports = 1,
	.port_offsets = { 0x7000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qhm_qup1 = {
	.name = "qhm_qup1",
	.channels = 1,
	.buswidth = 4,
	.qosbox = &qhm_qup1_qos,
	.num_links = 1,
	.link_nodes = { &qns_a1noc_snoc },
};

static const struct qcom_icc_qosbox xm_ufs_mem_qos = {
	.num_ports = 1,
	.port_offsets = { 0x8000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_ufs_mem = {
	.name = "xm_ufs_mem",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_ufs_mem_qos,
	.num_links = 1,
	.link_nodes = { &qns_a1noc_snoc },
};

static const struct qcom_icc_qosbox xm_usb3_0_qos = {
	.num_ports = 1,
	.port_offsets = { 0x9000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_usb3_0 = {
	.name = "xm_usb3_0",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_usb3_0_qos,
	.num_links = 1,
	.link_nodes = { &qns_a1noc_snoc },
};

static const struct qcom_icc_qosbox qhm_qdss_bam_qos = {
	.num_ports = 1,
	.port_offsets = { 0x12000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qhm_qdss_bam = {
	.name = "qhm_qdss_bam",
	.channels = 1,
	.buswidth = 4,
	.qosbox = &qhm_qdss_bam_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox qhm_qup0_qos = {
	.num_ports = 1,
	.port_offsets = { 0x13000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qhm_qup0 = {
	.name = "qhm_qup0",
	.channels = 1,
	.buswidth = 4,
	.qosbox = &qhm_qup0_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox qnm_cnoc_datapath_qos = {
	.num_ports = 1,
	.port_offsets = { 0x14000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qnm_cnoc_datapath = {
	.name = "qnm_cnoc_datapath",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qnm_cnoc_datapath_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox qxm_crypto_qos = {
	.num_ports = 1,
	.port_offsets = { 0x15000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qxm_crypto = {
	.name = "qxm_crypto",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qxm_crypto_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox qxm_ipa_qos = {
	.num_ports = 1,
	.port_offsets = { 0xe000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node qxm_ipa = {
	.name = "qxm_ipa",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &qxm_ipa_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static struct qcom_icc_node qxm_sp = {
	.name = "qxm_sp",
	.channels = 1,
	.buswidth = 8,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox xm_qdss_etr_0_qos = {
	.num_ports = 1,
	.port_offsets = { 0x10000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_qdss_etr_0 = {
	.name = "xm_qdss_etr_0",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_qdss_etr_0_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox xm_qdss_etr_1_qos = {
	.num_ports = 1,
	.port_offsets = { 0xd000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_qdss_etr_1 = {
	.name = "xm_qdss_etr_1",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_qdss_etr_1_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static const struct qcom_icc_qosbox xm_sdc2_qos = {
	.num_ports = 1,
	.port_offsets = { 0x11000 },
	.prio = 2,
	.urg_fwd = 0,
	.prio_fwd_disable = 1,
};

static struct qcom_icc_node xm_sdc2 = {
	.name = "xm_sdc2",
	.channels = 1,
	.buswidth = 8,
	.qosbox = &xm_sdc2_qos,
	.num_links = 1,
	.link_nodes = { &qns_a2noc_snoc },
};

static struct qcom_icc_node qxm_lpass_dsp = {
	.name = "qxm_lpass_dsp",
	.channels = 1,
	.buswidth = 8,
	.num_links = 4,
	.link_nodes = { &qhs_lpass_top, &qns_sysnoc, &srvc_niu_aml_noc,
			&srvc_niu_lpass_agnoc },
};

static struct qcom_icc_node qns_cnoc_a2noc = {
	.name = "qns_cnoc_a2noc",
	.channels = 1,
	.buswidth = 8,
	.num_links = 1,
	.link_nodes = { &qnm_cnoc_datapath },
};

static struct qcom_icc_node xm_qdss_dap = {
	.name = "xm_qdss_dap",
	.channels = 1,
	.buswidth = 8,
	.num_links = 45,
	.link_nodes = { &qhs_ahb2phy0, &qhs_ahb2phy1, &qhs_aoss,
			&qhs_camera_cfg, &qhs_clk_ctl, &qhs_compute_cfg,
			&qhs_cpr_cx, &qhs_cpr_mmcx, &qhs_cpr_mxa, &qhs_cpr_mxc,
			&qhs_crypto0_cfg, &qhs_cx_rdpm, &qhs_display_0_cfg,
			&qhs_display_1_cfg, &qhs_gpuss_cfg, &qhs_imem_cfg,
			&qhs_ipa, &qhs_ipc_router, &qhs_lpass_cfg,
			&qhs_mx_rdpm, &qhs_pdm, &qhs_prng, &qhs_qdss_cfg,
			&qhs_qup0, &qhs_qup1, &qhs_sdc2, &qhs_spss_cfg,
			&qhs_tcsr, &qhs_tlmm, &qhs_tme_cfg, &qhs_ufs_mem_cfg,
			&qhs_usb3_0, &qhs_venus_cfg, &qhs_vsense_ctrl_cfg,
			&qns_a1_noc_cfg, &qns_a2_noc_cfg, &qns_cnoc_a2noc,
			&qns_ddrss_cfg, &qns_mnoc_cfg, &qns_pcie_anoc_cfg,
			&qns_snoc_cfg, &qxs_imem, &srvc_cnoc, &xs_qdss_stm,
			&xs_sys_tcu_cfg },
};

static struct qcom_icc_bcm bcm_acv = {
	.name = "ACV",
	.enable_mask = 0x8,
	.num_nodes = 1,
	.nodes = { &ebi },
};

static struct qcom_icc_bcm bcm_ce0 = {
	.name = "CE0",
	.num_nodes = 1,
	.nodes = { &qxm_crypto },
};

static struct qcom_icc_bcm bcm_cn0 = {
	.name = "CN0",
	.enable_mask = 0x1,
	.keepalive = true,
	.num_nodes = 47,
	.nodes = { &qnm_gemnoc_cnoc, &xm_qdss_dap, &qhs_ahb2phy0,
		   &qhs_ahb2phy1, &qhs_aoss, &qhs_camera_cfg, &qhs_clk_ctl,
		   &qhs_compute_cfg, &qhs_cpr_cx, &qhs_cpr_mmcx, &qhs_cpr_mxa,
		   &qhs_cpr_mxc, &qhs_crypto0_cfg, &qhs_cx_rdpm,
		   &qhs_display_0_cfg, &qhs_display_1_cfg, &qhs_gpuss_cfg,
		   &qhs_imem_cfg, &qhs_ipa, &qhs_ipc_router, &qhs_lpass_cfg,
		   &qhs_mx_rdpm, &qhs_pdm, &qhs_prng, &qhs_qdss_cfg, &qhs_qup0,
		   &qhs_qup1, &qhs_sdc2, &qhs_spss_cfg, &qhs_tcsr, &qhs_tlmm,
		   &qhs_tme_cfg, &qhs_ufs_mem_cfg, &qhs_usb3_0, &qhs_venus_cfg,
		   &qhs_vsense_ctrl_cfg, &qns_a1_noc_cfg, &qns_a2_noc_cfg,
		   &qns_cnoc_a2noc, &qns_ddrss_cfg, &qns_mnoc_cfg,
		   &qns_pcie_anoc_cfg, &qns_snoc_cfg, &qxs_imem, &srvc_cnoc,
		   &xs_qdss_stm, &xs_sys_tcu_cfg },
};

static struct qcom_icc_bcm bcm_co0 = {
	.name = "CO0",
	.enable_mask = 0x1,
	.num_nodes = 2,
	.nodes = { &qxm_nsp, &qns_nsp_gemnoc },
};

static struct qcom_icc_bcm bcm_mc0 = {
	.name = "MC0",
	.keepalive = true,
	.num_nodes = 1,
	.nodes = { &ebi },
};

static struct qcom_icc_bcm bcm_mc4 = {
	.name = "MC4",
	.num_nodes = 1,
	.nodes = { &slv_ddr_rt },
};

static struct qcom_icc_bcm bcm_mm0 = {
	.name = "MM0",
	.num_nodes = 3,
	.nodes = { &qnm_mdp0, &qnm_mdp1, &qns_mem_noc_hf },
};

static struct qcom_icc_bcm bcm_mm1 = {
	.name = "MM1",
	.enable_mask = 0x1,
	.num_nodes = 10,
	.nodes = { &qnm_camnoc_hf, &qnm_camnoc_icp, &qnm_camnoc_sf,
		   &qnm_mnoc_cfg, &qnm_vapss_hcp, &qnm_video,
		   &qnm_video_cv_cpu, &qnm_video_cvp, &qnm_video_v_cpu,
		   &qns_mem_noc_sf },
};

static struct qcom_icc_bcm bcm_qup0 = {
	.name = "QUP0",
	.keepalive = true,
	.vote_scale = 1,
	.num_nodes = 1,
	.nodes = { &qup0_core_slave },
};

static struct qcom_icc_bcm bcm_qup1 = {
	.name = "QUP1",
	.keepalive = true,
	.vote_scale = 1,
	.num_nodes = 1,
	.nodes = { &qup1_core_slave },
};

static struct qcom_icc_bcm bcm_sh0 = {
	.name = "SH0",
	.keepalive = true,
	.num_nodes = 1,
	.nodes = { &qns_llcc },
};

static struct qcom_icc_bcm bcm_sh1 = {
	.name = "SH1",
	.enable_mask = 0x1,
	.num_nodes = 6,
	.nodes = { &alm_gpu_tcu, &alm_sys_tcu, &qnm_nsp_gemnoc, &qnm_pcie,
		   &qnm_snoc_gc, &qns_gem_noc_cnoc },
};

static struct qcom_icc_bcm bcm_sn0 = {
	.name = "SN0",
	.keepalive = true,
	.num_nodes = 1,
	.nodes = { &qns_gemnoc_sf },
};

static struct qcom_icc_bcm bcm_sn1 = {
	.name = "SN1",
	.enable_mask = 0x1,
	.num_nodes = 3,
	.nodes = { &qhm_gic, &xm_gic, &qns_gemnoc_gc },
};

static struct qcom_icc_bcm bcm_sn2 = {
	.name = "SN2",
	.num_nodes = 1,
	.nodes = { &qnm_aggre1_noc },
};

static struct qcom_icc_bcm bcm_sn3 = {
	.name = "SN3",
	.num_nodes = 1,
	.nodes = { &qnm_aggre2_noc },
};

static struct qcom_icc_bcm bcm_sn4 = {
	.name = "SN4",
	.num_nodes = 2,
	.nodes = { &qxm_lpass_dsp, &qnm_lpass_noc },
};

static struct qcom_icc_bcm bcm_sn7 = {
	.name = "SN7",
	.num_nodes = 1,
	.nodes = { &qns_pcie_mem_noc },
};

static struct qcom_icc_bcm * const aggre1_noc_bcms[] = {
};

static struct qcom_icc_node * const aggre1_noc_nodes[] = {
	[MASTER_QUP_1] = &qhm_qup1,
	[MASTER_A1NOC_CFG] = &qnm_a1noc_cfg,
	[MASTER_UFS_MEM] = &xm_ufs_mem,
	[MASTER_USB3_0] = &xm_usb3_0,
	[SLAVE_A1NOC_SNOC] = &qns_a1noc_snoc,
	[SLAVE_SERVICE_A1NOC] = &srvc_aggre1_noc,
};

static const struct regmap_config halliday_aggre1_noc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x9080,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_aggre1_noc = {
	.config = &halliday_aggre1_noc_regmap_config,
	.nodes = aggre1_noc_nodes,
	.num_nodes = ARRAY_SIZE(aggre1_noc_nodes),
	.bcms = aggre1_noc_bcms,
	.num_bcms = ARRAY_SIZE(aggre1_noc_bcms),
	.qos_requires_clocks = true,
};

static struct qcom_icc_bcm * const aggre2_noc_bcms[] = {
	&bcm_ce0,
};

static struct qcom_icc_node * const aggre2_noc_nodes[] = {
	[MASTER_QDSS_BAM] = &qhm_qdss_bam,
	[MASTER_QUP_0] = &qhm_qup0,
	[MASTER_A2NOC_CFG] = &qnm_a2noc_cfg,
	[MASTER_CNOC_A2NOC] = &qnm_cnoc_datapath,
	[MASTER_CRYPTO] = &qxm_crypto,
	[MASTER_IPA] = &qxm_ipa,
	[MASTER_SP] = &qxm_sp,
	[MASTER_QDSS_ETR] = &xm_qdss_etr_0,
	[MASTER_QDSS_ETR_1] = &xm_qdss_etr_1,
	[MASTER_SDCC_2] = &xm_sdc2,
	[SLAVE_A2NOC_SNOC] = &qns_a2noc_snoc,
	[SLAVE_SERVICE_A2NOC] = &srvc_aggre2_noc,
};

static const struct regmap_config halliday_aggre2_noc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x15080,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_aggre2_noc = {
	.config = &halliday_aggre2_noc_regmap_config,
	.nodes = aggre2_noc_nodes,
	.num_nodes = ARRAY_SIZE(aggre2_noc_nodes),
	.bcms = aggre2_noc_bcms,
	.num_bcms = ARRAY_SIZE(aggre2_noc_bcms),
	.qos_requires_clocks = true,
};

static struct qcom_icc_bcm * const clk_virt_bcms[] = {
	&bcm_qup0,
	&bcm_qup1,
};

static struct qcom_icc_node * const clk_virt_nodes[] = {
	[MASTER_QUP_CORE_0] = &qup0_core_master,
	[MASTER_QUP_CORE_1] = &qup1_core_master,
	[SLAVE_QUP_CORE_0] = &qup0_core_slave,
	[SLAVE_QUP_CORE_1] = &qup1_core_slave,
};

static const struct qcom_icc_desc halliday_clk_virt = {
	.nodes = clk_virt_nodes,
	.num_nodes = ARRAY_SIZE(clk_virt_nodes),
	.bcms = clk_virt_bcms,
	.num_bcms = ARRAY_SIZE(clk_virt_bcms),
};

static struct qcom_icc_bcm * const config_noc_bcms[] = {
	&bcm_cn0,
};

static struct qcom_icc_node * const config_noc_nodes[] = {
	[MASTER_GEM_NOC_CNOC] = &qnm_gemnoc_cnoc,
	[MASTER_QDSS_DAP] = &xm_qdss_dap,
	[SLAVE_AHB2PHY_SOUTH] = &qhs_ahb2phy0,
	[SLAVE_AHB2PHY_NORTH] = &qhs_ahb2phy1,
	[SLAVE_AOSS] = &qhs_aoss,
	[SLAVE_CAMERA_CFG] = &qhs_camera_cfg,
	[SLAVE_CLK_CTL] = &qhs_clk_ctl,
	[SLAVE_CDSP_CFG] = &qhs_compute_cfg,
	[SLAVE_RBCPR_CX_CFG] = &qhs_cpr_cx,
	[SLAVE_RBCPR_MMCX_CFG] = &qhs_cpr_mmcx,
	[SLAVE_RBCPR_MXA_CFG] = &qhs_cpr_mxa,
	[SLAVE_RBCPR_MXC_CFG] = &qhs_cpr_mxc,
	[SLAVE_CRYPTO_0_CFG] = &qhs_crypto0_cfg,
	[SLAVE_CX_RDPM] = &qhs_cx_rdpm,
	[SLAVE_DISPLAY_CFG] = &qhs_display_0_cfg,
	[SLAVE_DISPLAY1_CFG] = &qhs_display_1_cfg,
	[SLAVE_GFX3D_CFG] = &qhs_gpuss_cfg,
	[SLAVE_IMEM_CFG] = &qhs_imem_cfg,
	[SLAVE_IPA_CFG] = &qhs_ipa,
	[SLAVE_IPC_ROUTER_CFG] = &qhs_ipc_router,
	[SLAVE_LPASS] = &qhs_lpass_cfg,
	[SLAVE_MX_RDPM] = &qhs_mx_rdpm,
	[SLAVE_PDM] = &qhs_pdm,
	[SLAVE_PRNG] = &qhs_prng,
	[SLAVE_QDSS_CFG] = &qhs_qdss_cfg,
	[SLAVE_QUP_0] = &qhs_qup0,
	[SLAVE_QUP_1] = &qhs_qup1,
	[SLAVE_SDCC_2] = &qhs_sdc2,
	[SLAVE_SPSS_CFG] = &qhs_spss_cfg,
	[SLAVE_TCSR] = &qhs_tcsr,
	[SLAVE_TLMM] = &qhs_tlmm,
	[SLAVE_TME_CFG] = &qhs_tme_cfg,
	[SLAVE_UFS_MEM_CFG] = &qhs_ufs_mem_cfg,
	[SLAVE_USB3_0] = &qhs_usb3_0,
	[SLAVE_VENUS_CFG] = &qhs_venus_cfg,
	[SLAVE_VSENSE_CTRL_CFG] = &qhs_vsense_ctrl_cfg,
	[SLAVE_A1NOC_CFG] = &qns_a1_noc_cfg,
	[SLAVE_A2NOC_CFG] = &qns_a2_noc_cfg,
	[SLAVE_CNOC_A2NOC] = &qns_cnoc_a2noc,
	[SLAVE_DDRSS_CFG] = &qns_ddrss_cfg,
	[SLAVE_CNOC_MNOC_CFG] = &qns_mnoc_cfg,
	[SLAVE_PCIE_ANOC_CFG] = &qns_pcie_anoc_cfg,
	[SLAVE_SNOC_CFG] = &qns_snoc_cfg,
	[SLAVE_IMEM] = &qxs_imem,
	[SLAVE_SERVICE_CNOC] = &srvc_cnoc,
	[SLAVE_QDSS_STM] = &xs_qdss_stm,
	[SLAVE_TCU] = &xs_sys_tcu_cfg,
};

static const struct qcom_icc_desc halliday_config_noc = {
	.nodes = config_noc_nodes,
	.num_nodes = ARRAY_SIZE(config_noc_nodes),
	.bcms = config_noc_bcms,
	.num_bcms = ARRAY_SIZE(config_noc_bcms),
};

static struct qcom_icc_bcm * const gem_noc_bcms[] = {
	&bcm_sh0,
	&bcm_sh1,
};

static struct qcom_icc_node * const gem_noc_nodes[] = {
	[MASTER_GPU_TCU] = &alm_gpu_tcu,
	[MASTER_SYS_TCU] = &alm_sys_tcu,
	[MASTER_APPSS_PROC] = &chm_apps,
	[MASTER_GFX3D] = &qnm_gpu,
	[MASTER_MNOC_HF_MEM_NOC] = &qnm_mnoc_hf,
	[MASTER_MNOC_SF_MEM_NOC] = &qnm_mnoc_sf,
	[MASTER_COMPUTE_NOC] = &qnm_nsp_gemnoc,
	[MASTER_ANOC_PCIE_GEM_NOC] = &qnm_pcie,
	[MASTER_SNOC_GC_MEM_NOC] = &qnm_snoc_gc,
	[MASTER_SNOC_SF_MEM_NOC] = &qnm_snoc_sf,
	[SLAVE_GEM_NOC_CNOC] = &qns_gem_noc_cnoc,
	[SLAVE_LLCC] = &qns_llcc,
};

static const struct regmap_config halliday_gem_noc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0xa9080,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_gem_noc = {
	.config = &halliday_gem_noc_regmap_config,
	.nodes = gem_noc_nodes,
	.num_nodes = ARRAY_SIZE(gem_noc_nodes),
	.bcms = gem_noc_bcms,
	.num_bcms = ARRAY_SIZE(gem_noc_bcms),
};

static struct qcom_icc_bcm * const lpass_ag_noc_bcms[] = {
	&bcm_sn4,
};

static struct qcom_icc_node * const lpass_ag_noc_nodes[] = {
	[MASTER_CNOC_LPASS_AG_NOC] = &qhm_config_noc,
	[MASTER_LPASS_PROC] = &qxm_lpass_dsp,
	[SLAVE_LPASS_CORE_CFG] = &qhs_lpass_core,
	[SLAVE_LPASS_LPI_CFG] = &qhs_lpass_lpi,
	[SLAVE_LPASS_MPU_CFG] = &qhs_lpass_mpu,
	[SLAVE_LPASS_TOP_CFG] = &qhs_lpass_top,
	[SLAVE_LPASS_SNOC] = &qns_sysnoc,
	[SLAVE_SERVICES_LPASS_AML_NOC] = &srvc_niu_aml_noc,
	[SLAVE_SERVICE_LPASS_AG_NOC] = &srvc_niu_lpass_agnoc,
};

static const struct qcom_icc_desc halliday_lpass_ag_noc = {
	.nodes = lpass_ag_noc_nodes,
	.num_nodes = ARRAY_SIZE(lpass_ag_noc_nodes),
	.bcms = lpass_ag_noc_bcms,
	.num_bcms = ARRAY_SIZE(lpass_ag_noc_bcms),
};

static struct qcom_icc_bcm * const mc_virt_bcms[] = {
	&bcm_acv,
	&bcm_mc0,
	&bcm_mc4,
};

static struct qcom_icc_node * const mc_virt_nodes[] = {
	[MASTER_LLCC] = &llcc_mc,
	[SLAVE_EBI1] = &ebi,
	[MASTER_DDR_RT] = &master_ddr_rt,
	[SLAVE_DDR_RT] = &slv_ddr_rt,
};

static const struct qcom_icc_desc halliday_mc_virt = {
	.nodes = mc_virt_nodes,
	.num_nodes = ARRAY_SIZE(mc_virt_nodes),
	.bcms = mc_virt_bcms,
	.num_bcms = ARRAY_SIZE(mc_virt_bcms),
};

static struct qcom_icc_bcm * const mmss_noc_bcms[] = {
	&bcm_mm0,
	&bcm_mm1,
};

static struct qcom_icc_node * const mmss_noc_nodes[] = {
	[MASTER_CAMNOC_HF] = &qnm_camnoc_hf,
	[MASTER_CAMNOC_ICP] = &qnm_camnoc_icp,
	[MASTER_CAMNOC_SF] = &qnm_camnoc_sf,
	[MASTER_MDP0] = &qnm_mdp0,
	[MASTER_MDP1] = &qnm_mdp1,
	[MASTER_CNOC_MNOC_CFG] = &qnm_mnoc_cfg,
	[MASTER_CDSP_HCP] = &qnm_vapss_hcp,
	[MASTER_VIDEO] = &qnm_video,
	[MASTER_VIDEO_CV_PROC] = &qnm_video_cv_cpu,
	[MASTER_VIDEO_PROC] = &qnm_video_cvp,
	[MASTER_VIDEO_V_PROC] = &qnm_video_v_cpu,
	[SLAVE_MNOC_HF_MEM_NOC] = &qns_mem_noc_hf,
	[SLAVE_MNOC_SF_MEM_NOC] = &qns_mem_noc_sf,
	[SLAVE_SERVICE_MNOC] = &srvc_mnoc,
};

static const struct regmap_config halliday_mmss_noc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x1c100,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_mmss_noc = {
	.config = &halliday_mmss_noc_regmap_config,
	.nodes = mmss_noc_nodes,
	.num_nodes = ARRAY_SIZE(mmss_noc_nodes),
	.bcms = mmss_noc_bcms,
	.num_bcms = ARRAY_SIZE(mmss_noc_bcms),
};

static struct qcom_icc_bcm * const nsp_noc_bcms[] = {
	&bcm_co0,
};

static struct qcom_icc_node * const nsp_noc_nodes[] = {
	[MASTER_CDSP_NOC_CFG] = &qhm_nsp_noc_config,
	[MASTER_CDSP_PROC] = &qxm_nsp,
	[SLAVE_CDSP_MEM_NOC] = &qns_nsp_gemnoc,
	[SLAVE_SERVICE_NSP_NOC] = &service_nsp_noc,
};

static const struct qcom_icc_desc halliday_nsp_noc = {
	.nodes = nsp_noc_nodes,
	.num_nodes = ARRAY_SIZE(nsp_noc_nodes),
	.bcms = nsp_noc_bcms,
	.num_bcms = ARRAY_SIZE(nsp_noc_bcms),
};

static struct qcom_icc_bcm * const pcie_anoc_bcms[] = {
	&bcm_sn7,
};

static struct qcom_icc_node * const pcie_anoc_nodes[] = {
	[MASTER_PCIE_ANOC_CFG] = &qnm_pcie_anoc_cfg,
	[MASTER_PCIE_0] = &xm_pcie3_0,
	[MASTER_PCIE_1] = &xm_pcie3_1,
	[MASTER_PCIE_4] = &xm_pcie4_0,
	[SLAVE_ANOC_PCIE_GEM_NOC] = &qns_pcie_mem_noc,
	[SLAVE_SERVICE_PCIE_ANOC] = &srvc_pcie_aggre_noc,
};

static const struct regmap_config halliday_pcie_anoc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0xc080,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_pcie_anoc = {
	.config = &halliday_pcie_anoc_regmap_config,
	.nodes = pcie_anoc_nodes,
	.num_nodes = ARRAY_SIZE(pcie_anoc_nodes),
	.bcms = pcie_anoc_bcms,
	.num_bcms = ARRAY_SIZE(pcie_anoc_bcms),
	.qos_requires_clocks = true,
};

static struct qcom_icc_bcm * const system_noc_bcms[] = {
	&bcm_sn0,
	&bcm_sn1,
	&bcm_sn2,
	&bcm_sn3,
	&bcm_sn4,
};

static struct qcom_icc_node * const system_noc_nodes[] = {
	[MASTER_GIC_AHB] = &qhm_gic,
	[MASTER_A1NOC_SNOC] = &qnm_aggre1_noc,
	[MASTER_A2NOC_SNOC] = &qnm_aggre2_noc,
	[MASTER_LPASS_ANOC] = &qnm_lpass_noc,
	[MASTER_SNOC_CFG] = &qnm_snoc_cfg,
	[MASTER_GIC] = &xm_gic,
	[SLAVE_SNOC_GEM_NOC_GC] = &qns_gemnoc_gc,
	[SLAVE_SNOC_GEM_NOC_SF] = &qns_gemnoc_sf,
	[SLAVE_SERVICE_SNOC] = &srvc_snoc,
};

static const struct regmap_config halliday_system_noc_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x13080,
	.fast_io = true,
};

static const struct qcom_icc_desc halliday_system_noc = {
	.config = &halliday_system_noc_regmap_config,
	.nodes = system_noc_nodes,
	.num_nodes = ARRAY_SIZE(system_noc_nodes),
	.bcms = system_noc_bcms,
	.num_bcms = ARRAY_SIZE(system_noc_bcms),
};

static const struct of_device_id qnoc_of_match[] = {
	{ .compatible = "qcom,halliday-aggre1-noc", .data = &halliday_aggre1_noc },
	{ .compatible = "qcom,halliday-aggre2-noc", .data = &halliday_aggre2_noc },
	{ .compatible = "qcom,halliday-clk-virt", .data = &halliday_clk_virt },
	{ .compatible = "qcom,halliday-config-noc", .data = &halliday_config_noc },
	{ .compatible = "qcom,halliday-gem-noc", .data = &halliday_gem_noc },
	{ .compatible = "qcom,halliday-lpass-ag-noc", .data = &halliday_lpass_ag_noc },
	{ .compatible = "qcom,halliday-mc-virt", .data = &halliday_mc_virt },
	{ .compatible = "qcom,halliday-mmss-noc", .data = &halliday_mmss_noc },
	{ .compatible = "qcom,halliday-nsp-noc", .data = &halliday_nsp_noc },
	{ .compatible = "qcom,halliday-pcie-anoc", .data = &halliday_pcie_anoc },
	{ .compatible = "qcom,halliday-system-noc", .data = &halliday_system_noc },
	{ }
};
MODULE_DEVICE_TABLE(of, qnoc_of_match);

static struct platform_driver qnoc_driver = {
	.probe = qcom_icc_rpmh_probe,
	.remove = qcom_icc_rpmh_remove,
	.driver = {
		.name = "qnoc-halliday",
		.of_match_table = qnoc_of_match,
		.sync_state = icc_sync_state,
	},
};

static int __init qnoc_driver_init(void)
{
	return platform_driver_register(&qnoc_driver);
}
core_initcall(qnoc_driver_init);

static void __exit qnoc_driver_exit(void)
{
	platform_driver_unregister(&qnoc_driver);
}
module_exit(qnoc_driver_exit);

MODULE_DESCRIPTION("Qualcomm Halliday NoC driver");
MODULE_LICENSE("GPL");
