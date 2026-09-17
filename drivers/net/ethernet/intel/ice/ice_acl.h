/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2026, Intel Corporation. */

#ifndef _ICE_ACL_H_
#define _ICE_ACL_H_

#include "ice_common.h"

#define ICE_ACL_TBL_PARAMS_DEP_TBLS_MAX	15
struct ice_acl_tbl_params {
	u16 width;	/* Select/match bytes */
	u16 depth;	/* Number of entries */
	u16 dep_tbls[ICE_ACL_TBL_PARAMS_DEP_TBLS_MAX];
	u8 num_dep_tbls;	/* Number of valid entries in dep_tbls */
	u8 entry_act_pairs;	/* Action pairs per entry */
	u8 concurr;		/* Concurrent table lookup enable */
};

#define ICE_ACL_ACT_MEM_ACT_MEM_INVAL	0xff
struct ice_acl_act_mem {
	u8 act_mem;
	u8 member_of_tcam;
};

struct ice_acl_tbl {
	/* TCAM configuration */
	u8 first_tcam;
	u8 last_tcam;
	u16 first_entry; /* Index of the first entry in the first TCAM */
	u16 last_entry; /* Index of the last entry in the last TCAM */
	u16 id;

	/* List of active scenarios */
	struct list_head scens;

	struct ice_acl_tbl_params info;
	struct ice_acl_act_mem act_mems[ICE_AQC_MAX_ACTION_MEMORIES];

	/* Keep track of available 64-entry chunks in TCAMs */
	DECLARE_BITMAP(avail, ICE_AQC_ACL_ALLOC_UNITS);
};

enum ice_acl_entry_prio {
	ICE_ACL_PRIO_LOW = 0,
	ICE_ACL_PRIO_NORMAL,
	ICE_ACL_PRIO_HIGH,
	ICE_ACL_MAX_PRIO
};

#define ICE_ACL_SCEN_MIN_WIDTH	0x3
#define ICE_ACL_SCEN_PKT_DIR_IDX_IN_TCAM	0x2
#define ICE_ACL_SCEN_PID_IDX_IN_TCAM		0x3
#define ICE_ACL_SCEN_RNG_CHK_IDX_IN_TCAM	0x4
/* Scenario structure
 * A scenario is a logical partition within an ACL table. It can span more
 * than one TCAM in cascade mode to support select/mask key widths larger
 * than the width of a TCAM. It can also span more than one TCAM in stacked
 * mode to support larger number of entries than what a TCAM can hold. It is
 * used to select values from selection bases (field vectors holding extract
 * protocol header fields) to form lookup keys, and to associate action memory
 * banks to the TCAMs used.
 */
struct ice_acl_scen {
	struct list_head list_entry;
	/* If nth bit of act_mem_bitmap is set, then nth action memory will
	 * participate in this scenario
	 */
	DECLARE_BITMAP(act_mem_bitmap, ICE_AQC_MAX_ACTION_MEMORIES);
	u16 first_idx[ICE_ACL_MAX_PRIO];
	u16 last_idx[ICE_ACL_MAX_PRIO];

	u16 id;
	u16 start;	/* Number of entry from the start of the parent table */
	u16 width;	/* Number of select/mask bytes */
	u16 num_entry;	/* Number of scenario entry */
	u16 end;	/* Last addressable entry from start of table */
	u8 eff_width;	/* Available width in bytes to match */
	u8 pid_idx;	/* Byte index used to match profile ID */
	u8 rng_chk_idx;	/* Byte index used to match range checkers result */
	u8 pkt_dir_idx;	/* Byte index used to match packet direction */
};

/* Input fields needed to allocate ACL table */
struct ice_acl_alloc_tbl {
	/* Table's width in number of bytes matched */
	u16 width;
	/* Table's depth in number of entries. */
	u16 depth;
	u8 num_dependent_alloc_ids;
	/* true for concurrent table type */
	u8 concurr;

	/* Amount of action pairs per table entry. Minimal valid
	 * value for this field is 1 (e.g. single pair of actions)
	 */
	u8 act_pairs_per_entry;
	union {
		struct ice_aqc_acl_alloc_table_data data_buf;
		struct ice_aqc_acl_generic resp_buf;
	} buf;
};

int ice_acl_create_tbl(struct ice_hw *hw, struct ice_acl_tbl_params *params);
int ice_acl_destroy_tbl(struct ice_hw *hw);
int ice_aq_alloc_acl_tbl(struct ice_hw *hw, struct ice_acl_alloc_tbl *tbl,
			 struct ice_sq_cd *cd);
int ice_aq_dealloc_acl_tbl(struct ice_hw *hw, u16 alloc_id,
			   struct ice_aqc_acl_generic *buf,
			   struct ice_sq_cd *cd);
int ice_aq_program_acl_entry(struct ice_hw *hw, u8 tcam_idx, u16 entry_idx,
			     struct ice_aqc_acl_data *buf,
			     struct ice_sq_cd *cd);
int ice_aq_program_actpair(struct ice_hw *hw, u8 act_mem_idx, u16 act_entry_idx,
			   struct ice_aqc_actpair *buf, struct ice_sq_cd *cd);
int ice_aq_alloc_acl_scen(struct ice_hw *hw, u16 *scen_id,
			  struct ice_aqc_acl_scen *buf, struct ice_sq_cd *cd);

#endif /* _ICE_ACL_H_ */
