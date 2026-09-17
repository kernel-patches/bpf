// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2026, Intel Corporation. */

#include "ice_acl.h"

/* Determine the TCAM index of entry 'e' within the ACL table */
#define ICE_ACL_TBL_TCAM_IDX(e) ((e) / ICE_AQC_ACL_TCAM_DEPTH)

/**
 * ice_acl_init_tbl - initialize ACL table
 * @hw: pointer to the hardware structure
 *
 * Invalidate TCAM entries and action pairs.
 *
 * Return: 0 on success, negative on error
 */
static int ice_acl_init_tbl(struct ice_hw *hw)
{
	struct ice_aqc_actpair act_buf = {};
	struct ice_aqc_acl_data buf = {};
	struct ice_acl_tbl *tbl;
	u8 tcam_idx;
	int err = 0;
	u16 idx;

	tbl = hw->acl_tbl;

	tcam_idx = tbl->first_tcam;
	idx = tbl->first_entry;
	while (tcam_idx < tbl->last_tcam ||
	       (tcam_idx == tbl->last_tcam && idx <= tbl->last_entry)) {
		/* Use the same value for entry_key and entry_key_inv since
		 * we are initializing the fields to 0
		 */
		err = ice_aq_program_acl_entry(hw, tcam_idx, idx, &buf, NULL);
		if (err)
			return err;

		if (++idx > tbl->last_entry) {
			tcam_idx++;
			idx = tbl->first_entry;
		}
	}

	for (int i = 0; i < ICE_AQC_MAX_ACTION_MEMORIES; i++) {
		u16 act_entry_idx;

		if (tbl->act_mems[i].act_mem == ICE_ACL_ACT_MEM_ACT_MEM_INVAL)
			continue;

		for (act_entry_idx = tbl->first_entry;
		     act_entry_idx <= tbl->last_entry; act_entry_idx++) {
			/* Invalidate all allocated action pairs */
			err = ice_aq_program_actpair(hw, i, act_entry_idx,
						     &act_buf, NULL);
			if (err)
				return err;
		}
	}

	return err;
}

/**
 * ice_acl_assign_act_mems_to_tcam - assign number of action memories to TCAM
 * @tbl: pointer to ACL table structure
 * @cur_tcam: Index of current TCAM. Value = 0 to (ICE_AQC_ACL_SLICES - 1)
 * @cur_mem_idx: Index of current action memory bank. Value = 0 to
 *		 (ICE_AQC_MAX_ACTION_MEMORIES - 1)
 * @num_mem: Number of action memory banks for this TCAM
 *
 * Assign "num_mem" valid action memory banks from "curr_mem_idx" to
 * "curr_tcam" TCAM.
 */
static void
ice_acl_assign_act_mems_to_tcam(struct ice_acl_tbl *tbl, u8 cur_tcam,
				u8 *cur_mem_idx, u8 num_mem)
{
	u8 mem_cnt;

	for (mem_cnt = 0;
	     *cur_mem_idx < ICE_AQC_MAX_ACTION_MEMORIES && mem_cnt < num_mem;
	     (*cur_mem_idx)++) {
		struct ice_acl_act_mem *p_mem = &tbl->act_mems[*cur_mem_idx];

		if (p_mem->act_mem == ICE_ACL_ACT_MEM_ACT_MEM_INVAL)
			continue;

		p_mem->member_of_tcam = cur_tcam;

		mem_cnt++;
	}
}

/**
 * ice_acl_divide_act_mems_to_tcams - assign action memory banks to TCAMs
 * @tbl: pointer to ACL table structure
 *
 * Figure out how to divide given action memory banks to given TCAMs. This
 * division is for SW book keeping. In the time when scenario is created,
 * an action memory bank can be used for different TCAM.
 *
 * For example, given that we have 2x2 ACL table with each table entry has
 * 2 action memory pairs. As the result, we will have 4 TCAMs (T1,T2,T3,T4)
 * and 4 action memory banks (A1,A2,A3,A4)
 *	[T1 - T2] { A1 - A2 }
 *	[T3 - T4] { A3 - A4 }
 * In the time when we need to create a scenario, for example, 2x1 scenario,
 * we will use [T3,T4] in a cascaded layout. As it is a requirement that all
 * action memory banks in a cascaded TCAM's row will need to associate with
 * the last TCAM. Thus, we will associate action memory banks [A3] and [A4]
 * for TCAM [T4].
 * For SW book-keeping purpose, we will keep theoretical maps between TCAM
 * [Tn] to action memory bank [An].
 */
static void ice_acl_divide_act_mems_to_tcams(struct ice_acl_tbl *tbl)
{
	u16 num_cscd, stack_level, stack_idx, min_act_mem;
	u8 tcam_idx = tbl->first_tcam;
	u16 max_idx_to_get_extra;
	u8 mem_idx = 0;

	/* Determine number of stacked TCAMs */
	stack_level = DIV_ROUND_UP(tbl->info.depth, ICE_AQC_ACL_TCAM_DEPTH);

	/* Determine number of cascaded TCAMs */
	num_cscd = DIV_ROUND_UP(tbl->info.width, ICE_AQC_ACL_KEY_WIDTH_BYTES);

	/* In a line of cascaded TCAM, given the number of action memory
	 * banks per ACL table entry, we want to fairly divide these action
	 * memory banks between these TCAMs.
	 *
	 * For example, there are 3 TCAMs (TCAM 3,4,5) in a line of
	 * cascaded TCAM, and there are 7 act_mems for each ACL table entry.
	 * The result is:
	 *	[TCAM_3 will have 3 act_mems]
	 *	[TCAM_4 will have 2 act_mems]
	 *	[TCAM_5 will have 2 act_mems]
	 */
	min_act_mem = tbl->info.entry_act_pairs / num_cscd;
	max_idx_to_get_extra = tbl->info.entry_act_pairs % num_cscd;

	for (stack_idx = 0; stack_idx < stack_level; stack_idx++) {
		u16 i;

		for (i = 0; i < num_cscd; i++) {
			u8 total_act_mem = min_act_mem;

			if (i < max_idx_to_get_extra)
				total_act_mem++;

			ice_acl_assign_act_mems_to_tcam(tbl, tcam_idx,
							&mem_idx,
							total_act_mem);

			tcam_idx++;
		}
	}
}

/**
 * ice_acl_create_tbl - create ACL table
 * @hw: pointer to the HW struct
 * @params: parameters for the table to be created
 *
 * Create a LEM table for ACL usage. We are currently starting with some fixed
 * values for the size of the table, but this will need to grow as more flow
 * entries are added by the user level.
 *
 * Return: 0 on success, negative on error
 */
int ice_acl_create_tbl(struct ice_hw *hw, struct ice_acl_tbl_params *params)
{
	struct ice_acl_alloc_tbl tbl_alloc = {};
	struct ice_aqc_acl_generic *resp_buf;
	u16 width, depth, first_e, last_e;
	struct ice_acl_tbl *tbl;
	u16 alloc_id;
	int err;

	if (hw->acl_tbl)
		return -EEXIST;

	/* round up the width to the next TCAM width boundary. */
	width = roundup(params->width, (u16)ICE_AQC_ACL_KEY_WIDTH_BYTES);
	/* depth should be provided in chunk (64 entry) increments */
	depth = ALIGN(params->depth, ICE_ACL_ENTRY_ALLOC_UNIT);

	if (params->entry_act_pairs < width / ICE_AQC_ACL_KEY_WIDTH_BYTES) {
		params->entry_act_pairs = width / ICE_AQC_ACL_KEY_WIDTH_BYTES;

		if (params->entry_act_pairs > ICE_AQC_TBL_MAX_ACTION_PAIRS)
			params->entry_act_pairs = ICE_AQC_TBL_MAX_ACTION_PAIRS;
	}

	/* Validate that width*depth will not exceed the TCAM limit */
	if ((DIV_ROUND_UP(depth, ICE_AQC_ACL_TCAM_DEPTH) *
	     (width / ICE_AQC_ACL_KEY_WIDTH_BYTES)) > ICE_AQC_ACL_SLICES)
		return -ENOSPC;

	tbl_alloc.width = width;
	tbl_alloc.depth = depth;
	tbl_alloc.act_pairs_per_entry = params->entry_act_pairs;
	tbl_alloc.concurr = params->concurr;

	if (params->concurr) {
		int i;

		tbl_alloc.num_dependent_alloc_ids = params->num_dep_tbls;

		for (i = 0; i < params->num_dep_tbls; i++)
			tbl_alloc.buf.data_buf.alloc_ids[i] =
				cpu_to_le16(params->dep_tbls[i]);

		for (; i < ICE_AQC_MAX_CONCURRENT_ACL_TBL; i++)
			tbl_alloc.buf.data_buf.alloc_ids[i] =
				cpu_to_le16(ICE_AQC_CONCURR_ID_INVALID);
	}

	err = ice_aq_alloc_acl_tbl(hw, &tbl_alloc, NULL);
	if (err) {
		dev_err(ice_hw_to_dev(hw), "ACL table allocation failed with error %d\n",
			err);
		return err;
	}

	alloc_id = le16_to_cpu(tbl_alloc.buf.resp_buf.alloc_id);
	if (alloc_id < ICE_AQC_ALLOC_ID_4K) {
		dev_err(ice_hw_to_dev(hw), "ACL table allocation failed due to unavailable resources.\n");
		return -ENOMEM;
	}

	resp_buf = &tbl_alloc.buf.resp_buf;

	tbl = kzalloc_obj(*tbl);
	if (!tbl) {
		err = -ENOMEM;
		goto err_dealloc_tbl;
	}

	/* Retrieve information of the allocated table */
	tbl->id = alloc_id;
	tbl->first_tcam = resp_buf->ops.table.first_tcam;
	tbl->last_tcam = resp_buf->ops.table.last_tcam;
	tbl->first_entry = le16_to_cpu(resp_buf->first_entry);
	tbl->last_entry = le16_to_cpu(resp_buf->last_entry);

	tbl->info = *params;
	tbl->info.width = width;
	tbl->info.depth = depth;
	hw->acl_tbl = tbl;

	for (int i = 0; i < ICE_AQC_MAX_ACTION_MEMORIES; i++)
		tbl->act_mems[i].act_mem = resp_buf->act_mem[i];

	/* Figure out which TCAMs that these newly allocated action memories
	 * belong to.
	 */
	ice_acl_divide_act_mems_to_tcams(tbl);

	/* Initialize the resources allocated by invalidating all TCAM entries
	 * and all the action pairs
	 */
	err = ice_acl_init_tbl(hw);
	if (err) {
		ice_debug(hw, ICE_DBG_ACL, "Initialization of TCAM entries failed. status: %d\n",
			  err);
		goto err_free_tbl;
	}

	first_e = (tbl->first_tcam * ICE_AQC_MAX_TCAM_ALLOC_UNITS) +
		(tbl->first_entry / ICE_ACL_ENTRY_ALLOC_UNIT);
	last_e = (tbl->last_tcam * ICE_AQC_MAX_TCAM_ALLOC_UNITS) +
		(tbl->last_entry / ICE_ACL_ENTRY_ALLOC_UNIT);

	/* Indicate available entries in the table */
	bitmap_set(tbl->avail, first_e, last_e - first_e + 1);

	INIT_LIST_HEAD(&tbl->scens);

	return 0;

err_free_tbl:
	hw->acl_tbl = NULL;
	kfree(tbl);
err_dealloc_tbl:
	ice_aq_dealloc_acl_tbl(hw, alloc_id, resp_buf, NULL);
	return err;
}

/**
 * ice_acl_destroy_tbl - Destroy a previously created LEM table for ACL
 * @hw: pointer to the HW struct
 *
 * Return: 0 on success, negative on error
 */
int ice_acl_destroy_tbl(struct ice_hw *hw)
{
	struct ice_aqc_acl_generic resp_buf;
	int err;

	if (!hw->acl_tbl)
		return -ENOENT;

	err = ice_aq_dealloc_acl_tbl(hw, hw->acl_tbl->id, &resp_buf, NULL);
	if (err) {
		ice_debug(hw, ICE_DBG_ACL, "AQ de-allocation of ACL failed. status: %d\n",
			  err);
		return err;
	}

	kfree(hw->acl_tbl);
	hw->acl_tbl = NULL;

	return 0;
}
