// SPDX-License-Identifier: GPL-2.0-only
#include <linux/acpi.h>
#include <linux/arm_ffa.h>
#include <linux/arm-smccc.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#define FFH_FFA_CALL_FAILED		1
#define FFH_FFA_SUCCESS			0
#define FFH_FFA_NOT_SUPPORTED		-1
#define FFH_FFA_INVALID_PARAMETERS	-2
#define FFH_FFA_OUT_OF_MEMORY		-3
#define FFH_FFA_UNSPECIFIED_ERROR	-4

#define FFH_FFA_MIN_LEN			(5 * sizeof(u64))
#define FFH_FFA_MAX_LEN			(18 * sizeof(u64))
#define FFH_FFA_UUID_OFFSET		(2 * sizeof(u64))

/*
 * Implements ARM64 specific callbacks to support ACPI FFH Operation Region as
 * specified in https://developer.arm.com/docs/den0048/latest
 */
struct acpi_ffh_data {
	struct acpi_ffh_info info;
	void (*invoke_ffh_fn)(unsigned long a0, unsigned long a1,
			      unsigned long a2, unsigned long a3,
			      unsigned long a4, unsigned long a5,
			      unsigned long a6, unsigned long a7,
			      struct arm_smccc_res *args,
			      struct arm_smccc_quirk *res);
	void (*invoke_ffh64_fn)(const struct arm_smccc_1_2_regs *args,
				struct arm_smccc_1_2_regs *res);
};

static DEFINE_MUTEX(acpi_ffh_ffa_lock);
static bool acpi_ffh_ffa_initialized, acpi_ffh_ffa_partition_info_regs;
static u16 acpi_ffh_ffa_sender_id;

static void acpi_ffh_ffa_invoke(struct acpi_ffh_data *ffh_ctxt,
				const struct arm_smccc_1_2_regs *args,
				struct arm_smccc_1_2_regs *res)
{
	ffh_ctxt->invoke_ffh64_fn(args, res);
}

static int acpi_ffh_ffa_features(struct acpi_ffh_data *ffh_ctxt, u32 fid)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = FFA_FEATURES,
		.a1 = fid,
	};
	struct arm_smccc_1_2_regs res;

	acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	if (res.a0 == FFA_ERROR) {
		if ((s32)res.a2 == FFA_RET_NOT_SUPPORTED)
			return -EOPNOTSUPP;
		return -EINVAL;
	}

	return res.a0 == FFA_SUCCESS ? 0 : -EIO;
}

static int acpi_ffh_ffa_init(struct acpi_ffh_data *ffh_ctxt)
{
	struct arm_smccc_1_2_regs args = { }, res;
	u32 version;
	int ret = 0;

	guard(mutex)(&acpi_ffh_ffa_lock);
	if (acpi_ffh_ffa_initialized)
		return 0;

	args.a0 = FFA_VERSION;
	args.a1 = FFA_VERSION_1_2;
	acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	version = res.a0;
	if ((s32)version == SMCCC_RET_NOT_SUPPORTED ||
	    FFA_MAJOR_VERSION(version) != 1 || version < FFA_VERSION_1_2) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	ret = acpi_ffh_ffa_features(ffh_ctxt, FFA_MSG_SEND_DIRECT_REQ2);
	if (ret)
		return ret;

	ret = acpi_ffh_ffa_features(ffh_ctxt, FFA_MSG_SEND_DIRECT_RESP2);
	if (ret)
		return ret;

	acpi_ffh_ffa_partition_info_regs =
		!acpi_ffh_ffa_features(ffh_ctxt, FFA_PARTITION_INFO_GET_REGS);

	args = (struct arm_smccc_1_2_regs) { .a0 = FFA_ID_GET };
	acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	if (res.a0 == FFA_ERROR) {
		ret = (s32)res.a2 == FFA_RET_NOT_SUPPORTED ? -EOPNOTSUPP : -EIO;
		return ret;
	}
	if (res.a0 != FFA_SUCCESS) {
		ret = -EIO;
		return ret;
	}

	acpi_ffh_ffa_sender_id = (u16)res.a2;
	acpi_ffh_ffa_initialized = true;
	return ret;
}

static void acpi_ffh_ffa_uuid_convert(const u8 *guid, u8 *uuid)
{
	/* ACPI ToUUID uses GUID byte order while FF-A uses UUID byte order. */
	uuid[0] = guid[3];
	uuid[1] = guid[2];
	uuid[2] = guid[1];
	uuid[3] = guid[0];
	uuid[4] = guid[5];
	uuid[5] = guid[4];
	uuid[6] = guid[7];
	uuid[7] = guid[6];
	memcpy(uuid + 8, guid + 8, UUID_SIZE - 8);
}

static int acpi_ffh_ffa_receiver_id(struct acpi_ffh_data *ffh_ctxt,
				    u64 uuid_lo, u64 uuid_hi, u16 *receiver_id)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = FFA_PARTITION_INFO_GET_REGS,
		.a1 = uuid_lo,
		.a2 = uuid_hi,
	};
	struct arm_smccc_1_2_regs res;
	u32 properties;

	if (!acpi_ffh_ffa_partition_info_regs)
		return -EOPNOTSUPP;

	acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	if (res.a0 == FFA_ERROR) {
		switch ((s32)res.a2) {
		case FFA_RET_NOT_SUPPORTED:
			return -EOPNOTSUPP;
		case FFA_RET_INVALID_PARAMETERS:
			return -EINVAL;
		case FFA_RET_NO_MEMORY:
			return -ENOMEM;
		default:
			return -EIO;
		}
	}
	if (res.a0 != FFA_FN64_SUCCESS)
		return -EINVAL;

	if (FIELD_GET(FFA_PART_INFO_LAST_IDX_MASK, res.a2) ||
	    FIELD_GET(FFA_PART_INFO_CUR_IDX_MASK, res.a2) ||
	    FIELD_GET(FFA_PART_INFO_DESC_SIZE_MASK, res.a2) <
		    FFA_PART_INFO_MIN_DESC_SIZE)
		return -EINVAL;

	properties = FIELD_GET(FFA_PART_INFO_PROPS_MASK, res.a3);
	if (!(properties & FFA_PARTITION_DIRECT_REQ2_RECV))
		return -EINVAL;

	*receiver_id = FIELD_GET(FFA_PART_INFO_ID_MASK, res.a3);
	return 0;
}

static int acpi_ffh_ffa_status(int error)
{
	switch (error) {
	case -EOPNOTSUPP:
		return FFH_FFA_NOT_SUPPORTED;
	case -EINVAL:
		return FFH_FFA_INVALID_PARAMETERS;
	case -ENOMEM:
		return FFH_FFA_OUT_OF_MEMORY;
	default:
		return FFH_FFA_UNSPECIFIED_ERROR;
	}
}

static int acpi_ffh_ffa_direct_req2(acpi_integer *value,
				    struct acpi_ffh_data *ffh_ctxt)
{
	struct arm_smccc_1_2_regs args = { }, res;
	u64 *buf = (u64 *)value;
	u64 uuid_lo, uuid_hi;
	u16 receiver_id = (u16)buf[1];
	uuid_t uuid;
	size_t len = ffh_ctxt->info.length;
	int ret;

	if (len < FFH_FFA_MIN_LEN || len > FFH_FFA_MAX_LEN ||
	    !IS_ALIGNED(len - 4 * sizeof(u64), sizeof(u64))) {
		buf[0] = FFH_FFA_INVALID_PARAMETERS;
		return AE_OK;
	}

	acpi_ffh_ffa_uuid_convert((u8 *)value + FFH_FFA_UUID_OFFSET, uuid.b);
	if (uuid_is_null(&uuid)) {
		buf[0] = FFH_FFA_INVALID_PARAMETERS;
		return AE_OK;
	}

	ret = acpi_ffh_ffa_init(ffh_ctxt);
	if (ret) {
		buf[0] = acpi_ffh_ffa_status(ret);
		return AE_OK;
	}

	uuid_lo = get_unaligned_le64(uuid.b);
	uuid_hi = get_unaligned_le64(uuid.b + sizeof(uuid_lo));
	if (!receiver_id) {
		ret = acpi_ffh_ffa_receiver_id(ffh_ctxt, uuid_lo, uuid_hi,
					       &receiver_id);
		if (ret) {
			buf[0] = acpi_ffh_ffa_status(ret);
			return AE_OK;
		}
	}

	args.a0 = FFA_MSG_SEND_DIRECT_REQ2;
	args.a1 = ffa_pack_target_info(acpi_ffh_ffa_sender_id, receiver_id);
	args.a2 = uuid_lo;
	args.a3 = uuid_hi;
	memcpy((void *)&args + offsetof(struct arm_smccc_1_2_regs, a4),
	       &buf[4], len - 4 * sizeof(u64));

	acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	while (res.a0 == FFA_INTERRUPT || res.a0 == FFA_YIELD) {
		if (res.a0 == FFA_YIELD)
			fsleep(1000);

		args = (struct arm_smccc_1_2_regs) {
			.a0 = FFA_RUN,
			.a1 = res.a1,
		};
		acpi_ffh_ffa_invoke(ffh_ctxt, &args, &res);
	}

	memcpy(buf, &res, len);
	if (res.a0 == FFA_MSG_SEND_DIRECT_RESP2 || res.a0 == FFA_SUCCESS ||
	    res.a0 == FFA_FN64_SUCCESS)
		buf[0] = FFH_FFA_SUCCESS;
	else
		buf[0] = FFH_FFA_CALL_FAILED;

	return AE_OK;
}

int acpi_ffh_address_space_arch_setup(void *handler_ctxt, void **region_ctxt)
{
	enum arm_smccc_conduit conduit;
	struct acpi_ffh_data *ffh_ctxt;

	if (arm_smccc_get_version() < ARM_SMCCC_VERSION_1_2)
		return -EOPNOTSUPP;

	conduit = arm_smccc_1_1_get_conduit();
	if (conduit == SMCCC_CONDUIT_NONE) {
		pr_err("%s: invalid SMCCC conduit\n", __func__);
		return -EOPNOTSUPP;
	}

	ffh_ctxt = kzalloc_obj(*ffh_ctxt);
	if (!ffh_ctxt)
		return -ENOMEM;

	if (conduit == SMCCC_CONDUIT_SMC) {
		ffh_ctxt->invoke_ffh_fn = __arm_smccc_smc;
		ffh_ctxt->invoke_ffh64_fn = arm_smccc_1_2_smc;
	} else {
		ffh_ctxt->invoke_ffh_fn = __arm_smccc_hvc;
		ffh_ctxt->invoke_ffh64_fn = arm_smccc_1_2_hvc;
	}

	memcpy(ffh_ctxt, handler_ctxt, sizeof(ffh_ctxt->info));

	*region_ctxt = ffh_ctxt;
	return AE_OK;
}

static bool acpi_ffh_smccc_owner_allowed(u32 fid)
{
	int owner = ARM_SMCCC_OWNER_NUM(fid);

	if (owner == ARM_SMCCC_OWNER_STANDARD ||
	    owner == ARM_SMCCC_OWNER_SIP || owner == ARM_SMCCC_OWNER_OEM)
		return true;

	return false;
}

int acpi_ffh_address_space_arch_handler(acpi_integer *value, void *region_context)
{
	int ret = 0;
	struct acpi_ffh_data *ffh_ctxt = region_context;

	if (ffh_ctxt->info.offset == 0) {
		/* SMC/HVC 32bit call */
		struct arm_smccc_res res;
		u32 a[8] = { 0 }, *ptr = (u32 *)value;

		if (!ARM_SMCCC_IS_FAST_CALL(*ptr) || ARM_SMCCC_IS_64(*ptr) ||
		    !acpi_ffh_smccc_owner_allowed(*ptr) ||
		    ffh_ctxt->info.length > 32) {
			ret = AE_ERROR;
		} else {
			int idx, len = ffh_ctxt->info.length >> 2;

			for (idx = 0; idx < len; idx++)
				a[idx] = *(ptr + idx);

			ffh_ctxt->invoke_ffh_fn(a[0], a[1], a[2], a[3], a[4],
						a[5], a[6], a[7], &res, NULL);
			memcpy(value, &res, sizeof(res));
		}

	} else if (ffh_ctxt->info.offset == 1) {
		/* SMC/HVC 64bit call */
		struct arm_smccc_1_2_regs *r = (struct arm_smccc_1_2_regs *)value;

		if (!ARM_SMCCC_IS_FAST_CALL(r->a0) || !ARM_SMCCC_IS_64(r->a0) ||
		    !acpi_ffh_smccc_owner_allowed(r->a0) ||
		    ffh_ctxt->info.length > sizeof(*r)) {
			ret = AE_ERROR;
		} else {
			ffh_ctxt->invoke_ffh64_fn(r, r);
			memcpy(value, r, ffh_ctxt->info.length);
		}
	} else if (ffh_ctxt->info.offset == 2) {
		ret = acpi_ffh_ffa_direct_req2(value, ffh_ctxt);
	} else {
		ret = AE_ERROR;
	}

	return ret;
}
