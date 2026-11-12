// SPDX-License-Identifier: GPL-2.0
//
// soc-apci.c - support for ACPI enumeration.
//
// Copyright (c) 2013-15, Intel Corporation.

#include <linux/device.h>
#include <linux/export.h>
#include <linux/module.h>
#include <sound/soc-acpi.h>

#if IS_ENABLED(CONFIG_ACPI)
static bool snd_soc_acpi_id_present(struct snd_soc_acpi_mach *machine)
{
	const struct snd_soc_acpi_codecs *comp_ids = machine->comp_ids;
	int i;

	if (machine->id[0]) {
		if (acpi_dev_present(machine->id, NULL, -1))
			return true;
	}

	if (comp_ids) {
		for (i = 0; i < comp_ids->num_codecs; i++) {
			if (acpi_dev_present(comp_ids->codecs[i], NULL, -1)) {
				strscpy(machine->id, comp_ids->codecs[i], ACPI_ID_LEN);
				return true;
			}
		}
	}

	return false;
}

struct snd_soc_acpi_mach *
snd_soc_acpi_find_machine(struct snd_soc_acpi_mach *machines)
{
	struct snd_soc_acpi_mach *mach;
	struct snd_soc_acpi_mach *mach_alt;

	for (mach = machines; mach->id[0] || mach->comp_ids; mach++) {
		if (snd_soc_acpi_id_present(mach)) {
			if (mach->machine_quirk) {
				mach_alt = mach->machine_quirk(mach);
				if (!mach_alt)
					continue; /* not full match, ignore */
				mach = mach_alt;
			}

			return mach;
		}
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_find_machine);

static acpi_status snd_soc_acpi_find_package(acpi_handle handle, u32 level,
					     void *context, void **ret)
{
	struct acpi_device *adev = acpi_fetch_acpi_dev(handle);
	acpi_status status;
	struct snd_soc_acpi_package_context *pkg_ctx = context;

	pkg_ctx->data_valid = false;

	if (adev && adev->status.present && adev->status.functional) {
		struct acpi_buffer buffer = {ACPI_ALLOCATE_BUFFER, NULL};
		union acpi_object  *myobj = NULL;

		status = acpi_evaluate_object_typed(handle, pkg_ctx->name,
						NULL, &buffer,
						ACPI_TYPE_PACKAGE);
		if (ACPI_FAILURE(status))
			return AE_OK;

		myobj = buffer.pointer;
		if (!myobj || myobj->package.count != pkg_ctx->length) {
			kfree(buffer.pointer);
			return AE_OK;
		}

		status = acpi_extract_package(myobj,
					pkg_ctx->format, pkg_ctx->state);
		if (ACPI_FAILURE(status)) {
			kfree(buffer.pointer);
			return AE_OK;
		}

		kfree(buffer.pointer);
		pkg_ctx->data_valid = true;
		return AE_CTRL_TERMINATE;
	}

	return AE_OK;
}

bool snd_soc_acpi_find_package_from_hid(const u8 hid[ACPI_ID_LEN],
				struct snd_soc_acpi_package_context *ctx)
{
	acpi_status status;

	status = acpi_get_devices(hid, snd_soc_acpi_find_package, ctx, NULL);

	if (ACPI_FAILURE(status) || !ctx->data_valid)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_find_package_from_hid);

struct snd_soc_acpi_mach *snd_soc_acpi_codec_list(void *arg)
{
	struct snd_soc_acpi_mach *mach = arg;
	struct snd_soc_acpi_codecs *codec_list =
		(struct snd_soc_acpi_codecs *) mach->quirk_data;
	int i;

	if (mach->quirk_data == NULL)
		return mach;

	for (i = 0; i < codec_list->num_codecs; i++) {
		if (!acpi_dev_present(codec_list->codecs[i], NULL, -1))
			return NULL;
	}

	return mach;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_codec_list);
#endif /* CONFIG_ACPI */

#define SDW_CODEC_ADR_MASK(_adr) ((_adr) & (SDW_DISCO_LINK_ID_MASK | SDW_VERSION_MASK | \
				  SDW_MFG_ID_MASK | SDW_PART_ID_MASK))

/* Check if all Slaves defined on the link can be found */
bool snd_soc_acpi_sdw_link_slaves_found(struct device *dev,
					const struct snd_soc_acpi_link_adr *link,
					struct sdw_peripherals *peripherals)
{
	unsigned int part_id, link_id, unique_id, mfg_id, version;
	int i, j, k;

	for (i = 0; i < link->num_adr; i++) {
		u64 adr = link->adr_d[i].adr;
		int reported_part_count = 0;

		mfg_id = SDW_MFG_ID(adr);
		part_id = SDW_PART_ID(adr);
		link_id = SDW_DISCO_LINK_ID(adr);
		version = SDW_VERSION(adr);

		for (j = 0; j < peripherals->num_peripherals; j++) {
			struct sdw_slave *peripheral = peripherals->array[j];

			/* find out how many identical parts were reported on that link */
			if (peripheral->bus->link_id == link_id &&
			    peripheral->id.part_id == part_id &&
			    peripheral->id.mfg_id == mfg_id &&
			    peripheral->id.sdw_version == version)
				reported_part_count++;
		}

		for (j = 0; j < peripherals->num_peripherals; j++) {
			struct sdw_slave *peripheral = peripherals->array[j];
			int expected_part_count = 0;

			if (peripheral->bus->link_id != link_id ||
			    peripheral->id.part_id != part_id ||
			    peripheral->id.mfg_id != mfg_id ||
			    peripheral->id.sdw_version != version)
				continue;

			/* find out how many identical parts are expected */
			for (k = 0; k < link->num_adr; k++) {
				u64 adr2 = link->adr_d[k].adr;

				if (SDW_CODEC_ADR_MASK(adr2) == SDW_CODEC_ADR_MASK(adr))
					expected_part_count++;
			}

			if (reported_part_count == expected_part_count) {
				/*
				 * we have to check unique id
				 * if there is more than one
				 * Slave on the link
				 */
				unique_id = SDW_UNIQUE_ID(adr);
				if (reported_part_count == 1 ||
				    peripheral->id.unique_id == unique_id) {
					dev_dbg(dev, "found part_id %#x at link %d\n", part_id, link_id);
					break;
				}
			} else {
				dev_dbg(dev, "part_id %#x reported %d expected %d on link %d, skipping\n",
					part_id, reported_part_count, expected_part_count, link_id);
			}
		}
		if (j == peripherals->num_peripherals) {
			dev_dbg(dev, "Slave part_id %#x not found\n", part_id);
			return false;
		}
	}
	return true;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_sdw_link_slaves_found);

int snd_soc_acpi_sof_get_platform_name(struct device *dev,
				       const struct snd_soc_acpi_mach *mach, char *platform)
{
	int ret;

	/* platform must hold at least SND_SOC_ACPI_SOF_PLATFORM_NAME_MAX bytes */
	ret = sscanf(mach->sof_tplg_filename, "sof-%7[^-]-*.tplg", platform);
	if (ret != 1) {
		dev_err(dev, "Invalid platform name of tplg %s\n",
			mach->sof_tplg_filename);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_sof_get_platform_name);

char *snd_soc_acpi_sof_get_tplg_filename(struct device *dev, const char *prefix,
					 const char *platform, const char *tplg_dev_name,
					 int dai_link_id,
					 enum snd_soc_acpi_tplg_device_id tplg_dev)
{
	char *filename = NULL;

	/*
	 * The tplg file naming rule is sof-<platform>-<function>-id<BE id number>.tplg
	 * where <platform> is required for functions that depend on NHLT blobs (e.g. DMIC/SSP)
	 * as the nhlt blob is platform dependent.
	 */
	switch (tplg_dev) {
	case SND_SOC_ACPI_TPLG_DEVICE_PCH_DMIC:
	case SND_SOC_ACPI_TPLG_DEVICE_SSP_JACK:
	case SND_SOC_ACPI_TPLG_DEVICE_SSP_AMP:
	case SND_SOC_ACPI_TPLG_DEVICE_SSP_BT:
	case SND_SOC_ACPI_TPLG_DEVICE_SSP_HDMI_IN:
	case SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_JACK:
	case SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_AMP:
	case SND_SOC_ACPI_TPLG_DEVICE_ACP_SDW_MIC:
	case SND_SOC_ACPI_TPLG_DEVICE_ACP_DMIC:
		filename = devm_kasprintf(dev, GFP_KERNEL, "%s/sof-%s-%s-id%d.tplg",
					  prefix, platform, tplg_dev_name, dai_link_id);
		break;
	default:
		filename = devm_kasprintf(dev, GFP_KERNEL, "%s/sof-%s-id%d.tplg",
					  prefix, tplg_dev_name, dai_link_id);
		break;
	}

	return filename;
}
EXPORT_SYMBOL_GPL(snd_soc_acpi_sof_get_tplg_filename);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("ALSA SoC ACPI module");
