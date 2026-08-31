// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2024 Intel Corporation */
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/intel_vsec.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/types.h>

#include <drm/drm_drv.h>

#include "xe_device.h"
#include "xe_device_types.h"
#include "xe_mmio.h"
#include "xe_platform_types.h"
#include "xe_pm.h"
#include "xe_sysctrl.h"
#include "xe_vsec.h"

#include "regs/xe_pmt.h"

/* PMT GUID value for BMG and CRI devices.  NOTE: this is NOT a PCI id */
#define BMG_DEVICE_ID 0xE2F8
#define CRI_DEVICE_ID 0xE2FA

/*
 * sizeof(Crashlog Type1 Version2) = 0x18 (24) bytes
 * For BMG and CRI PUNIT and OOBMSMS crashlogs are consecutive.
 */
#define BMG_CRASHLOG_PUNIT_DISC_OFFSET (0x60)
#define BMG_CRASHLOG_OOBMSM_DISC_OFFSET (BMG_CRASHLOG_PUNIT_DISC_OFFSET + 0x18)

#define CRI_CRASHLOG_PUNIT_DISC_OFFSET (0x80)
#define CRI_CRASHLOG_OOBMSM_DISC_OFFSET (CRI_CRASHLOG_PUNIT_DISC_OFFSET + 0x18)

static struct intel_vsec_header bmg_telemetry = {
	.rev = 1,
	.length = 0x10,
	.id = VSEC_ID_TELEMETRY,
	.num_entries = 2,
	.entry_size = 4,
	.tbir = 0,
	.offset = BMG_DISCOVERY_OFFSET,
};

static struct intel_vsec_header bmg_crashlog = {
	.rev = 1,
	.length = 0x10,
	.id = VSEC_ID_CRASHLOG,
	.num_entries = 2,
	.entry_size = 6,
	.tbir = 0,
	.offset = BMG_DISCOVERY_OFFSET + BMG_CRASHLOG_PUNIT_DISC_OFFSET,
};

static struct intel_vsec_header *bmg_capabilities[] = {
	&bmg_telemetry,
	&bmg_crashlog,
	NULL
};

static struct intel_vsec_header cri_telemetry = {
	.rev = 1,
	.length = 0x10,
	.id = VSEC_ID_TELEMETRY,
	.num_entries = 3,
	.entry_size = 4,
	.tbir = 0,
	.offset = CRI_DISCOVERY_OFFSET,
};

static struct intel_vsec_header cri_crashlog = {
	.rev = 1,
	.length = 0x10,
	.id = VSEC_ID_CRASHLOG,
	.num_entries = 2,
	.entry_size = 6,
	.tbir = 0,
	.offset = CRI_DISCOVERY_OFFSET + CRI_CRASHLOG_PUNIT_DISC_OFFSET,
};

static struct intel_vsec_header *cri_capabilities[] = {
	&cri_telemetry,
	&cri_crashlog,
	NULL
};

enum xe_vsec {
	XE_VSEC_UNKNOWN = 0,
	XE_VSEC_BMG,
	XE_VSEC_CRI,
};

static struct intel_vsec_platform_info xe_vsec_info[] = {
	[XE_VSEC_BMG] = {
		.caps = VSEC_CAP_TELEMETRY | VSEC_CAP_CRASHLOG,
		.headers = bmg_capabilities,
	},
	[XE_VSEC_CRI] = {
		.caps = VSEC_CAP_TELEMETRY | VSEC_CAP_CRASHLOG,
		.headers = cri_capabilities,
	},
	{ }
};

/*
 * The GUID will have the following bits to decode:
 *   [0:3]   - {Telemetry space iteration number (0,1,..)}
 *   [4:7]   - BMG Segment (SEGMENT_INDEPENDENT-0, Client-1, Server-2)
 *   [4:5]   - CRI Segment (SEGMENT_INDEPENDENT-0, Client-1, Server-2)
 *   [6:7]   - CRI Instance
 *   [8:11]  - SOC_SKU
 *   [12:27] – Device ID – changes for each down bin SKU’s
 *   [28:29] - Capability Type (Crashlog-0, Telemetry Aggregator-1, Watcher-2)
 *   [30:31] - Record-ID (0-PUNIT, 1-OOBMSM_0, 2-OOBMSM_1)
 */
#define GUID_TELEM_ITERATION	GENMASK(3, 0)
#define GUID_SOC_SKU		GENMASK(11, 8)
#define GUID_DEVICE_ID		GENMASK(27, 12)
#define GUID_CAP_TYPE		GENMASK(29, 28)
#define GUID_RECORD_ID		GENMASK(31, 30)

#define BMG_GUID_SEGMENT	GENMASK(7, 4)

#define CRI_GUID_SEGMENT	GENMASK(5, 4)
#define CRI_GUID_INSTANCE	GENMASK(7, 6)

#define BMG_IDX_TELEM_PUNIT		0x00
#define BMG_IDX_TELEM_OOBMSM		0x01
#define BMG_IDX_CRASHLOG_PUNIT		0x02
#define BMG_IDX_CRASHLOG_OOBMSM		0x04

#define BMG_PUNIT_TELEMETRY_OFFSET	0x0200
#define BMG_PUNIT_WATCHER_OFFSET	0x14A0
#define BMG_OOBMSM_0_WATCHER_OFFSET	0x18D8
#define BMG_OOBMSM_1_TELEMETRY_OFFSET	0x1000

#define CRI_IDX_TELEM_DISCOVERY		0x00
#define CRI_IDX_TELEM_PUNIT		0x01
#define CRI_IDX_TELEM_OOBMSM		0x02
#define CRI_IDX_CRASHLOG_PUNIT		0x03
#define CRI_IDX_WATCHER_OOBMSM		0x03  /* PUNIT and OOBMSM share this index */
#define CRI_IDX_CRASHLOG_OOBMSM		0x04

#define CRI_PUNIT_TELEMETRY_OFFSET		0x0200
#define CRI_PUNIT_WATCHER_OFFSET		0x08A0
#define CRI_OOBMSM_WATCHER_OFFSET		0x0CF8
#define CRI_OOBMSM_GFSP_TELEMETRY_OFFSET	0x1600
#define CRI_PUNIT_CRASHLOG_OFFSET		0x0E60

enum record_id {
	PUNIT,
	OOBMSM_0,
	OOBMSM_1,
};

enum capability {
	CRASHLOG,
	TELEMETRY,
	WATCHER,
};

/*
 * Late bind will delay 100msec for up to 20 seconds
 */
#define VSEC_LATE_BIND_DELAY_MSEC	(100)
#define VSEC_LATE_BIND_RETRY		(200)

static void cri_late_bind_probe(struct xe_device *xe);

static int bmg_guid_decode(u32 guid, int *index, u32 *offset)
{
	u32 record_id = FIELD_GET(GUID_RECORD_ID, guid);
	u32 cap_type  = FIELD_GET(GUID_CAP_TYPE, guid);

	*offset = 0;

	if (cap_type == CRASHLOG) {
		*index = record_id == PUNIT ? BMG_IDX_CRASHLOG_PUNIT : BMG_IDX_CRASHLOG_OOBMSM;
		return 0;
	}

	switch (record_id) {
	case PUNIT:
		*index = BMG_IDX_TELEM_PUNIT;
		if (cap_type == TELEMETRY)
			*offset = BMG_PUNIT_TELEMETRY_OFFSET;
		else
			*offset = BMG_PUNIT_WATCHER_OFFSET;
		break;

	case OOBMSM_0:
		*index = BMG_IDX_TELEM_OOBMSM;
		if (cap_type == WATCHER)
			*offset = BMG_OOBMSM_0_WATCHER_OFFSET;
		break;

	case OOBMSM_1:
		*index = BMG_IDX_TELEM_OOBMSM;
		if (cap_type == TELEMETRY)
			*offset = BMG_OOBMSM_1_TELEMETRY_OFFSET;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int cri_guid_decode(u32 guid, int *index, u32 *offset)
{
	u32 record_id = FIELD_GET(GUID_RECORD_ID, guid);
	u32 cap_type  = FIELD_GET(GUID_CAP_TYPE, guid);
	u32 instance  = FIELD_GET(CRI_GUID_INSTANCE, guid);

	*offset = 0;

	if (cap_type == CRASHLOG) {
		if (record_id == PUNIT) {
			*index = CRI_IDX_CRASHLOG_PUNIT;
			*offset = CRI_PUNIT_CRASHLOG_OFFSET;
		} else {
			*index = CRI_IDX_CRASHLOG_OOBMSM;
		}
		return 0;
	}

	switch (record_id) {
	case PUNIT:
		*index = CRI_IDX_TELEM_PUNIT;
		if (cap_type == TELEMETRY)
			*offset = CRI_PUNIT_TELEMETRY_OFFSET;
		else
			*offset = CRI_PUNIT_WATCHER_OFFSET;
		break;

	case OOBMSM_0:
		*index = CRI_IDX_TELEM_OOBMSM;
		switch (instance) {
		case 0:
			if (cap_type == WATCHER) {
				*index = CRI_IDX_WATCHER_OOBMSM;
				*offset = CRI_OOBMSM_WATCHER_OFFSET;
			}
			break;

		case 1:
			if (cap_type == TELEMETRY)
				*offset = CRI_OOBMSM_GFSP_TELEMETRY_OFFSET;
			break;

		default:
			return -EINVAL;
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int xe_guid_decode(u32 guid, int *index, u32 *offset)
{
	u32 cap_type  = FIELD_GET(GUID_CAP_TYPE, guid);
	u32 device_id = FIELD_GET(GUID_DEVICE_ID, guid);

	if (cap_type > WATCHER)
		return -EINVAL;

	if (device_id == BMG_DEVICE_ID)
		return bmg_guid_decode(guid, index, offset);

	if (device_id == CRI_DEVICE_ID)
		return cri_guid_decode(guid, index, offset);

	return -ENODEV;
}

#define WAITING_FOR_SYCTLR
#ifdef WAITING_FOR_SYCTLR
static bool xe_is_oobmsm_fw_ready(struct xe_device *xe)
{
	return true;
}
#endif

static void cri_late_bind_probe_work(struct work_struct *work)
{
	struct xe_device *xe = container_of(work, struct xe_device, pmt.work.work);

	if (xe_is_oobmsm_fw_ready(xe)) {
		cri_late_bind_probe(xe);
		xe_pm_runtime_put(xe);
		return;
	}

	xe->pmt.retry_count++;

	/* wait up to 20 seconds */
	if (xe->pmt.retry_count == VSEC_LATE_BIND_RETRY) {
		drm_warn(&xe->drm, "PMT probe: Late Binding failed to complete\n");
		xe_pm_runtime_put(xe);
		return;
	}

	if (!schedule_delayed_work(&xe->pmt.work, msecs_to_jiffies(VSEC_LATE_BIND_DELAY_MSEC)))
		xe_pm_runtime_put(xe);
}

static bool wait_for_fw(struct xe_device *xe)
{
	int retries = VSEC_LATE_BIND_RETRY;  /* wait up to 20 secs */

	if (xe->info.platform != XE_CRESCENTISLAND)
		return true;

	while (retries--) {
		if (xe_is_oobmsm_fw_ready(xe))
			return true;

		msleep(VSEC_LATE_BIND_DELAY_MSEC);
	}

	drm_warn(&xe->drm, "Late Binding failed to complete\n");

	return false;
}

/*
 * xe_pmt_telem_read is a callback API.  I.e this can be accessed external to
 * XE driver (PMT driver scope).  Because of this, DRM hotplug needs to be
 * verified (drm_dev_enter()).
 */
int xe_pmt_telem_read(struct device *dev, u32 guid, u64 *data, loff_t user_offset,
		      u32 count)
{
	struct xe_device *xe = kdev_to_xe_device(dev);
	u32 cap_type = FIELD_GET(GUID_CAP_TYPE, guid);
	void __iomem *telem_addr = xe->mmio.regs + xe->pmt.base_offset;
	u32 mem_region;
	u32 offset;
	int ret = 0;
	int idx;

	if (!drm_dev_enter(&xe->drm, &idx))
		return -ENODEV;

	if (!xe->soc_remapper.set_telem_region) {
		ret = -EINVAL;
		goto dev_exit;
	}

	ret = xe_guid_decode(guid, &mem_region, &offset);
	if (ret)
		goto dev_exit;

	telem_addr += offset + user_offset;

	/* Always allow crashlog. Telemetry, only when powered */
	switch (cap_type) {
	case CRASHLOG:
		xe_pm_runtime_get(xe);
		break;
	case TELEMETRY:
		if (!xe_pm_runtime_get_if_active(xe)) {
			ret = -ENODATA;
			goto dev_exit;
		}
		break;
	case WATCHER:
		ret = -EINVAL;
		goto dev_exit;
	}

	if (!wait_for_fw(xe)) {
		ret = -ENODATA;
		goto runtime_exit;
	}

	mutex_lock(&xe->pmt.lock);

	/* set SoC re-mapper index register based on GUID memory region */
	xe->soc_remapper.set_telem_region(xe, mem_region);

	memcpy_fromio(data, telem_addr, count);

	mutex_unlock(&xe->pmt.lock);

runtime_exit:
	xe_pm_runtime_put(xe);

dev_exit:
	drm_dev_exit(idx);

	return ret == 0 ? count : ret;
}

/**
 * xe_pmt_read_reg() - read a crashlog register
 * @dev: the xe device that registered the callback
 * @guid: PMT guid of the crashlog instance
 * @reg: data read from the PMT data structure
 * @offset: which data to read from the PMT data structure
 *
 * Read the requested PMT register based on the pcie device and guid.  The
 * supported struct is the Crashlog Type1 Version2.
 *
 * Currently this is for CRI only.
 */
static int xe_pmt_read_reg(struct device *dev, u32 guid, u32 *reg, u32 offset)
{
	struct xe_device *xe = kdev_to_xe_device(dev);
	void __iomem *disc_addr = xe->mmio.regs;
	int ret = 0;
	u32 inst;
	int idx;

	if (!drm_dev_enter(&xe->drm, &idx))
		return -ENODEV;

	if (!xe->soc_remapper.set_telem_region) {
		ret = -ENODEV;
		goto dev_exit;
	}

	if (FIELD_GET(GUID_DEVICE_ID, guid) != CRI_DEVICE_ID ||
	    FIELD_GET(GUID_CAP_TYPE, guid) != CRASHLOG) {
		ret = -EINVAL;
		goto dev_exit;
	}

	inst = FIELD_GET(GUID_RECORD_ID, guid) == PUNIT ?
		CRI_CRASHLOG_PUNIT_DISC_OFFSET : CRI_CRASHLOG_OOBMSM_DISC_OFFSET;
	disc_addr += CRI_DISCOVERY_OFFSET + inst + offset;

	xe_pm_runtime_get(xe);
	if (!wait_for_fw(xe)) {
		ret = -ENODATA;
		goto runtime_exit;
	}
	mutex_lock(&xe->pmt.lock);

	xe->soc_remapper.set_telem_region(xe, CRI_IDX_TELEM_DISCOVERY);

	memcpy_fromio(reg, disc_addr, sizeof(*reg));

	mutex_unlock(&xe->pmt.lock);

runtime_exit:
	xe_pm_runtime_put(xe);

dev_exit:
	drm_dev_exit(idx);

	return ret;
}

static int xe_pmt_write_reg(struct device *dev, u32 guid, u32 reg, u32 offset)
{
	struct xe_device *xe = kdev_to_xe_device(dev);
	void __iomem *disc_addr = xe->mmio.regs;
	int ret = 0;
	u32 inst;
	int idx;

	if (!drm_dev_enter(&xe->drm, &idx))
		return -ENODEV;

	if (!xe->soc_remapper.set_telem_region) {
		ret = -ENODEV;
		goto dev_exit;
	}

	if (FIELD_GET(GUID_DEVICE_ID, guid) != CRI_DEVICE_ID ||
	    FIELD_GET(GUID_CAP_TYPE, guid) != CRASHLOG) {
		ret = -EINVAL;
		goto dev_exit;
	}

	inst = FIELD_GET(GUID_RECORD_ID, guid) == PUNIT ?
		CRI_CRASHLOG_PUNIT_DISC_OFFSET : CRI_CRASHLOG_OOBMSM_DISC_OFFSET;
	disc_addr += CRI_DISCOVERY_OFFSET + inst + offset;

	xe_pm_runtime_get(xe);
	if (!wait_for_fw(xe)) {
		ret = -ENODATA;
		goto runtime_exit;
	}
	mutex_lock(&xe->pmt.lock);

	xe->soc_remapper.set_telem_region(xe, CRI_IDX_TELEM_DISCOVERY);

	memcpy_toio(disc_addr, &reg, sizeof(reg));

	mutex_unlock(&xe->pmt.lock);

runtime_exit:
	xe_pm_runtime_put(xe);

dev_exit:
	drm_dev_exit(idx);

	return ret;
}

static struct pmt_callbacks xe_bmg_pmt_cb = {
	.read_telem = xe_pmt_telem_read,
};

static struct pmt_callbacks xe_cri_pmt_cb = {
	.read_telem = xe_pmt_telem_read,
	.read_reg = xe_pmt_read_reg,
	.write_reg = xe_pmt_write_reg,
};

static const int vsec_platforms[] = {
	[XE_BATTLEMAGE] = XE_VSEC_BMG,
	[XE_CRESCENTISLAND] = XE_VSEC_CRI,
};

static enum xe_vsec get_platform_info(struct xe_device *xe)
{
	if (xe->info.platform > XE_CRESCENTISLAND)
		return XE_VSEC_UNKNOWN;

	return vsec_platforms[xe->info.platform];
}

static void cri_late_bind_probe(struct xe_device *xe)
{
	struct intel_vsec_platform_info *info;
	struct device *dev = xe->drm.dev;
	enum xe_vsec platform;

	platform = get_platform_info(xe);
	if (platform != XE_VSEC_CRI)
		return;

	info = &xe_vsec_info[platform];
	if (!info->headers)
		return;

	info->priv_data = &xe_cri_pmt_cb;
	xe->soc_remapper.set_telem_region(xe, CRI_IDX_TELEM_DISCOVERY);

	intel_vsec_register(dev, info);
}

static void vsec_disable_late_bind_work(void *arg)
{
	struct xe_device *xe = arg;

	/*
	 * If was work was cancelled while it was still pending, we need to
	 * take care of releasing the runtime reference
	 */
	if (disable_delayed_work_sync(&xe->pmt.work))
		xe_pm_runtime_put(xe);
}

u32 xe_vsec_get_guid(struct xe_device *xe)
{
	struct xe_mmio *mmio = xe_root_tile_mmio(xe);
	u32 guid;

	/*
	 * Both supported platforms (BMG, CRI) require the remapper callback to
	 * access data. CRI needs it for the GUID.
	 */
	if (!xe->soc_remapper.set_telem_region)
		return 0;

	/* caller must ensure correct power state */
	if (!xe_pm_runtime_get_if_active(xe))
		return 0;

	mutex_lock(&xe->pmt.lock);

	if (xe->pmt.punit_guid_cache) {
		guid = xe->pmt.punit_guid_cache;
		goto unlock;
	}

	switch (xe->info.platform) {
	case XE_BATTLEMAGE:
		guid = xe_mmio_read32(mmio, BMG_PUNIT_TELEMETRY_GUID);
		break;

	case XE_CRESCENTISLAND:
		xe->soc_remapper.set_telem_region(xe, CRI_IDX_TELEM_DISCOVERY);
		guid = xe_mmio_read32(mmio, CRI_PUNIT_TELEMETRY_GUID);
		break;

	default:
		guid = 0;
		drm_err(&xe->drm, "Unsupported platform: %u\n", xe->info.platform);
		break;
	}

	xe->pmt.punit_guid_cache = guid;

unlock:
	mutex_unlock(&xe->pmt.lock);
	xe_pm_runtime_put(xe);

	return guid;
}

/**
 * xe_vsec_init - Initialize resources and add intel_vsec auxiliary
 * interface
 * @xe: valid xe instance
 */
int xe_vsec_init(struct xe_device *xe)
{
	struct intel_vsec_platform_info *info;
	struct device *dev = xe->drm.dev;
	enum xe_vsec platform;

	platform = get_platform_info(xe);
	if (platform == XE_VSEC_UNKNOWN)
		return 0;

	info = &xe_vsec_info[platform];
	if (!info->headers)
		return 0;

	switch (platform) {
	case XE_VSEC_BMG:
		if (!xe->soc_remapper.set_telem_region)
			return 0;
		xe->pmt.base_offset = BMG_TELEMETRY_OFFSET;
		info->priv_data = &xe_bmg_pmt_cb;
		break;

	case XE_VSEC_CRI:
		if (!xe->soc_remapper.set_telem_region)
			return 0;
		xe->pmt.base_offset = CRI_TELEMETRY_OFFSET;

		xe->pmt.retry_count = 0;
		INIT_DELAYED_WORK(&xe->pmt.work, cri_late_bind_probe_work);

		xe_pm_runtime_get_noresume(xe);
		if (!xe_is_oobmsm_fw_ready(xe)) {
			schedule_delayed_work(&xe->pmt.work,
					      msecs_to_jiffies(VSEC_LATE_BIND_DELAY_MSEC));
			return devm_add_action_or_reset(xe->drm.dev,
							vsec_disable_late_bind_work,
							xe);
		}

		info->priv_data = &xe_cri_pmt_cb;
		xe->soc_remapper.set_telem_region(xe, CRI_IDX_TELEM_DISCOVERY);
		break;

	default:
		drm_err(&xe->drm, "Unsupported platform: %u\n", platform);
		return 0;
	}

	/*
	 * Register a VSEC. Cleanup is handled using device managed
	 * resources.
	 */
	intel_vsec_register(dev, info);

	if (platform == XE_VSEC_CRI)
		xe_pm_runtime_put(xe);

	return 0;
}
MODULE_IMPORT_NS("INTEL_VSEC");
