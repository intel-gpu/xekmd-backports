// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/pci.h>

#include <generated/xe_device_wa_oob.h>

#include "xe_device.h"
#include "xe_gt.h"
#include "xe_hw_error.h"
#include "xe_log.h"
#include "xe_pci.h"
#include "xe_pcode.h"
#include "xe_pm.h"
#include "xe_printk.h"
#include "xe_ras.h"
#include "xe_survivability_mode.h"
#include "xe_wa.h"
#include "xe_wedge.h"

static void prepare_device_for_reset(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	struct xe_gt *gt;
	u8 id;

	/*
	 * Wedge the device to prevent userspace access but do not send the uevent.
	 * xe_wedge_fini() releases runtime pm if wedged flag is set, so acquire a runtime
	 * pm reference to avoid underflow.
	 */
	if (!atomic_xchg(&xe->wedged.flag, 1))
		xe_pm_runtime_get_noresume(xe);

	xe_device_set_in_reset(xe);

	for_each_gt(gt, xe, id) {
		xe_gt_wedge_declare(gt);
		flush_work(&gt->wedge.worker);
	}

	pci_disable_device(pdev);
}

static pci_ers_result_t ras_action_to_pci_result(struct pci_dev *pdev, u8 action)
{
	switch (action) {
	case XE_RAS_RECOVERY_ACTION_RECOVERED:
		return PCI_ERS_RESULT_RECOVERED;
	case XE_RAS_RECOVERY_ACTION_RESET:
		prepare_device_for_reset(pdev);
		return PCI_ERS_RESULT_NEED_RESET;
	case XE_RAS_RECOVERY_ACTION_DISCONNECT:
		return PCI_ERS_RESULT_DISCONNECT;
	default:
		return PCI_ERS_RESULT_DISCONNECT;
	}
}

static bool is_aer_internal_error(struct pci_dev *pdev)
{
	struct pci_dev *usp;
	u16 aer_cap;
	u32 status;

	usp = xe_pci_get_usp_dev(pdev);
	if (!usp)
		return false;

	aer_cap = pci_find_ext_capability(usp, PCI_EXT_CAP_ID_ERR);
	if (!aer_cap) {
		dev_warn_once(&usp->dev, "AER capability unavailable\n");
		return false;
	}

	pci_read_config_dword(usp, aer_cap + PCI_ERR_UNCOR_STATUS, &status);
	if (PCI_POSSIBLE_ERROR(status))
		return false;

	return status & PCI_ERR_UNC_INTN;
}

static pci_ers_result_t xe_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);

	xe_info(xe, "PCI error: detected state = %d\n", state);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	/* If the device is already in survivability mode, do not attempt recovery */
	if (xe_survivability_mode_is_boot_enabled(xe))
		return PCI_ERS_RESULT_DISCONNECT;

	/*
	 * If non-fatal error processing is in progress when uncorrectable internal error occurs,
	 * flush and disable the worker to prevent further processing, as a reset is imminent.
	 */
	if (XE_DEVICE_WA(xe, 14028434957) && is_aer_internal_error(pdev)) {
		xe_ras_set_aer_internal_error(xe);
		xe_hw_error_work_disable(xe);
	}

	if (xe_wedged(xe))
		return PCI_ERS_RESULT_DISCONNECT;

	switch (state) {
	case pci_channel_io_normal:
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		prepare_device_for_reset(pdev);
		return PCI_ERS_RESULT_NEED_RESET;
	default:
		xe_info(xe, "PCI error: unknown state %d\n", state);
		return PCI_ERS_RESULT_DISCONNECT;
	}
}

static pci_ers_result_t xe_pci_error_mmio_enabled(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	enum xe_ras_recovery_action action;

	xe_info(xe, "PCI error: MMIO enabled\n");
	action = xe_ras_process_errors(xe);

	/* User wants to debug the error, prevent reset */
	if (xe_wedge_mode_is_no_reset(xe)) {
		xe_wedge_declare(xe, DRM_WEDGE_RECOVERY_NONE);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return ras_action_to_pci_result(pdev, action);
}

static pci_ers_result_t xe_pci_error_slot_reset(struct pci_dev *pdev)
{
	const struct pci_device_id *ent = pci_match_id(pdev->driver->id_table, pdev);
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	xe_info(xe, "PCI error: slot reset\n");

	pci_restore_state(pdev);

	err = pci_enable_device(pdev);
	if (err) {
		xe_log_err_fatal(xe, PCI, err, "Cannot re-enable PCI device after reset\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	err = xe_pcode_ready(xe, true);
	/* TODO: dump survivability info on pcode init failure */
	if (err)
		return PCI_ERS_RESULT_DISCONNECT;

	/*
	 * Secondary Bus Reset causes all VRAM state to be lost along with
	 * hardware state. As an initial step, re-probe the device to
	 * re-initialize the driver and hardware.
	 * TODO: optimize by re-initializing only the hardware state and re-creating
	 * kernel BOs.
	 */
	pdev->driver->remove(pdev);
	devres_release_group(&pdev->dev, xe->devres_group);

	if (pdev->driver->probe(pdev, ent))
		return PCI_ERS_RESULT_DISCONNECT;

	xe = pdev_to_xe_device(pdev);

	/* Wedge the device to prevent I/O operations till the resume callback */
	atomic_set(&xe->wedged.flag, 1);

	return PCI_ERS_RESULT_RECOVERED;
}

static void xe_pci_error_resume(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);

	xe_info(xe, "PCI error: resume\n");

	atomic_set(&xe->wedged.flag, 0);
}

const struct pci_error_handlers xe_pci_error_handlers = {
	.error_detected	= xe_pci_error_detected,
	.mmio_enabled	= xe_pci_error_mmio_enabled,
	.slot_reset	= xe_pci_error_slot_reset,
	.resume		= xe_pci_error_resume,
};
