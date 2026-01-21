// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023-2024 Intel Corporation
 */

#include <linux/bitops.h>
#include <linux/pci.h>

#include "regs/xe_bars.h"
#include "xe_assert.h"
#include "xe_device.h"
#include "prelim/xe_eudebug.h"
#include "xe_gt_sriov_pf_config.h"
#include "xe_gt_sriov_pf_control.h"
#include "xe_gt_sriov_printk.h"
#include "xe_guc_engine_activity.h"
#include "xe_pci_sriov.h"
#include "xe_pm.h"
#include "xe_sriov.h"
#include "xe_sriov_pf.h"
#include "xe_sriov_pf_helpers.h"
#include "xe_sriov_printk.h"

/*
 * NOTE: Backport-only.
 *
 * We need to update the SR-IOV VF BAR size cache (pdev->sriov->barsz[])
 * when programming VF Resizable BAR (VF REBAR) on kernels that do not
 * provide PCI VF REBAR helper APIs.
 *
 * The real 'struct pci_sriov' is PCI-core internal (drivers/pci/pci.h).
 * For OOT/backport builds, we provide a local copy of the v6.6 layout
 * to access barsz[] only. Keep this in sync with the target baseline.
 */
#ifndef HAVE_STRUCT_PCI_SRIOV
struct pci_sriov {
	int		pos;			/* Capability position */
	int		nres;			/* Number of resources */
	u32		cap;			/* SR-IOV Capabilities */
	u16		ctrl;			/* SR-IOV Control */
	u16		total_VFs;		/* Total VFs associated with the PF */
	u16		initial_VFs;		/* Initial VFs associated with the PF */
	u16		num_VFs;		/* Number of VFs available */
	u16		offset;			/* First VF Routing ID offset */
	u16		stride;			/* Following VF stride */
	u16		vf_device;		/* VF device ID */
	u32		pgsz;			/* Page size for BAR alignment */
	u8		link;			/* Function Dependency Link */
	u8		max_VF_buses;		/* Max buses consumed by VFs */
	u16		driver_max_VFs;		/* Max num VFs driver supports */
	struct pci_dev	*dev;			/* Lowest numbered PF */
	struct pci_dev	*self;			/* This PF */
	u32		class;			/* VF device */
	u8		hdr_type;		/* VF header type */
	u16		subsystem_vendor;	/* VF subsystem vendor */
	u16		subsystem_device;	/* VF subsystem device */
	resource_size_t	barsz[PCI_SRIOV_NUM_BARS]; /* VF BAR size */
	bool		drivers_autoprobe;	/* Auto probing of VFs by driver */
};
#endif /* HAVE_STRUCT_PCI_SRIOV */

static int pf_needs_provisioning(struct xe_gt *gt, unsigned int num_vfs)
{
	unsigned int n;

	for (n = 1; n <= num_vfs; n++)
		if (!xe_gt_sriov_pf_config_is_empty(gt, n))
			return false;

	return true;
}

static int pf_provision_vfs(struct xe_device *xe, unsigned int num_vfs)
{
	struct xe_gt *gt;
	unsigned int id;
	int result = 0, err;

	for_each_gt(gt, xe, id) {
		if (!pf_needs_provisioning(gt, num_vfs))
			continue;
		err = xe_gt_sriov_pf_config_set_fair(gt, VFID(1), num_vfs);
		result = result ?: err;
	}

	return result;
}

static void pf_unprovision_vfs(struct xe_device *xe, unsigned int num_vfs)
{
	struct xe_gt *gt;
	unsigned int id;
	unsigned int n;

	for_each_gt(gt, xe, id)
		for (n = 1; n <= num_vfs; n++)
			xe_gt_sriov_pf_config_release(gt, n, true);
}

static void pf_reset_vfs(struct xe_device *xe, unsigned int num_vfs)
{
	struct xe_gt *gt;
	unsigned int id;
	unsigned int n;

	for_each_gt(gt, xe, id)
		for (n = 1; n <= num_vfs; n++)
			xe_gt_sriov_pf_control_trigger_flr(gt, n);
}

static struct pci_dev *xe_pci_pf_get_vf_dev(struct xe_device *xe, unsigned int vf_id)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);

	xe_assert(xe, IS_SRIOV_PF(xe));

	/* caller must use pci_dev_put() */
	return pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
			pdev->bus->number,
			pci_iov_virtfn_devfn(pdev, vf_id));
}

static void pf_link_vfs(struct xe_device *xe, int num_vfs)
{
	struct pci_dev *pdev_pf = to_pci_dev(xe->drm.dev);
	struct device_link *link;
	struct pci_dev *pdev_vf;
	unsigned int n;

	/*
	 * When both PF and VF devices are enabled on the host, during system
	 * resume they are resuming in parallel.
	 *
	 * But PF has to complete the provision of VF first to allow any VFs to
	 * successfully resume.
	 *
	 * Create a parent-child device link between PF and VF devices that will
	 * enforce correct resume order.
	 */
	for (n = 1; n <= num_vfs; n++) {
		pdev_vf = xe_pci_pf_get_vf_dev(xe, n - 1);

		/* unlikely, something weird is happening, abort */
		if (!pdev_vf) {
			xe_sriov_err(xe, "Cannot find VF%u device, aborting link%s creation!\n",
				     n, str_plural(num_vfs));
			break;
		}

		link = device_link_add(&pdev_vf->dev, &pdev_pf->dev,
				       DL_FLAG_AUTOREMOVE_CONSUMER);
		/* unlikely and harmless, continue with other VFs */
		if (!link)
			xe_sriov_notice(xe, "Failed linking VF%u\n", n);

		pci_dev_put(pdev_vf);
	}
}

static void pf_engine_activity_stats(struct xe_device *xe, unsigned int num_vfs, bool enable)
{
	struct xe_gt *gt;
	unsigned int id;
	int ret = 0;

	for_each_gt(gt, xe, id) {
		ret = xe_guc_engine_activity_function_stats(&gt->uc.guc, num_vfs, enable);
		if (ret)
			xe_gt_sriov_info(gt, "Failed to %s engine activity function stats (%pe)\n",
					 str_enable_disable(enable), ERR_PTR(ret));
	}
}

#ifndef PCI_EXT_CAP_ID_VF_REBAR
#define PCI_EXT_CAP_ID_VF_REBAR 0x24 /* VF Resizable BAR */
#endif

#ifndef HAVE_PCI_REBAR_SIZE_TO_BYTES
static inline resource_size_t pci_rebar_size_to_bytes(int size)
{
	return 1ULL << (size + ilog2((resource_size_t)SZ_1M));
}
#endif

static int resize_vf_vram_bar(struct xe_device *xe, int num_vfs)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);
	resource_size_t size, total;
	int pos, i, vf_bar_idx = VF_LMEM_BAR - PCI_IOV_RESOURCES;
	u32 rebar, ctrl;
	int err;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_VF_REBAR);
	if (!pos)
		return 0;

	/*
	 * For all current platforms we're expecting a single VF resizable BAR,
	 * and we expect it to always be BAR2.
	 */
	err = pci_read_config_dword(pdev, pos + PCI_REBAR_CTRL, &ctrl);
	if (err)
		return err;

	if (FIELD_GET(PCI_REBAR_CTRL_NBAR_MASK, ctrl) != 1 ||
	    FIELD_GET(PCI_REBAR_CTRL_BAR_IDX, ctrl) != vf_bar_idx) {
		xe_sriov_warn(xe, "Unexpected resource in VF resizable BAR, skipping resize\n");
		return 0;
	}

	err = pci_read_config_dword(pdev, pos + PCI_REBAR_CAP, &rebar);
	if (err)
		return err;

	rebar = FIELD_GET(PCI_REBAR_CAP_SIZES, rebar);
	total = pci_resource_len(pdev, VF_LMEM_BAR);

	while (rebar) {
		i = __fls(rebar);
		size = pci_rebar_size_to_bytes(i);

		if (num_vfs && size <= div_u64(total, num_vfs)) {
			ctrl &= ~PCI_REBAR_CTRL_BAR_SIZE;
			ctrl |= pci_rebar_bytes_to_size(size) << PCI_REBAR_CTRL_BAR_SHIFT;

			err = pci_write_config_dword(pdev, pos + PCI_REBAR_CTRL, ctrl);
			if (err)
				return err;

			((struct pci_sriov *)pdev->sriov)->barsz[vf_bar_idx] = size;

			xe_sriov_info(xe, "VF BAR%d resized to %llu MiB\n",
				      vf_bar_idx, (unsigned long long)(size >> 20));
			break;
		}

		rebar &= ~BIT(i);
	}

	return 0;
}

static void restore_vf_vram_bar_size(struct xe_device *xe)
{
	int err;

	if (!IS_DGFX(xe))
		return;

	err = resize_vf_vram_bar(xe, xe->sriov.pf.device_total_vfs);
	if (err)
		xe_sriov_info(xe, "Failed to restore VF LMEM BAR size: %pe\n",
			      ERR_PTR(err));
}

static int pf_enable_vfs(struct xe_device *xe, int num_vfs)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);
	int total_vfs = xe_sriov_pf_get_totalvfs(xe);
	int err;

	xe_assert(xe, IS_SRIOV_PF(xe));
	xe_assert(xe, num_vfs > 0);
	xe_assert(xe, num_vfs <= total_vfs);
	xe_sriov_dbg(xe, "enabling %u VF%s\n", num_vfs, str_plural(num_vfs));

	err = xe_sriov_pf_wait_ready(xe);
	if (err)
		goto out;

	err = prelim_xe_eudebug_support_disable(xe);
	if (err < 0)
		goto out;

	/*
	 * We must hold additional reference to the runtime PM to keep PF in D0
	 * during VFs lifetime, as our VFs do not implement the PM capability.
	 *
	 * With PF being in D0 state, all VFs will also behave as in D0 state.
	 * This will also keep GuC alive with all VFs' configurations.
	 *
	 * We will release this additional PM reference in pf_disable_vfs().
	 */
	xe_pm_runtime_get_noresume(xe);

	err = pf_provision_vfs(xe, num_vfs);
	if (err < 0)
		goto failed;

	if (IS_DGFX(xe)) {
		err = resize_vf_vram_bar(xe, num_vfs);
		if (err)
			xe_sriov_info(xe, "Failed to set VF LMEM BAR size: %pe\n", ERR_PTR(err));
	}

	err = pci_enable_sriov(pdev, num_vfs);
	if (err < 0)
		goto failed;

	pf_link_vfs(xe, num_vfs);

	xe_sriov_info(xe, "Enabled %u of %u VF%s\n",
		      num_vfs, total_vfs, str_plural(total_vfs));

	pf_engine_activity_stats(xe, num_vfs, true);

	return num_vfs;

failed:
	restore_vf_vram_bar_size(xe);
	pf_unprovision_vfs(xe, num_vfs);
	xe_pm_runtime_put(xe);
	prelim_xe_eudebug_support_enable(xe);
out:
	xe_sriov_notice(xe, "Failed to enable %u VF%s (%pe)\n",
			num_vfs, str_plural(num_vfs), ERR_PTR(err));
	return err;
}

static int pf_disable_vfs(struct xe_device *xe)
{
	struct device *dev = xe->drm.dev;
	struct pci_dev *pdev = to_pci_dev(dev);
	u16 num_vfs = pci_num_vf(pdev);

	xe_assert(xe, IS_SRIOV_PF(xe));
	xe_sriov_dbg(xe, "disabling %u VF%s\n", num_vfs, str_plural(num_vfs));

	if (!num_vfs)
		return 0;

	pf_engine_activity_stats(xe, num_vfs, false);

	pci_disable_sriov(pdev);

	restore_vf_vram_bar_size(xe);

	pf_reset_vfs(xe, num_vfs);

	pf_unprovision_vfs(xe, num_vfs);

	/* not needed anymore - see pf_enable_vfs() */
	xe_pm_runtime_put(xe);

	prelim_xe_eudebug_support_enable(xe);

	xe_sriov_info(xe, "Disabled %u VF%s\n", num_vfs, str_plural(num_vfs));
	return 0;
}

/**
 * xe_pci_sriov_configure - Configure SR-IOV (enable/disable VFs).
 * @pdev: the &pci_dev
 * @num_vfs: number of VFs to enable or zero to disable all VFs
 *
 * This is the Xe implementation of struct pci_driver.sriov_configure callback.
 *
 * This callback will be called by the PCI subsystem to enable or disable SR-IOV
 * Virtual Functions (VFs) as requested by the used via the PCI sysfs interface.
 *
 * Return: number of configured VFs or a negative error code on failure.
 */
int xe_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int ret;

	if (!IS_SRIOV_PF(xe))
		return -ENODEV;

	if (num_vfs < 0)
		return -EINVAL;

	if (num_vfs > xe_sriov_pf_get_totalvfs(xe))
		return -ERANGE;

	if (num_vfs && pci_num_vf(pdev))
		return -EBUSY;

	xe_pm_runtime_get(xe);
	if (num_vfs > 0)
		ret = pf_enable_vfs(xe, num_vfs);
	else
		ret = pf_disable_vfs(xe);
	xe_pm_runtime_put(xe);

	return ret;
}
