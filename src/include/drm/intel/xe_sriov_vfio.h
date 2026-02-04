/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2025 Intel Corporation
 */

#ifndef _XE_SRIOV_VFIO_H_
#define _XE_SRIOV_VFIO_H_

#include <linux/types.h>

struct pci_dev;
struct xe_device;

struct xe_device *xe_sriov_vfio_get_pf(struct pci_dev *pdev);
bool xe_sriov_vfio_migration_supported(struct xe_device *xe);
int xe_sriov_vfio_wait_flr_done(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_suspend_device(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_resume_device(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_stop_copy_enter(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_stop_copy_exit(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_resume_data_enter(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_resume_data_exit(struct xe_device *xe, unsigned int vfid);
int xe_sriov_vfio_error(struct xe_device *xe, unsigned int vfid);
ssize_t xe_sriov_vfio_data_read(struct xe_device *xe, unsigned int vfid,
				char __user *buf, size_t len);
ssize_t xe_sriov_vfio_data_write(struct xe_device *xe, unsigned int vfid,
				 const char __user *buf, size_t len);
ssize_t xe_sriov_vfio_stop_copy_size(struct xe_device *xe, unsigned int vfid);

#endif
