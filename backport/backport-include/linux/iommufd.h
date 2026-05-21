/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __BACKPORT_IOMMUFD_H
#define __BACKPORT_IOMMUFD_H

#include_next <linux/iommufd.h>

#ifdef BPM_IOMMUFD_DEVICE_PASID_ATTACH_REPLACE_DETACH_NOT_PRESENT
static inline int bpm_iommufd_device_attach(struct iommufd_device *idev,
					ioasid_t pasid, u32 *pt_id)
{
	return iommufd_device_attach(idev, pt_id);
}
#define iommufd_device_attach bpm_iommufd_device_attach

static inline int bpm_iommufd_device_replace(struct iommufd_device *idev,
					ioasid_t pasid, u32 *pt_id)
{
	return iommufd_device_replace(idev, pt_id);
}
#define iommufd_device_replace bpm_iommufd_device_replace

static inline void bpm_iommufd_device_detach(struct iommufd_device *idev,
					ioasid_t pasid)
{
	return iommufd_device_detach(idev);
}
#define iommufd_device_detach bpm_iommufd_device_detach
#endif
#endif
