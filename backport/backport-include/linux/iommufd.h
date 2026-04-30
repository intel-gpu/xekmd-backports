/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __BACKPORT_IOMMUFD_H
#define __BACKPORT_IOMMUFD_H

//#include_next<linux/iommufd.h>

enum {
	IOMMUFD_ACCESS_RW_READ = 0,
	IOMMUFD_ACCESS_RW_WRITE = 1 << 0,
	/* Set if the caller is in a kthread then rw will use kthread_use_mm() */
	IOMMUFD_ACCESS_RW_KTHREAD = 1 << 1,

	/* Only for use by selftest */
	__IOMMUFD_ACCESS_RW_SLOW_PATH = 1 << 2,
};

static inline void iommufd_ctx_put(struct iommufd_ctx *ictx)
{
}

static inline struct iommufd_ctx *iommufd_ctx_from_file(struct file *file)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int iommufd_vfio_compat_set_no_iommu(struct iommufd_ctx *ictx)
{
	return -EOPNOTSUPP;
}

static inline int iommufd_vfio_compat_ioas_create(struct iommufd_ctx *ictx)
{
	return -EOPNOTSUPP;
}

static inline int iommufd_access_pin_pages(struct iommufd_access *access,
					   unsigned long iova,
					   unsigned long length,
					   struct page **out_pages,
					   unsigned int flags)
{
	return -EOPNOTSUPP;
}

static inline void iommufd_access_unpin_pages(struct iommufd_access *access,
					      unsigned long iova,
					      unsigned long length)
{
}

static inline int iommufd_access_rw(struct iommufd_access *access,
				    unsigned long iova, void *data, size_t len,
				    unsigned int flags)
{
	return -EOPNOTSUPP;
}
#endif
