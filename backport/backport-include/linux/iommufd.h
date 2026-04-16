/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __BACKPORT_IOMMUFD_H
#define __BACKPORT_IOMMUFD_H

//#include_next<linux/iommufd.h>

static inline void iommufd_ctx_put(struct iommufd_ctx *ictx)
{
}

#endif
