/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __BACKPORT_DRM_GPUVA_MGR_H
#define __BACKPORT_DRM_GPUVA_MGR_H

#include_next<drm/drm_gpuva_mgr.h>

#ifdef BPM_DRM_GPUVA_OP_DRIVER_NOT_PRESENT
#define drm_gpuva_op_type LINUX_BACKPORT(drm_gpuva_op_type)
#define DRM_GPUVA_OP_MAP LINUX_BACKPORT(DRM_GPUVA_OP_MAP)
#define DRM_GPUVA_OP_REMAP LINUX_BACKPORT(DRM_GPUVA_OP_REMAP)
#define DRM_GPUVA_OP_UNMAP LINUX_BACKPORT(DRM_GPUVA_OP_UNMAP)
#define DRM_GPUVA_OP_PREFETCH LINUX_BACKPORT(DRM_GPUVA_OP_PREFETCH)
#define DRM_GPUVA_OP_DRIVER LINUX_BACKPORT(DRM_GPUVA_OP_DRIVER)

/**
 * enum drm_gpuva_op_type - GPU VA operation type
 *
 * Operations to alter the GPU VA mappings tracked by the &drm_gpuvm.
 */
enum drm_gpuva_op_type {
        /**
         * @DRM_GPUVA_OP_MAP: the map op type
         */
        DRM_GPUVA_OP_MAP,

        /**
         * @DRM_GPUVA_OP_REMAP: the remap op type
         */
        DRM_GPUVA_OP_REMAP,

        /**
         * @DRM_GPUVA_OP_UNMAP: the unmap op type
         */
        DRM_GPUVA_OP_UNMAP,

        /**
         * @DRM_GPUVA_OP_PREFETCH: the prefetch op type
         */
        DRM_GPUVA_OP_PREFETCH,

        /**
         * @DRM_GPUVA_OP_DRIVER: the driver defined op type
         */
        DRM_GPUVA_OP_DRIVER,
};
#endif

#endif /* __BACKPORT_DRM_GPUVA_MGR_H */
