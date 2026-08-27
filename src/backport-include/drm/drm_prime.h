/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _DRM_PRIME_H
#define _DRM_PRIME_H

#include_next <drm/drm_prime.h>
#include <linux/dma-buf.h>

#ifdef BPM_DRM_DRIVER_GEM_PRIME_MMAP_NOT_PRESENT
static inline int backport_drm_gem_dmabuf_mmap(struct dma_buf *dma_buf,
                                                struct vm_area_struct *vma)
{
    struct drm_gem_object *obj = dma_buf->priv;
    return drm_gem_prime_mmap(obj, vma);
}
#undef drm_gem_dmabuf_mmap
#define drm_gem_dmabuf_mmap(dma_buf, vma) \
        backport_drm_gem_dmabuf_mmap((dma_buf), (vma))

#endif /* BPM_DRM_DRIVER_GEM_PRIME_MMAP_NOT_PRESENT */

#endif /* _DRM_PRIME_H */
