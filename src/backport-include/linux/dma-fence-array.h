/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __BACKPORT_LINUX_DMA_FENCE_ARRAY_H
#define __BACKPORT_LINUX_DMA_FENCE_ARRAY_H
#include_next <linux/dma-fence-array.h>

#ifdef BPM_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT
#define dma_fence_array_create LINUX_BACKPORT(dma_fence_array_create)
struct dma_fence_array *dma_fence_array_create(int num_fences,
                                               struct dma_fence **fences,
                                               u64 context, unsigned seqno,
                                               bool signal_on_any);
struct dma_fence_array *dma_fence_array_alloc(int num_fences);
void dma_fence_array_init(struct dma_fence_array *array,
                          int num_fences, struct dma_fence **fences,
                          u64 context, unsigned seqno,
                          bool signal_on_any);
#endif
#endif
