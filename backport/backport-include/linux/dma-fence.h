/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_DMA_FENCE_H
#define __BACKPORT_LINUX_DMA_FENCE_H

#include_next <linux/dma-fence.h>

#ifdef BPM_DMA_FENCE_SET_DEADLINE_NOT_PRESENT
static inline void dma_fence_set_deadline(struct dma_fence *fence,
					  ktime_t deadline)
{
}
#endif
#endif
