/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_DMA_FENCE_H
#define __BACKPORT_LINUX_DMA_FENCE_H

#include_next <linux/dma-fence.h>

#ifdef BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT
/*
 * dma_fence_check_and_signal_locked - check if signaled and signal if not
 * Must be called with fence->lock held.
 * Returns true if fence was already signaled, false otherwise.
 */
static inline bool
dma_fence_check_and_signal_locked(struct dma_fence *fence)
{
	bool was_signaled = test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags);

	dma_fence_signal_locked(fence);
	return was_signaled;
}
#endif /* BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT */

#ifdef BPM_DMA_FENCE_SET_DEADLINE_NOT_PRESENT
static inline void dma_fence_set_deadline(struct dma_fence *fence,
					  ktime_t deadline)
{
}
#endif

#endif /* __BACKPORT_LINUX_DMA_FENCE_H */
