#ifndef __BACKPORT_LINUX_DMA_FENCE_H
#define __BACKPORT_LINUX_DMA_FENCE_H

#include_next <linux/dma-fence.h>

#ifdef BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT
#ifndef dma_fence_test_signaled_flag
static inline bool dma_fence_test_signaled_flag(struct dma_fence *fence)
{
	return test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags);
}
#endif

bool dma_fence_check_and_signal_locked(struct dma_fence *fence);
#endif /* BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_DMA_FENCE_H */
