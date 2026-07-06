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

#ifdef BPM_DMA_FENCE_IS_CONTAINER_NOT_PRESENT
#include <linux/dma-fence-array.h>
#include <linux/dma-fence-chain.h>
#include <linux/kernel.h>

/* Some older header variants don't expose this declaration to wrappers. */
extern const struct dma_fence_ops dma_fence_array_ops;

static inline bool dma_fence_is_container(struct dma_fence *fence)
{
	return fence && (fence->ops == &dma_fence_array_ops ||
			 fence->ops == &dma_fence_chain_ops);
}

static inline bool dma_fence_is_chain(struct dma_fence *fence)
{
	return fence && fence->ops == &dma_fence_chain_ops;
}

static inline struct dma_fence_chain *__bp_to_dma_fence_chain(struct dma_fence *fence)
{
	return container_of(fence, struct dma_fence_chain, base);
}

static inline struct dma_fence *dma_fence_chain_contained(struct dma_fence *fence)
{
	if (!dma_fence_is_chain(fence))
		return fence;

	return __bp_to_dma_fence_chain(fence)->fence;
}
#endif

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

#ifdef BPM_DMA_FENCE_EXTERN_LOCK_NOT_PRESENT
#define extern_lock lock
#endif   /* BPM_DMA_FENCE_EXTERN_LOCK_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_DMA_FENCE_H */
