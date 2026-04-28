#include <linux/export.h>
#include <linux/dma-fence.h>

#ifdef BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT
bool dma_fence_check_and_signal_locked(struct dma_fence *fence)
{
	bool ret;

	ret = dma_fence_test_signaled_flag(fence);
	dma_fence_signal_locked(fence);

	return ret;
}
EXPORT_SYMBOL(dma_fence_check_and_signal_locked);
#endif /* BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT */
