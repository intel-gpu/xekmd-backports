dnl #
dnl #
dnl #
dnl #
AC_DEFUN([AC_DMA_FENCE_LOCK_IRQSAVE_AND_IRQRESTORE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			struct dma_fence *fence = NULL;
			unsigned long flags;
			dma_fence_lock_irqsave(fence, flags);
			dma_fence_unlock_irqrestore(fence, flags);
		],[
		],[
			AC_DEFINE([BPM_DMA_FENCE_LOCK_IRQSAVE_AND_IRQRESTORE_NOT_PRESENT], 1,
				[dma_fence_lock_irqsave() and dma_fence_unlock_irqrestore() are not available])
		])
	])
])
