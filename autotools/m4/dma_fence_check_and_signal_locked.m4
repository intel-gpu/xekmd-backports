dnl #
dnl # v7.0-rc1 - c891b99d25dd
dnl # dma-buf/dma-fence: Add dma_fence_check_and_signal()
dnl #
AC_DEFUN([AC_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			struct dma_fence *fence = NULL;
			bool ret = dma_fence_check_and_signal_locked(fence);
			(void)ret;
		],[
		],[
			AC_DEFINE([BPM_DMA_FENCE_CHECK_AND_SIGNAL_LOCKED_NOT_PRESENT], 1,
				[dma_fence_check_and_signal_locked() is not available])
		])
	])
])
