dnl #
dnl #  v7.3 - 9370a5c664e8
dnl #  dma-buf: rename dma_fence_enable_sw_signaling
dnl #

AC_DEFUN([AC_DMA_FENCE_ENABLE_SIGNALING_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		], [
			dma_fence_enable_signaling(NULL);
		], [
		], [
			AC_DEFINE(BPM_DMA_FENCE_ENABLE_SIGNALING_NOT_PRESENT, 1,
				  [dma_fence_enable_signaling() is not available])
		])
	])
])
