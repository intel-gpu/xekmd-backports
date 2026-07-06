dnl #
dnl # 1f32f310a13c
dnl # dma-buf: inline spinlock for fence protection v5
dnl #

AC_DEFUN([AC_DMA_FENCE_EXTERN_LOCK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			struct dma_fence *fence = NULL;
			spinlock_t *lock = fence->extern_lock;
			(void)lock;
		],[
		],[
			AC_DEFINE([BPM_DMA_FENCE_EXTERN_LOCK_NOT_PRESENT], 1,
				[dma_fence struct has no extern_lock member])
		])
	])
])
