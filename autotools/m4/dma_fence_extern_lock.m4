dnl #
dnl # 3e5067931b5d
dnl # dma-buf: abstract fence locking v2
dnl #

AC_DEFUN([AC_DMA_FENCE_EXTERN_LOCK_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			struct dma_fence *fence = NULL;
			spinlock_t *lock = fence->extern_lock;
			(void)lock;
		],[
			AC_DEFINE([BPM_DMA_FENCE_EXTERN_LOCK_PRESENT], 1,
				[dma_fence struct has extern_lock member])
		],[
		])
	])
])
