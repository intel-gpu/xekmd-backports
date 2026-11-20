dnl #
dnl # v6.4-aec11c8d7cb3 dma-buf/dma-fence: Add deadline awareness
dnl #
AC_DEFUN([AC_DMA_FENCE_SET_DEADLINE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			dma_fence_set_deadline(NULL, 0);
		],[
		],[
			AC_DEFINE(BPM_DMA_FENCE_SET_DEADLINE_NOT_PRESENT, 1,
				  [dma_fence_set_deadline() is not available in the kernel])
		])
	])
])

dnl #
dnl # v5.18-976b6d97c623
dnl # dma-buf: consolidate dma_fence subclass checking
dnl #
AC_DEFUN([AC_DMA_FENCE_IS_CONTAINER_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			dma_fence_is_container(NULL);
		],[
		],[
			AC_DEFINE(BPM_DMA_FENCE_IS_CONTAINER_NOT_PRESENT, 1,
				  [dma_fence_is_container() is not available in the kernel])
		])
	])
])

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

dnl #
dnl # 3e5067931b
dnl # dma-buf: abstract fence locking v2
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
