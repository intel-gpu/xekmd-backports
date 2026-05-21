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
