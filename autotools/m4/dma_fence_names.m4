dnl #
dnl # v6.17-506aa8b02a8d
dnl # dma-fence: Add safe access helpers and document the rules
dnl #
AC_DEFUN([AC_DMA_FENCE_NAME_HELPERS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			(void)&dma_fence_driver_name;
		],[
		],[
			AC_DEFINE(BPM_DMA_FENCE_NAME_HELPERS_NOT_PRESENT, 1,
				  [dma_fence driver and timeline name helpers are not available])
		])
	])
])
