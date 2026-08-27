dnl #
dnl # v6.16 - 393cf700e624
dnl # dma-mapping: Provide an interface to allow allocate IOVA
dnl #
AC_DEFUN([AC_DMA_IOVA_STATE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-mapping.h>
		],[
			struct dma_iova_state state = { 0 };
			(void)state;
		],[
		],[
			AC_DEFINE(BPM_DMA_IOVA_STATE_NOT_PRESENT, 1,
				[struct dma_iova_state is not available])
		])
	])
])
