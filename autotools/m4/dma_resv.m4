dnl #
dnl # v5.19-7bc80a5462c3 dma-buf: add enum dma_resv_usage v4
dnl #
AC_DEFUN([AC_DMA_RESV_USAGE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE([
				#include <linux/dma-resv.h>
			],[
				enum dma_resv_usage usage = DMA_RESV_USAGE_BOOKKEEP;
				(void)usage;
			],[
			],[
				AC_DEFINE(BPM_DMA_RESV_USAGE_NOT_PRESENT, 1,
					  [enum dma_resv_usage is not available in the kernel])
			])
	])
])

