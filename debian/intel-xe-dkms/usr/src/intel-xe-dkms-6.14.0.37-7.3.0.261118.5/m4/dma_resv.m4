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

dnl #
dnl # v5.16-5baaac3184ab dma-buf: add dma_resv_for_each_fence v3
dnl #
AC_DEFUN([AC_DMA_RESV_FOR_EACH_FENCE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                        AC_KERNEL_TRY_COMPILE([
                                #include <linux/dma-resv.h>
                        ],[
                                struct dma_resv_iter cursor;
                                struct dma_fence *fence = NULL;
                                dma_resv_for_each_fence(&cursor, NULL, 0, fence)
                                        ;
                        ],[
                        ],[
                                AC_DEFINE(BPM_DMA_RESV_FOR_EACH_FENCE_NOT_PRESENT, 1,
                                          [dma_resv_for_each_fence() is not available in the kernel])
                        ])
        ])
])

dnl #
dnl # v5.19-c8d4c18bfbc4a
dnl # dma-buf/drivers: make reserving a shared slot mandatory v4
dnl #
AC_DEFUN([AC_DMA_RESV_RESERVE_FENCES_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE([
				#include <linux/dma-resv.h>
			],[
				dma_resv_reserve_fences(NULL, 0);
			],[
			],[
				AC_DEFINE(BPM_DMA_RESV_RESERVE_FENCES_NOT_PRESENT, 1,
					  [dma_resv_reserve_fences() is not available in the kernel])
			])
	])
])

dnl #
dnl # v5.19-73511edf8b196
dnl # dma-buf: specify usage while adding fences to dma_resv obj v7
dnl #
AC_DEFUN([AC_DMA_RESV_ADD_FENCE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE([
				#include <linux/dma-resv.h>
			],[
				dma_resv_add_fence(NULL, NULL, 0);
			],[
			],[
				AC_DEFINE(BPM_DMA_RESV_ADD_FENCE_NOT_PRESENT, 1,
					  [dma_resv_add_fence() is not available in the kernel])
			])
	])
])

dnl #
dnl # v5.19-548e7432dc2da dma-buf: add dma_resv_replace_fences v2
dnl #
AC_DEFUN([AC_DMA_RESV_REPLACE_FENCES_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE([
				#include <linux/dma-resv.h>
			],[
				dma_resv_replace_fences(NULL, 0, NULL, 0);
			],[
			],[
				AC_DEFINE(BPM_DMA_RESV_REPLACE_FENCES_NOT_PRESENT, 1,
					  [dma_resv_replace_fences() is not available in the kernel])
			])
	])
])
