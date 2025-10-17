dnl #
dnl # v6.12-ddc94d0b17e8e
dnl # dma-buf: Split out dma fence array create into alloc and arm functions
dnl #
AC_DEFUN([AC_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/dma-fence-array.h>
                ],[
			void *p = dma_fence_array_alloc(1);
			(void)p;
		],[
		],[
                        AC_DEFINE(BPM_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT, 1,
                                [dma_fence_array_alloc() is not available])
                ])
        ])
])
