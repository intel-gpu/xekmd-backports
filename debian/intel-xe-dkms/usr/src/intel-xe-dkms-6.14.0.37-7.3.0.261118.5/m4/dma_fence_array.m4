dnl #
dnl #  v6.12 - ddc94d0b17e8
dnl #  dma-buf: Split out dma fence array create into alloc and arm functions
dnl #
dnl #  v7.2 - d4c14903bf5e
dnl #  dma-buf/dma_fence_array: remove unused functionality v4
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

AC_DEFUN([AC_DMA_FENCE_ARRAY_NO_SIGNAL_ON_ANY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence-array.h>
		], [
			struct dma_fence_array *array;
			struct dma_fence **fences = NULL;

			array = dma_fence_array_create(1, fences, 0, 1);
			dma_fence_array_init(array, 1, fences, 0, 1);
		], [
		], [
			AC_DEFINE(BPM_DMA_FENCE_ARRAY_NO_SIGNAL_ON_ANY_NOT_PRESENT, 1,
				  [Fence-array create/init without signal_on_any are unavailable])
		])
	])
])
