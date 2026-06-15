dnl #
dnl # v6.17-549810e91815
dnl # dma-fence: Change signature of __dma_fence_is_later
dnl #
AC_DEFUN([AC_DRM_FENCE_IS_LATER_ARG_DMA_FENCE_OPS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/dma-fence.h>
		],[
			struct dma_fence fence;
			u64 seqno1 = 1, seqno2 = 2;
			__dma_fence_is_later(&fence, seqno1, seqno2);
		],[
		],[
			AC_DEFINE([BPM_DRM_FENCE_IS_LATER_ARG_DMA_FENCE_OPS_NOT_PRESENT], 1,
				[__dma_fence_is_later uses old signature with seqno and ops arguments])
		])
	])
])
