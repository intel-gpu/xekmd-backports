dnl #
dnl # v5.16-cf30f6a5f0c6
dnl # lib: zstd: Add kernel-specific API
dnl #
AC_DEFUN([AC_ZSTD_GET_PARAMS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/zstd.h>
		],[
			zstd_parameters params = zstd_get_params(3, 0);
			(void)params;
		],[
		],[
			AC_DEFINE(BPM_ZSTD_GET_PARAMS_NOT_PRESENT, 1,
				[zstd_get_params is not available])
		])
	])
])
