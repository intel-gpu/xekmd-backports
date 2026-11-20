dnl #
dnl # 2232ba9c7931
dnl # mm: add gpu active/reclaim per-node stat counters (v2)
dnl #

AC_DEFUN([AC_NR_GPU_STATS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mmzone.h>
		],[
			int x = NR_GPU_ACTIVE;
			int y = NR_GPU_RECLAIM;
		],[
		],[
			AC_DEFINE(BPM_NR_GPU_STATS_NOT_PRESENT, 1,
				[NR_GPU_ACTIVE and NR_GPU_RECLAIM are available])
		])
	])
])
