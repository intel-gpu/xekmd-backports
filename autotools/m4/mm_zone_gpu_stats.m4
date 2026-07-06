dnl #
dnl # ae80122f3896
dnl # drm/ttm: use gpu mm stats to track gpu memory allocations.
dnl #

AC_DEFUN([AC_NR_GPU_STATS_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mmzone.h>
		],[
			int x = NR_GPU_ACTIVE;
			int y = NR_GPU_RECLAIM;
		],[
			AC_DEFINE(BPM_NR_GPU_STATS_PRESENT, 1,
				[NR_GPU_ACTIVE and NR_GPU_RECLAIM are available])
		])
	])
])
