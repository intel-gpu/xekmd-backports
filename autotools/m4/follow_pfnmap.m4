dnl #
dnl # v6.12-6da8e9634bb7
dnl # mm: new follow_pfnmap API
dnl #
AC_DEFUN([AC_FOLLOW_PFNMAP_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		],[
			struct follow_pfnmap_args args = { 0 };

			args.addr_mask = 0;
			follow_pfnmap_start(&args);
		],[
		],[
			AC_DEFINE(BPM_FOLLOW_PFNMAP_NOT_PRESENT, 1,
				[follow_pfnmap_args/follow_pfnmap_start()/follow_pfnmap_end() are not available])
		])
	])
])
