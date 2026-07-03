dnl #
dnl # v6.12-6da8e9634bb7
dnl # mm: new follow_pfnmap API
dnl #
AC_DEFUN([AC_FOLLOW_PFNMAP_START_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		],[
			struct follow_pfnmap_args args = { 0 };
			follow_pfnmap_start(&args);
		],[
		],[
			AC_DEFINE(BPM_FOLLOW_PFNMAP_START_NOT_PRESENT, 1,
				[follow_pfnmap_start/end() is not available])
		])
	])
])

dnl #
dnl # v6.15-62fb8adc43af
dnl # mm: Provide address mask in struct follow_pfnmap_args
dnl #
AC_DEFUN([AC_FOLLOW_PFNMAP_ARGS_ADDR_MASK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		],[
			struct follow_pfnmap_args args = { 0 };
			unsigned long mask = args.addr_mask;
			(void)mask;
		],[
		],[
			AC_DEFINE(BPM_FOLLOW_PFNMAP_ARGS_ADDR_MASK_NOT_PRESENT, 1,
				[struct follow_pfnmap_args does not have addr_mask member])
		])
	])
])
