dnl #
dnl # v6.5-2f2665c13af4
dnl # sysctl: replace child with an enumeration
dnl #
AC_DEFUN([AC_SYSCTL_TABLE_SENTINEL_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/sysctl.h>
		],[
			struct ctl_table test_table[] = {
				{
					.child = NULL,
				},
			};
			(void)test_table;
		],[
			AC_DEFINE([BPM_SYSCTL_TABLE_SENTINEL_NOT_PRESENT], 1,
				[legacy register_sysctl path requires explicit ctl_table sentinel])
		],[
		])
	])
])
