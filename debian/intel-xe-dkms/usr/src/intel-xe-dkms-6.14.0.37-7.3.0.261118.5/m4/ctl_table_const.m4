dnl #
dnl # v6.13-7abc9b53bd51
dnl # sysctl: allow registration of const struct ctl_table
dnl #
AC_DEFUN([AC_STRUCT_CTL_TABLE_CONST_KEYWORD_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/sysctl.h>
		],[
			const struct ctl_table test_table[] = {
				{
					.procname = "test",
					.data = NULL,
					.maxlen = 0,
					.mode = 0644,
				},
				{}
			};
			register_sysctl("test", test_table);
		],[
		],[
			AC_DEFINE([BPM_STRUCT_CTL_TABLE_CONST_KEYWORD_NOT_PRESENT], 1,
				[const keyword not supported for struct ctl_table])
		])
	])
])
