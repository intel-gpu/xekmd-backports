dnl #
dnl # v6.1-f0b933236ec97
dnl # lib/string_helpers: Introduce parse_int_array_user()
dnl #
AC_DEFUN([AC_PARSE_INT_ARRAY_USER_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/string.h>
			#include <linux/string_helpers.h>
		],[
			parse_int_array_user(NULL, 0, NULL);
		],[
		],[
			AC_DEFINE(BPM_PARSE_INT_ARRAY_USER_NOT_PRESENT, 1,
				[parse_int_array_user() function is not present or not exported])
		])
	])
])
