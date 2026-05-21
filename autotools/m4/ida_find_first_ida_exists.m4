dnl #
dnl # v6.15-7fe6b987166b
dnl # ida: Add ida_find_first_range() and ida_find_first()/ida_exists() variants
dnl #
AC_DEFUN([AC_IDA_FIND_FIRST_IDA_EXISTS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/idr.h>
		],[
			struct ida ida;
			int first;

			first = ida_find_first(&ida);
			(void)first;
		],[
		],[
			AC_DEFINE(BPM_IDA_FIND_FIRST_IDA_EXISTS_NOT_PRESENT, 1,
				[ida_find_first() and ida_exists() are not available])
		])
	])
])
