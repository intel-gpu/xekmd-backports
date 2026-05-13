dnl # v6.5-dd06e72e68bc
dnl # Compiler Attributes: Add __counted_by macro
AC_DEFUN([AC_COUNTED_BY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/compiler_types.h>
		],[
			struct bp_counted_by_test {
				unsigned int n;
				int a[] __counted_by(n);
			};
		],[
		],[
			AC_DEFINE(BPM_COUNTED_BY_NOT_PRESENT, 1,
				[__counted_by is not available in the kernel])
		])
	])
])
