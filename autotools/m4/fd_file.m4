dnl #
dnl # v6.12 - 88a2f6468d01
dnl # struct fd: representation change
dnl #
AC_DEFUN([AC_FD_FILE_FD_EMPTY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/file.h>
		],[
			struct fd f = {0};
			struct file *file = fd_file(f);
			(void)file;
		],[
		],[
			AC_DEFINE(BPM_FD_FILE_FD_EMPTY_NOT_PRESENT, 1,
				[fd_file()/fd_empty() helpers are not available])
		])
	])
])
