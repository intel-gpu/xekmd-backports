dnl #
dnl # v6.4-428e106ae1ad
dnl # mm: Introduce untagged_addr_remote()
dnl #
AC_DEFUN([AC_UNTAGGED_ADDR_REMOTE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/uaccess.h>
		],[
			unsigned long addr = 0;

			addr = untagged_addr_remote(NULL, addr);
			(void)addr;
		],[
		],[
			AC_DEFINE(BPM_UNTAGGED_ADDR_REMOTE_NOT_PRESENT, 1,
				[untagged_addr_remote() is not available])
		])
	])
])
