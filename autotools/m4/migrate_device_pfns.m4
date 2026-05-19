dnl #
dnl # v7.0 - migrate_device_pfns() introduced
dnl #
AC_DEFUN([AC_MIGRATE_DEVICE_PFNS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/migrate.h>
		],[
			int ret = migrate_device_pfns(NULL, 0);
			(void)ret;
		],[
		],[
			AC_DEFINE(BPM_MIGRATE_DEVICE_PFNS_NOT_PRESENT, 1,
				[migrate_device_pfns() not present])
		])
	])
])
