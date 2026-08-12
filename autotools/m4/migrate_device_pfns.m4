dnl #
dnl # v6.1-241f68859656
dnl # mm/migrate_device.c: refactor migrate_vma and
dnl # migrate_deivce_coherent_page()
dnl #
AC_DEFUN([AC_MIGRATE_DEVICE_PAGES_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/migrate.h>
		],[
			migrate_device_pages(NULL, NULL, 0);
			migrate_device_finalize(NULL, NULL, 0);
		],[
		],[
			AC_DEFINE(BPM_MIGRATE_DEVICE_PAGES_NOT_PRESENT, 1,
				[migrate_device_pages()/finalize() not present])
		])
	])
])

dnl #
dnl # v7.0-a14fa8ec9d81
dnl # mm/migrate: Add migrate_device_pfns
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
