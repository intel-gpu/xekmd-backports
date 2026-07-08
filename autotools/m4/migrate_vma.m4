dnl #
dnl # v7.0 - struct migrate_vma gained fault_page for migrate_to_ram callbacks
dnl #
AC_DEFUN([AC_MIGRATE_VMA_FAULT_PAGE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/migrate.h>
		],[
			struct migrate_vma args = {
				.fault_page = NULL,
			};
			(void)args;
		],[
		],[
			AC_DEFINE(BPM_MIGRATE_VMA_FAULT_PAGE_NOT_PRESENT, 1,
				[struct migrate_vma fault_page member is not present])
		])
	])
])

dnl #
dnl # migrate_vma_setup()/migrate_vma_pages()/migrate_vma_finalize() live in
dnl # mm/migrate_device.c (mm/migrate.c on pre-split kernels), which is built
dnl # and EXPORT_SYMBOL'd only when CONFIG_DEVICE_PRIVATE is enabled.
dnl #
AC_DEFUN([AC_MIGRATE_VMA_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/migrate.h>
		],[
			#ifndef CONFIG_DEVICE_PRIVATE
			#error CONFIG_DEVICE_PRIVATE not enabled
			#endif
		],[
		],[
			AC_DEFINE(BPM_MIGRATE_VMA_NOT_PRESENT, 1,
				[migrate_vma_* helpers are not present or not exported])
		])
	])
])
