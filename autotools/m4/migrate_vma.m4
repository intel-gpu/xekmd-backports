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