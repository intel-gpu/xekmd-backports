dnl #
dnl # v6.1 - 16ce101db85d
dnl # mm/memory.c: fix race when faulting a device private page
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
