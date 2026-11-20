dnl #
dnl # v6.5-0b295316b3a9
dnl # mm/gup: remove unused vmas parameter from pin_user_pages_remote()
dnl #
AC_DEFUN([AC_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/kernel.h>
			#include <linux/build_bug.h>
			#include <linux/mm.h>
		],[
			BUILD_BUG_ON(!__same_type(&pin_user_pages_remote,
				(long (*)(struct mm_struct *mm,
					 unsigned long start,
					 unsigned long nr_pages,
					 unsigned int gup_flags,
					 struct page **pages,
					 int *locked))0));
		],[
		],[
			AC_DEFINE(BPM_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT, 1,
				[pin_user_pages_remote() does not have the 6-argument signature])
		])
	])
])
