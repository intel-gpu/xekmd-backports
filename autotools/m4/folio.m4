dnl #
dnl # v5.16-b620f63358cd
dnl # mm: Add folio_put()
dnl #
AC_DEFUN([AC_FOLIO_PUT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_put(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_PUT_NOT_PRESENT, 1,
				  [folio_put() is not available in the kernel])
		])
	])
])

dnl #
dnl # v5.16-5a7c2b8? folio helpers introduced during folio conversion.
dnl #
AC_DEFUN([AC_FOLIO_FILE_PAGE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)folio_file_page(NULL, 0);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_FILE_PAGE_NOT_PRESENT, 1,
				  [folio_file_page() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_MARK_ACCESSED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_mark_accessed(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_MARK_ACCESSED_NOT_PRESENT, 1,
				  [folio_mark_accessed() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_LOCK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_lock(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_LOCK_NOT_PRESENT, 1,
				  [folio_lock() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_UNLOCK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_unlock(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_UNLOCK_NOT_PRESENT, 1,
				  [folio_unlock() is not available in the kernel])
		])
	])
])

dnl #
dnl # b5e84594cafb
dnl # mm/writeback: Add folio_mark_dirty()
dnl #
AC_DEFUN([AC_FOLIO_MARK_DIRTY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_mark_dirty(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_MARK_DIRTY_NOT_PRESENT, 1,
				  [folio_mark_dirty() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_MAPPED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)folio_mapped(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_MAPPED_NOT_PRESENT, 1,
				  [folio_mapped() is not available in the kernel])
		])
	])
])

dnl #
dnl # 9350f20a070d
dnl # mm/writeback: Add folio_clear_dirty_for_io()
dnl #
AC_DEFUN([AC_FOLIO_CLEAR_DIRTY_FOR_IO_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)folio_clear_dirty_for_io(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_CLEAR_DIRTY_FOR_IO_NOT_PRESENT, 1,
				  [folio_clear_dirty_for_io() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_SET_RECLAIM_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_set_reclaim(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_SET_RECLAIM_NOT_PRESENT, 1,
				  [folio_set_reclaim() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_CLEAR_RECLAIM_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			folio_clear_reclaim(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_CLEAR_RECLAIM_NOT_PRESENT, 1,
				  [folio_clear_reclaim() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_FOLIO_TEST_WRITEBACK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)folio_test_writeback(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_TEST_WRITEBACK_NOT_PRESENT, 1,
				  [folio_test_writeback() is not available in the kernel])
		])
	])
])
